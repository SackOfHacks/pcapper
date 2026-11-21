"""One read of a large capture for every analyzer a fan-out step runs.

--threats runs ~90 analyzers, --overview and --ot-commands dozens more. When a
capture fits in memory the CLI loads it once and every analyzer iterates the
same packet list. A capture too large for that used to be read -- and every
packet dissected -- once per analyzer: 96 full passes for --threats.

A shared pass runs those analyzers concurrently instead, each in its own
thread, all fed by one reader:

1. Discovery. The orchestrator (``analyze_threats`` ...) is run once over an
   empty packet view with the analysis memo recording every memoised call it
   makes -- the exact calls, arguments included, that the real run will make.
2. Rounds. Every recorded call starts in a consumer thread. A consumer that
   asks for the capture's packets subscribes to the next read round; one that
   needs another analysis waits for it (the memo's in-flight tracking). When
   every live consumer is parked -- subscribed or waiting -- the reader starts
   a round: it reads the capture once and hands each record, in order, to
   every subscriber. Analyses that depended on others subscribe in the next
   round; a typical --threats run takes two or three.
3. Results land in the analysis memo under the keys the real run uses, so the
   orchestrator then runs as usual and finds every sub-analysis computed.

Every consumer sees exactly the packet sequence it would have read from disk
(scapy packets, dissected once and shared, or lite records for analyzers that
asked for them), so the output is identical to the sequential run. Builds of
one shared packet by the scapy layers that change while they build take turns,
and each TLS record is rebuilt once for all consumers (see _guard_scapy_builds
and _cached_tls_bytes). A consumer that blocks on another analysis while
subscribed is detached when
its buffer fills and finishes from its own read of the file (skipping what it
already consumed), so no wait can stall the reader. Disable with
``PCAPPER_SHARED_PASS=0``.
"""

from __future__ import annotations

import collections
import math
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from . import pcap_cache, utils
from .capture_parts import capture_parts
from . import progress
from .progress import build_statusbar
from .rawcap import LiteStream

_BATCH = 512  # records per hand-off
_BUFFER_BATCHES = 32  # per subscriber: at most _BATCH * _BUFFER_BATCHES pending

# Consumer states.
_RUNNING = "running"  # computing, not reading packets
_WAITING = "waiting"  # subscribed, waiting for the next round
_ATTACHED = "attached"  # reading the current round
_BLOCKED = "blocked"  # waiting for another analysis (not subscribed)
_BLOCKED_ATTACHED = "blocked-attached"  # waiting for another analysis mid-round
_DONE = "done"

_local = threading.local()
_lock = threading.Lock()
_active_paths: set[Path] = set()


def enabled() -> bool:
    return os.environ.get("PCAPPER_SHARED_PASS", "1") != "0"


# Consumers share one dissected scapy packet, and building some scapy layers
# back into bytes changes them while the build runs. A TLS/SSLv2 record clears
# its byte cache and freezes its TLS session for the build, restoring both
# afterwards (and some handshake messages overwrite a field in build()); a
# layer with a trailer field (an FCS, ICMP extensions, a DCE/RPC auth trailer)
# swaps in its own post_build method until the build ends. Two consumers
# building such a layer of one packet at once interleave those steps: the
# build raises ("While building field 'msg': 'bytes' object has no attribute
# 'fields'"), returns other bytes, or leaves the packet altered for every
# later consumer. While a shared pass runs, those builds therefore hold a lock
# kept on the packet (its first layer): builds of one packet take turns, as in
# a sequential run, and builds of different packets never wait for each other.
# Other layers build without changing anything and are not locked. Measured on
# --threats from disk: a per-packet lock on every build cost 3-6%, one lock
# for every build 70% (~90 threads queue on it), and one lock for all TLS
# builds 50% on a capture that is half TLS. A TLS layer's bytes() is moreover
# built once per shared packet and reused (_cached_tls_bytes).
_BUILD_LOCK_KEY = "_pcapper_build_lock"
_BUILT_KEY = "_pcapper_built"  # (raw_packet_cache at build time, built bytes)
_GUARD_MARK = "_pcapper_build_guard"
_fallback_build_lock = threading.RLock()  # for a first layer without a __dict__
_guarded_passes = 0  # shared passes running in this process
_guard_held = threading.local()  # this thread is inside a locked build


def _packet_build_lock(layer: Any) -> Any:
    root = layer
    while True:
        under = root.underlayer
        if under is None:
            break
        root = under
    store = getattr(root, "__dict__", None)
    if store is None:
        return _fallback_build_lock
    lock = store.get(_BUILD_LOCK_KEY)
    if lock is None:
        lock = store.setdefault(_BUILD_LOCK_KEY, threading.RLock())
    return lock


def _guarded(method: Callable[..., Any]) -> Callable[..., Any]:
    def guarded(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if not _guarded_passes or getattr(_guard_held, "active", False):
            # Outside a shared pass, or nested in a locked build of the same
            # packet (a TLS record building its messages): run as is.
            return method(self, *args, **kwargs)
        with _packet_build_lock(self):
            _guard_held.active = True
            try:
                return method(self, *args, **kwargs)
            finally:
                _guard_held.active = False

    guarded.__wrapped__ = method  # type: ignore[attr-defined]
    setattr(guarded, _GUARD_MARK, True)
    return guarded


def _cached_tls_bytes(method: Callable[..., Any]) -> Callable[..., Any]:
    """bytes() of a TLS-family layer while a shared pass runs: built once,
    under the packet's lock, then the same bytes for every later call.

    scapy rebuilds a TLS layer from its fields on every bytes() call, and about
    30 analyzers call bytes() on each TCP payload: 229,363 rebuilds of 8,151
    TLS packets in a --threats run over a capture that is half TLS. Rebuilding
    an unchanged layer returns the same bytes each time (checked on 27,713 TLS
    layers of eight captures), so the first rebuild is kept on the layer
    (_BUILT_KEY) and handed to the later callers: that run made 15,343
    rebuilds and took 62 s instead of 71 s (67 s with neither the lock nor
    this). Packets are never modified once read; as a check, a layer changed
    through setattr after its build (which clears its scapy byte cache,
    raw_packet_cache) is built again, and a layer that was not dissected from
    a capture is never kept."""

    def _build_and_keep(self, store):  # type: ignore[no-untyped-def]
        wire = self.raw_packet_cache
        _guard_held.active = True
        try:
            built = method(self)
        finally:
            _guard_held.active = False
        if store is not None and wire is not None and self.raw_packet_cache is wire:
            store[_BUILT_KEY] = (wire, built)
        return built

    def tls_bytes(self):  # type: ignore[no-untyped-def]
        if getattr(_guard_held, "active", False):
            return method(self)  # a nested build
        store = getattr(self, "__dict__", None)
        if store is not None:
            kept = store.get(_BUILT_KEY)
            if kept is not None and kept[0] is self.raw_packet_cache:
                return kept[1]
        if not _guarded_passes:
            # Analyzers taking turns over the packets kept in memory (no shared
            # pass, so no other thread builds): the same keep-once rule without
            # the lock -- every analyzer after the first gets the kept bytes.
            return _build_and_keep(self, store)
        with _packet_build_lock(self):
            wire = self.raw_packet_cache
            if store is not None:
                kept = store.get(_BUILT_KEY)  # built while this call waited
                if kept is not None and kept[0] is wire:
                    return kept[1]
            _guard_held.active = True
            try:
                built = method(self)
            finally:
                _guard_held.active = False
            if store is not None and wire is not None and self.raw_packet_cache is wire:
                store[_BUILT_KEY] = (wire, built)
            return built

    tls_bytes.__wrapped__ = method  # type: ignore[attr-defined]
    setattr(tls_bytes, _GUARD_MARK, True)
    return tls_bytes


def _has_trailer(field: Any, trailer: type, depth: int = 0) -> bool:
    if isinstance(field, trailer):
        return True
    if depth > 4:
        return False
    for inner in (getattr(field, "fld", None), getattr(field, "dflt", None)):
        if inner is not None and _has_trailer(inner, trailer, depth + 1):  # ConditionalField ...
            return True
    for entry in getattr(field, "flds", None) or ():  # MultipleTypeField
        if _has_trailer(entry[0] if isinstance(entry, tuple) else entry, trailer, depth + 1):
            return True
    return False


def _guard_scapy_builds() -> None:
    """Lock the builds of the scapy layers that change while they build (see
    above): every TLS-family layer and every layer class with a trailer field
    loaded so far. A TLS-family layer's bytes() is also built only once per
    shared packet (_cached_tls_bytes)."""
    try:
        from scapy.config import conf
        from scapy.fields import TrailerField
    except Exception:
        return
    targets: list[tuple[type, str, Callable[..., Any]]] = []
    try:
        from scapy.layers.tls.session import _GenericTLSSessionInheritance
    except Exception:  # scapy without its TLS layer (no cryptography)
        pass
    else:
        targets += [
            (_GenericTLSSessionInheritance, "__bytes__", _cached_tls_bytes),
            (_GenericTLSSessionInheritance, "do_build", _guarded),
        ]
    for cls in list(conf.layers):
        try:
            if any(_has_trailer(field, TrailerField) for field in getattr(cls, "fields_desc", None) or ()):
                targets.append((cls, "do_build", _guarded))
        except Exception:
            continue
    with _lock:
        for cls, name, wrap in targets:
            method = getattr(cls, name)
            if not getattr(method, _GUARD_MARK, False):  # not already (or inherited) guarded
                setattr(cls, name, wrap(method))


def _new_build_lock_in_child() -> None:
    # A fork while another thread holds the fallback lock would leave it held
    # for good in the child, so a forked worker starts with a fresh one.
    global _fallback_build_lock
    _fallback_build_lock = threading.RLock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_new_build_lock_in_child)


class _Aborted(Exception):
    pass


class _Subscription:
    __slots__ = ("owner", "lite", "prefilter", "stats", "buffer", "cond", "ended", "detached", "closed", "pushed")

    def __init__(
        self, owner: "_Consumer", lite: bool, prefilter: Optional[Callable], stats: Optional[object]
    ) -> None:
        self.owner = owner
        self.lite = lite
        self.prefilter = prefilter
        self.stats = stats
        self.buffer: collections.deque = collections.deque()
        self.cond = threading.Condition()
        self.ended = False
        self.detached = False
        self.closed = False
        self.pushed = 0


class _Consumer:
    __slots__ = ("session", "call", "thread", "state", "pending", "error", "name")

    def __init__(self, session: "SharedPass", call: Callable[[], Any], name: str) -> None:
        self.session = session
        self.call = call
        self.thread: Optional[threading.Thread] = None
        self.state = _RUNNING
        self.pending: Optional[_Subscription] = None
        self.error: Optional[BaseException] = None
        self.name = name


class SharedPass:
    """Run ``calls`` (zero-argument callables) with one capture read per round."""

    def __init__(self, path: Path, calls: list[tuple[str, Callable[[], Any]]], *, show_status: bool) -> None:
        self.path = path
        self.key = pcap_cache._path_key(path)
        self.show_status = show_status
        self.cond = threading.Condition()
        self.aborted = False
        self.rounds = 0
        self.records = 0
        self.detaches = 0
        self.round_sizes: list[int] = []
        self.round_names: list[list[str]] = []
        self.round_seconds: list[float] = []
        self.consumers = [_Consumer(self, call, name) for name, call in calls]

    # -- consumer side -------------------------------------------------------
    def _run_consumer(self, consumer: _Consumer) -> None:
        _local.consumer = consumer
        try:
            consumer.call()
        except BaseException as exc:  # noqa: BLE001 - recorded; the real run re-raises
            consumer.error = exc
        finally:
            _local.consumer = None
            with self.cond:
                consumer.state = _DONE
                self.cond.notify_all()

    def subscribe(
        self, consumer: _Consumer, lite: bool, prefilter: Optional[Callable], stats: Optional[object]
    ) -> Iterator[object]:
        sub = _Subscription(consumer, lite, prefilter, stats)
        with self.cond:
            consumer.pending = sub
            consumer.state = _WAITING
            self.cond.notify_all()
        return self._consume(consumer, sub)

    def _consume(self, consumer: _Consumer, sub: _Subscription) -> Iterator[object]:
        add = sub.stats.add if sub.stats is not None else None  # type: ignore[attr-defined]
        if sub.stats is not None:
            sub.stats.active = True  # type: ignore[attr-defined]
        prefilter = sub.prefilter
        lite = sub.lite
        consumed = 0
        try:
            while True:
                with sub.cond:
                    while not sub.buffer and not sub.ended and not sub.detached and not self.aborted:
                        sub.cond.wait()
                    if self.aborted:
                        raise _Aborted()
                    if sub.buffer:
                        batch = sub.buffer.popleft()
                        sub.cond.notify_all()
                    elif sub.detached:
                        batch = None
                    else:
                        return
                if batch is None:
                    break
                consumed += len(batch)
                for record in batch:
                    if add is not None:
                        add(record)
                    if prefilter is not None and not prefilter(record):
                        continue
                    yield record if lite else record.materialize()
            # Detached mid-round: finish from a private read of the capture.
            stream = LiteStream(self.path, pcap_cache.get_capture_window(self.path))
            try:
                for index, record in enumerate(stream):
                    if index < consumed:
                        continue
                    if add is not None:
                        add(record)
                    if prefilter is not None and not prefilter(record):
                        continue
                    yield record if lite else record.materialize()
            finally:
                stream.close()
        finally:
            with sub.cond:
                sub.closed = True
                sub.cond.notify_all()
            with self.cond:
                if consumer.state in (_ATTACHED, _WAITING, _BLOCKED_ATTACHED):
                    consumer.state = _RUNNING
                self.cond.notify_all()

    def spawn(self, parent: _Consumer, call: Callable[[], Any]) -> Callable[[], Any]:
        """Run ``call`` on a consumer thread of its own, beside ``parent``.

        Rounds start only once every live consumer is parked, so a sibling
        spawned before ``parent`` parks reads in the same round as ``parent``
        and the analyses ``parent`` then waits for. Returns the function that
        waits for it (``parent`` counts as blocked meanwhile, so rounds go on)
        and hands over its result, re-raising its error."""
        box: dict[str, Any] = {}

        def run() -> None:
            box["value"] = call()

        child = _Consumer(self, run, f"{parent.name}+")
        child.thread = threading.Thread(
            target=self._run_consumer, args=(child,), name=f"pcapper-shared-{parent.name}+", daemon=True
        )
        with self.cond:
            self.consumers.append(child)
        child.thread.start()

        def result() -> Any:
            self.blocked(parent, True)
            try:
                child.thread.join()  # type: ignore[union-attr]
            finally:
                self.blocked(parent, False)
            if child.error is not None:
                raise child.error
            return box.get("value")

        return result

    def blocked(self, consumer: _Consumer, waiting: bool) -> None:
        with self.cond:
            if waiting:
                consumer.state = _BLOCKED_ATTACHED if consumer.state == _ATTACHED else _BLOCKED
            else:
                consumer.state = _ATTACHED if consumer.state == _BLOCKED_ATTACHED else _RUNNING
            self.cond.notify_all()

    # -- reader side -----------------------------------------------------------
    def run(self) -> None:
        global _guarded_passes
        _guard_scapy_builds()
        with _lock:
            _guarded_passes += 1
        try:
            self._run()
        finally:
            with _lock:
                _guarded_passes -= 1

    def _run(self) -> None:
        # Snapshots: a running consumer may add siblings (spawn) to the list,
        # each started by spawn itself.
        initial = list(self.consumers)
        for index, consumer in enumerate(initial):
            thread = threading.Thread(
                target=self._run_consumer,
                args=(consumer,),
                name=f"pcapper-shared-{index}",
                daemon=True,
            )
            consumer.thread = thread
        for consumer in initial:
            consumer.thread.start()  # type: ignore[union-attr]
        try:
            while True:
                subs = self._next_round()
                if subs is None:
                    break
                self._broadcast(subs)
            with self.cond:
                everyone = list(self.consumers)
            for consumer in everyone:
                consumer.thread.join()  # type: ignore[union-attr]
        except BaseException:
            self.abort()
            raise

    def abort(self) -> None:
        self.aborted = True
        with self.cond:
            self.cond.notify_all()
            everyone = list(self.consumers)
        for consumer in everyone:
            sub = consumer.pending
            if sub is not None:
                with sub.cond:
                    sub.cond.notify_all()

    def _next_round(self) -> Optional[list[_Subscription]]:
        with self.cond:
            while True:
                alive = [c for c in self.consumers if c.state != _DONE]
                if not alive:
                    return None
                waiting = [c for c in alive if c.state == _WAITING]
                parked = all(c.state in (_WAITING, _BLOCKED) for c in alive)
                if waiting and parked:
                    subs = []
                    for consumer in waiting:
                        consumer.state = _ATTACHED
                        subs.append(consumer.pending)
                        consumer.pending = None
                    self.round_names.append(
                        [f"{c.name}{'' if s.lite else '*'}" for c, s in zip(waiting, subs)]  # type: ignore[union-attr]
                    )
                    return subs  # type: ignore[return-value]
                self.cond.wait(timeout=1.0)

    def _broadcast(self, subs: list[_Subscription]) -> None:
        self.rounds += 1
        self.round_sizes.append(len(subs))
        round_started = time.monotonic()
        materialize = any(not sub.lite for sub in subs)
        try:
            # The head the decode-as check read is replayed, not read again.
            stream = pcap_cache.open_lite_stream(self.path)
        except Exception:
            stream = None
        status = build_statusbar(self.path, enabled=self.show_status)
        size_bytes = stream.size_bytes if stream is not None else 0
        batch: list[object] = []
        count = 0
        try:
            if stream is not None:
                try:
                    for record in stream:
                        if materialize:
                            record.materialize()
                        batch.append(record)
                        if len(batch) >= _BATCH:
                            count += len(batch)
                            if status.enabled and size_bytes:
                                status.update(int(min(100, stream.tell() * 100 / size_bytes)))
                            if not self._push(subs, batch):
                                break
                            batch = []
                except pcap_cache.IncompleteCopy:
                    # A --jobs worker's copy of the capture stopped short:
                    # nothing computed from it may stand -- abort before the
                    # analyses are told the read is over.
                    self.abort()
                    raise
                if batch:
                    count += len(batch)
                    self._push(subs, batch)
        finally:
            status.finish()
            if stream is not None:
                stream.close()
            self.records += count
            self.round_seconds.append(time.monotonic() - round_started)
            for sub in subs:
                with sub.cond:
                    sub.ended = True
                    sub.cond.notify_all()
            self._release(subs)

    def _push(self, subs: list[_Subscription], batch: list[object]) -> bool:
        """Hand ``batch`` to every live subscriber; False once none is left."""
        live = False
        for sub in subs:
            with sub.cond:
                while (
                    len(sub.buffer) >= _BUFFER_BATCHES
                    and not sub.closed
                    and not sub.detached
                    and not self.aborted
                ):
                    if self._is_blocked(sub):
                        # Waiting on an analysis that may need the next round:
                        # let it finish from its own read instead of stalling.
                        sub.detached = True
                        self.detaches += 1
                        sub.cond.notify_all()
                        self._release([sub])
                        break
                    sub.cond.wait(timeout=0.25)
                if self.aborted:
                    raise _Aborted()
                if sub.closed or sub.detached:
                    continue
                sub.buffer.append(batch)
                sub.pushed += len(batch)
                sub.cond.notify_all()
                live = True
        return live

    def _is_blocked(self, sub: _Subscription) -> bool:
        with self.cond:
            return sub.owner.state == _BLOCKED_ATTACHED

    def _release(self, subs: list[_Subscription]) -> None:
        """A consumer that waits for another analysis while its subscription
        has ended or been detached no longer holds up a round: it is parked."""
        with self.cond:
            for sub in subs:
                if sub.owner.state == _BLOCKED_ATTACHED:
                    sub.owner.state = _BLOCKED
            self.cond.notify_all()


# ---------------------------------------------------------------------------
# Hooks into pcap_cache.iter_packets and the analysis memo
# ---------------------------------------------------------------------------


def _iter_hook(path, packets, lite, prefilter, stats):  # type: ignore[no-untyped-def]
    consumer = getattr(_local, "consumer", None)
    if consumer is None or packets is not None:
        return None
    session = consumer.session
    if session.aborted or session.key != pcap_cache._path_key(path):
        return None
    return session.subscribe(consumer, lite, prefilter, stats)


def _block_hook(waiting: bool) -> None:
    consumer = getattr(_local, "consumer", None)
    if consumer is not None:
        consumer.session.blocked(consumer, waiting)


def _streams_from_disk(path: Path) -> bool:
    return pcap_cache._raw_reader_enabled() and pcap_cache._streams_from_disk(path, None)


class _Recorder:
    """Memoised calls of a dry run, with what each one calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[Callable, tuple, dict]] = []
        self.children: list[set[int]] = []
        self._stack: list[int] = []

    def enter(self, func: Callable, _path: Path, args: tuple, kwargs: dict) -> int:
        index = len(self.calls)
        self.calls.append((func, args, {k: v for k, v in kwargs.items() if k not in ("packets", "meta")}))
        self.children.append(set())
        if self._stack:
            self.children[self._stack[-1]].add(index)
        self._stack.append(index)
        return index

    def exit(self, index: int) -> None:
        if self._stack and self._stack[-1] == index:
            self._stack.pop()


class Plan:
    """Distinct memoised calls and their dependency level: 0 calls nothing
    memoised, level n needs results of level < n only."""

    def __init__(self) -> None:
        self.calls: list[tuple[Callable, tuple, dict]] = []
        self.keys: list[tuple] = []
        self.levels: list[int] = []
        self.children: list[set[int]] = []  # the calls each call needs

    def __len__(self) -> int:
        return len(self.calls)


def _saved_view(path: Path) -> tuple:
    key = pcap_cache._path_key(Path(path))
    return (
        key,
        pcap_cache._FORCED_PACKET_VIEWS.get(key),
        pcap_cache._FORCED_VIEW_SERIALS.get(key),
        key in pcap_cache._COMPLETE_VIEWS,
    )


def _restore_view(path: Path, saved: tuple) -> None:
    """Put a capture's packet view back exactly, serial included (a new serial
    would turn every result memoised for it into a miss)."""
    key, view, serial, complete = saved
    if view is None:
        pcap_cache.clear_forced_packet_view(path)
        return
    pcap_cache._FORCED_PACKET_VIEWS[key] = view
    if serial is not None:
        pcap_cache._FORCED_VIEW_SERIALS[key] = serial
    if complete:
        pcap_cache._COMPLETE_VIEWS.add(key)
    else:
        pcap_cache._COMPLETE_VIEWS.discard(key)


def discover(path: Path, roots: list[tuple[Callable, tuple, dict]]) -> Plan:
    """Every memoised call ``roots`` make, found by running them over an
    empty packet view (nothing is read from disk, nothing is memoised). A
    packet view already set for the capture (one held in memory) is put back
    before the calls are keyed, so the keys are the ones the real calls use."""
    recorder = _Recorder()
    saved = _saved_view(path)
    pcap_cache.set_forced_packet_view(path, [], None)
    saved_hook = utils._FAN_OUT_HOOK
    utils._FAN_OUT_HOOK = None
    utils._MEMO_RECORDER = recorder
    try:
        for func, args, kwargs in roots:
            call_kwargs = dict(kwargs)
            if utils._call_accepts_kwarg(func, "show_status"):
                call_kwargs["show_status"] = False
            try:
                func(path, *args, **call_kwargs)
            except Exception:  # noqa: BLE001 - a partial plan still saves reads
                pass
    finally:
        utils._MEMO_RECORDER = None
        utils._FAN_OUT_HOOK = saved_hook
        _restore_view(path, saved)
    # Merge repeated calls (same memo key) and compute levels bottom-up.
    plan = Plan()
    index_of: dict[tuple, int] = {}
    mapped: list[int] = []
    for func, args, kwargs in recorder.calls:
        key = utils._memo_key(func, path, args, kwargs)
        if key is None:
            mapped.append(-1)
            continue
        if key not in index_of:
            index_of[key] = len(plan.calls)
            plan.calls.append((func, args, kwargs))
            plan.keys.append(key)
        mapped.append(index_of[key])
    children: list[set[int]] = [set() for _ in plan.calls]
    for raw, kids in enumerate(recorder.children):
        parent = mapped[raw]
        if parent < 0:
            continue
        for kid in kids:
            if mapped[kid] >= 0 and mapped[kid] != parent:
                children[parent].add(mapped[kid])
    levels: list[int] = [-1] * len(plan.calls)

    def _level(i: int, depth: int = 0) -> int:
        if levels[i] >= 0:
            return levels[i]
        if depth > 64:
            return 0
        levels[i] = 0
        levels[i] = 1 + max((_level(k, depth + 1) for k in children[i]), default=-1)
        return levels[i]

    for i in range(len(plan.calls)):
        _level(i)
    plan.levels = levels
    plan.children = children
    return plan


def dry_run_keys(path: Path, roots: list[tuple[Callable, tuple, dict]]) -> list[tuple]:
    """The memo keys of every analysis ``roots`` would compute: the dry run
    ``run_plan`` makes (nothing read from disk, nothing memoised). A packet
    view set for the capture is put back exactly, serial included -- a new
    serial would turn every memoised result for it into a miss."""
    return list(discover(Path(path), roots).keys)


def prefetch(
    path: Path,
    calls: list[tuple[Callable, tuple, dict]],
    *,
    show_status: bool = False,
) -> Optional[SharedPass]:
    """Compute ``calls`` (memoised analyzers) over ``path`` in shared rounds.

    Results land in the analysis memo; calls already memoised are skipped.
    Returns the finished pass (None when nothing needed computing).
    """
    key = pcap_cache._path_key(path)
    with _lock:
        if key in _active_paths:
            return None
        _active_paths.add(key)
    try:
        pending: list[tuple[str, Callable[[], Any]]] = []
        for func, call_args, call_kwargs in calls:
            memo_key = utils._memo_key(func, path, call_args, call_kwargs)
            if memo_key is not None and memo_key in utils._ANALYSIS_MEMO:
                continue
            kwargs = dict(call_kwargs)
            if utils._call_accepts_kwarg(func, "show_status"):
                kwargs["show_status"] = False

            def _call(func=func, call_args=call_args, kwargs=kwargs) -> Any:  # type: ignore[no-untyped-def]
                return func(path, *call_args, **kwargs)

            pending.append((getattr(func, "__qualname__", "analysis"), _call))
        if len(pending) < 2:
            return None
        session = SharedPass(path, pending, show_status=show_status)
        started = time.monotonic()
        previous_max = utils._ANALYSIS_MEMO_MAX
        utils._ANALYSIS_MEMO_MAX = max(previous_max, len(utils._ANALYSIS_MEMO) + 2 * len(pending) + 64)
        utils._COORDINATE = True
        utils._BLOCK_HOOK = _block_hook
        pcap_cache._SHARED_PASS_HOOK = _iter_hook
        try:
            session.run()
        finally:
            pcap_cache._SHARED_PASS_HOOK = None
            utils._BLOCK_HOOK = None
            utils._COORDINATE = False
        if os.environ.get("PCAPPER_SHARED_PASS_DEBUG") == "1":
            failed = [c.name for c in session.consumers if c.error is not None]
            sys.stderr.write(
                f"[pcapper] shared pass {path.name}: {len(pending)} analyses, "
                f"{session.rounds} read(s) {session.round_sizes}, "
                f"{session.records} records, {session.detaches} detached, "
                f"{len(failed)} failed {failed[:5]}, {time.monotonic() - started:.1f}s\n"
            )
            for index, names in enumerate(session.round_names, start=1):
                if index > 1 or os.environ.get("PCAPPER_SHARED_PASS_DEBUG_ALL") == "1":
                    took = session.round_seconds[index - 1] if index - 1 < len(session.round_seconds) else 0.0
                    sys.stderr.write(f"[pcapper]   read {index} ({took:.1f}s): {', '.join(names)}\n")
        return session
    finally:
        with _lock:
            _active_paths.discard(key)


# ---------------------------------------------------------------------------
# --jobs: the same plan, spread over processes
# ---------------------------------------------------------------------------

_JOBS: Optional[int] = 1  # None: chosen per capture (jobs_for)
# The analyses of a plan form a dependency graph whose longest chain bounds
# the run however many processes share it: past this many, more cost memory
# and forks and save nothing measurable. --overview of a 20k-packet capture
# held in memory: 33.7 s in one process, 19.5 s with 4, 14.3 s with 8 and
# 14.3 s with 16 or 32 (its longest chain is ~7.7 s of the 34).
AUTO_JOBS_MAX = 8
# Without a plan to size it by (the large-capture note), a capture of this
# many packets is taken to be worth processes.
AUTO_JOBS_MIN_PACKETS = 200_000
# Forks, a worker's own read from disk and the results sent back cost about
# what this many packet-analyses (packets x analyses still to compute) do:
# --overview of 20k packets is ~2M (34 s in one process held in memory, 56 s
# from disk; 14 s and 23 s with --jobs 8).
AUTO_JOBS_MIN_WORK = 500_000
# Share of available memory forked workers may take: each one that walks the
# packets copies, page by page, about the memory they fill in the parent.
_JOBS_MEMORY_SHARE = 0.5
# More analyses than any plan holds (every flag at once is ~150): a capture
# whose packets times this stay under AUTO_JOBS_MIN_WORK is not worth a plan.
_MAX_PLAN_ANALYSES = 256


def set_jobs(jobs: Optional[int]) -> None:
    """Processes a plan may use (--jobs): None picks them per capture
    (:func:`jobs_for`); 1 keeps everything in this process."""
    global _JOBS
    _JOBS = None if jobs is None else max(1, int(jobs or 1))


def usable_cpus() -> int:
    """CPUs this process may run on (its affinity mask, not the machine's count)."""
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def auto_jobs() -> int:
    """The automatic --jobs: one process per usable CPU, at most AUTO_JOBS_MAX."""
    return max(1, min(AUTO_JOBS_MAX, usable_cpus()))


def _jobs_by_memory(packets: int) -> int:
    """Workers that fit beside a capture of ``packets`` held in memory."""
    available = pcap_cache._available_memory()
    if not available:
        return AUTO_JOBS_MAX
    per_worker = max(1, packets) * pcap_cache.PACKET_MEMORY_BYTES
    return max(1, int(available * _JOBS_MEMORY_SHARE // per_worker))


def _looks_up(plan: Plan) -> bool:
    """The plan queries a network service (VirusTotal, IP geolocation): those
    are paced and budgeted per analysis, so analyses querying at the same
    time in several processes could hit a rate limit one process never does
    -- and change the report. Automatic --jobs keeps such a run in one."""
    return any(
        kwargs.get("vt_lookup") or kwargs.get("geo_lookup") for _func, _args, kwargs in plan.calls
    )


def _worth_processes(packets: Optional[int], analyses: Optional[int]) -> bool:
    if packets is None:
        return False
    if analyses is None:
        return packets >= AUTO_JOBS_MIN_PACKETS
    return analyses >= 4 and packets * analyses >= AUTO_JOBS_MIN_WORK


def jobs_for(path: Path, *, analyses: Optional[int] = None) -> int:
    """Processes a plan of ``analyses`` analyses over ``path`` uses: the
    --jobs given, else :func:`auto_jobs` when the plan is worth spreading
    (AUTO_JOBS_MIN_WORK; without a plan, AUTO_JOBS_MIN_PACKETS) -- never more
    than it has analyses, and for a capture held in memory never more than
    its memory allows (each worker may copy the packets' pages)."""
    if not parallel_available():
        return 1
    path = Path(path)
    view = pcap_cache.get_forced_packet_view(path)
    if _JOBS is not None:
        wanted = _JOBS
    else:
        if view is not None:
            packets: Optional[int] = len(view)
        else:
            bound = pcap_cache.packets_at_most(path)
            if bound is not None and not _worth_processes(bound, analyses):
                return 1  # its size alone rules processes out: no sampled estimate
            try:
                if analyses is None:  # no plan to size (the large-capture note)
                    packets = pcap_cache.estimated_packets(path)
                else:
                    # From the head the run reads first (kept and replayed),
                    # not a sampling read of its own for a heuristic.
                    packets = pcap_cache.quick_packet_estimate(path, prime=True)
            except Exception:  # noqa: BLE001 - unknown size: stay in one process
                packets = None
        if not _worth_processes(packets, analyses):
            return 1
        wanted = auto_jobs()
    if analyses is not None:
        wanted = min(wanted, analyses)
    if view is not None:
        wanted = min(wanted, _jobs_by_memory(len(view)))
    return max(1, wanted)


def parallel_available() -> bool:
    return hasattr(os, "fork") and not sys.platform.startswith("win")


def _jobs_child(
    path: Path,
    calls: list[tuple[Callable, tuple, dict]],
    group: list[int],
    feed: Optional[int],
    result: int,
    resume: bool = False,
) -> None:
    """A --jobs worker, forked: compute ``group`` -- from the copy of the
    capture its parent sends down ``feed`` (from the file when there is none)
    -- and send back, pickled, every result it added. Never returns."""
    import pickle

    status = 1
    try:
        # The parent's waits for workers' results, its primed reader and its
        # copies are its own (the reader and the copies share file offsets and
        # pipes with it): none of them is touched here.
        utils._IN_FLIGHT.clear()
        if feed is not None:
            pcap_cache.use_feed(path, feed, resume=resume)  # takes the inherited head along
        pcap_cache.forget_primed(keep_complete=True)  # a whole capture in memory: replayed here too
        pcap_cache.forget_tees()
        before = set(utils._ANALYSIS_MEMO)
        try:
            prefetch(path, [calls[i] for i in group])
        except Exception:  # noqa: BLE001 - an aborted pass leaves no results behind
            pass
        for i in group:  # a single call (or a failed pass) still gets computed
            func, args, kwargs = calls[i]
            call_kwargs = dict(kwargs)
            if utils._call_accepts_kwarg(func, "show_status"):
                call_kwargs["show_status"] = False
            try:
                func(path, *args, **call_kwargs)
            except Exception:  # noqa: BLE001 - the parent's own call reports it
                pass
        blobs: dict = {}
        for key, value in list(utils._ANALYSIS_MEMO.items()):
            if key in before:
                continue
            try:
                blobs[key] = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
            except Exception:  # noqa: BLE001 - the parent computes it itself
                continue
        data = memoryview(pickle.dumps(blobs, protocol=pickle.HIGHEST_PROTOCOL))
        while data:
            data = data[os.write(result, data):]
        status = 0
    except BaseException:  # noqa: BLE001 - never unwind into the parent's code
        pass
    finally:
        os._exit(status)


def _grow_pipe(fd: int) -> None:
    try:
        import fcntl

        fcntl.fcntl(fd, getattr(fcntl, "F_SETPIPE_SZ", 1031), 1 << 20)
    except (ImportError, OSError, ValueError):
        pass


def _analysis_cost(func: Callable) -> float:
    """Relative cost of an analysis for balancing work (the bar's weights:
    OT protocol analyses, cheap on IT traffic, below payload-scanning IT ones)."""
    weigher = progress._WEIGHER
    module = getattr(func, "__module__", "")
    try:
        return float(weigher(module)) if weigher is not None and module else 1.0
    except Exception:  # noqa: BLE001
        return 1.0


def _balanced_groups(indices: list[int], workers: int, plan: Plan) -> list[list[int]]:
    """``indices`` split over ``workers``: the costliest first, each to the
    least-loaded worker (longest-processing-time first)."""
    loads = [0.0] * workers
    groups: list[list[int]] = [[] for _ in range(workers)]
    for i in sorted(indices, key=lambda i: (-_analysis_cost(plan.calls[i][0]), i)):
        w = min(range(workers), key=lambda w: (loads[w], w))
        groups[w].append(i)
        loads[w] += _analysis_cost(plan.calls[i][0])
    return [sorted(group) for group in groups if group]


def _parallel(path: Path, plan: Plan, jobs: int, show_status: bool) -> None:
    """Analyses that depend on no other (most of a --threats run) are split
    over ``jobs`` forked workers. They read no file: this process copies every
    byte its own read of the capture passes into a pipe per worker, which
    parses the capture from there (a capture in several part files, which
    cannot be copied so, is read by each worker). The rest run here at the
    same time, in a shared pass of their own -- the read the copies come
    from: their own packet loops first, an analysis that needs a worker's
    result waiting for it to arrive instead of computing it again."""
    import pickle
    import selectors
    import signal
    import warnings

    debug = os.environ.get("PCAPPER_SHARED_PASS_DEBUG") == "1"
    memo = utils._ANALYSIS_MEMO
    # Analyses reporting the capture's hashes stay here, where the read that
    # computes them on the way is made.
    leaves = [
        i for i, level in enumerate(plan.levels)
        if level == 0 and plan.keys[i] not in memo and not getattr(plan.calls[i][0], "reports_hashes", False)
    ]
    if len(leaves) < 2:
        prefetch(path, [plan.calls[i] for i, key in enumerate(plan.keys) if key not in memo], show_status=show_status)
        return
    leaf_set = set(leaves)
    rest_indices = [i for i, key in enumerate(plan.keys) if key not in memo and i not in leaf_set]
    rest = [plan.calls[i] for i in rest_indices]
    started = time.monotonic()
    workers = min(jobs, len(leaves))
    if _JOBS is None and rest_indices:
        # Automatic: this process works through the rest meanwhile, and the
        # run ends when it does -- workers past what keeps the leaves within
        # that time only add work. (--overview from disk: 56 s in one
        # process, 23.7 s with 2 workers, 23.3 s with 8.)
        leaf_cost = sum(_analysis_cost(plan.calls[i][0]) for i in leaves)
        rest_cost = sum(_analysis_cost(plan.calls[i][0]) for i in rest_indices)
        workers = min(workers, max(1, math.ceil(leaf_cost / max(rest_cost, 1e-9))))
    groups = _balanced_groups(leaves, workers, plan)
    # The decode-as check may have kept the whole capture (a small one read
    # from disk): each worker then replays its own copy, no pipe needed. When
    # it kept only the head, workers replay that and are copied the rest.
    # A split capture's workers are copied every part, framed, from the first.
    split = len(capture_parts(path)) > 1
    copy = pcap_cache.can_tee(path, single=True) and not pcap_cache.primed_complete(path)
    resume: object = None
    if copy:
        resume = pcap_cache.primed_part_resume(path) if split else pcap_cache.primed_resume_point(path)
    feeds: list[Optional[tuple[int, int]]] = []
    results: list[tuple[int, int]] = []
    for _group in groups:
        if copy:
            feed = os.pipe()
            _grow_pipe(feed[1])
            feeds.append(feed)
        else:
            feeds.append(None)
        results.append(os.pipe())
    pids: list[int] = []
    try:
        for index, group in enumerate(groups):
            with warnings.catch_warnings():
                # "This process is multi-threaded, use of fork() may lead to
                # deadlocks": no thread here holds a lock a worker takes
                # (progress hands its write lock over a fork).
                warnings.simplefilter("ignore", DeprecationWarning)
                pid = os.fork()
            if pid == 0:
                for other, (feed, result) in enumerate(zip(feeds, results)):
                    if feed is not None:
                        os.close(feed[1])
                        if other != index:
                            os.close(feed[0])
                    os.close(result[0])
                    if other != index:
                        os.close(result[1])
                own = feeds[index]
                _jobs_child(
                    path, plan.calls, group, own[0] if own is not None else None, results[index][1],
                    resume=resume is not None,
                )
            pids.append(pid)
    except BaseException:
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
        for feed, result in zip(feeds, results):
            for fd in (*(feed or ()), *result):
                try:
                    os.close(fd)
                except OSError:
                    pass
        raise
    sinks: list[pcap_cache.TeeSink] = []
    for feed, result in zip(feeds, results):
        if feed is not None:
            os.close(feed[0])
            sinks.append(pcap_cache.TeeSink(feed[1], name="jobs-copy"))
        os.close(result[1])
    if sinks:
        # Through the read this process makes next (or the primed one it goes
        # on with, from where its head stopped).
        if split:
            pcap_cache.tee_parts(path, sinks, resume)  # type: ignore[arg-type]
        else:
            pcap_cache.tee_capture(path, sinks, resume or 0)  # type: ignore[arg-type]

    flights: dict[tuple, utils._Flight] = {}

    def _land(key: tuple) -> None:
        """A worker's result arrived (or never will): wake whoever waits."""
        with utils._MEMO_LOCK:
            flight = flights.pop(key, None)
            if flight is not None and utils._IN_FLIGHT.get(key) is flight:
                del utils._IN_FLIGHT[key]
        if flight is not None:
            flight.event.set()

    with utils._MEMO_LOCK:
        for i in leaves:
            key = plan.keys[i]
            if key not in utils._IN_FLIGHT:
                flights[key] = utils._IN_FLIGHT[key] = utils._Flight()

    running = {results[index][0]: index for index in range(len(groups))}

    def _collect() -> None:
        selector = selectors.DefaultSelector()
        chunks: dict[int, list[bytes]] = {fd: [] for fd in running}
        try:
            for fd in running:
                selector.register(fd, selectors.EVENT_READ)
            while chunks:
                for selected, _events in selector.select():
                    fd = selected.fd
                    data = os.read(fd, 1 << 20)
                    if data:
                        chunks[fd].append(data)
                        continue
                    selector.unregister(fd)
                    index = running[fd]
                    try:
                        os.waitpid(pids[index], 0)
                    except OSError:
                        pass
                    try:
                        blobs = pickle.loads(b"".join(chunks.pop(fd)))
                    except Exception:  # noqa: BLE001 - a worker that died mid-write
                        blobs = {}
                    entries: dict = {}
                    for key, blob in blobs.items():
                        try:
                            entries[key] = pickle.loads(blob)
                        except Exception:  # noqa: BLE001
                            continue
                    with utils._MEMO_LOCK:
                        utils._ANALYSIS_MEMO_MAX = max(utils._ANALYSIS_MEMO_MAX, len(memo) + len(entries) + 64)
                        for key, value in entries.items():
                            memo.setdefault(key, value)
                    for key in entries:  # a worker's analyses are done
                        progress.subtask_done(module=str(key[0]) if isinstance(key, tuple) and key else "")
                        _land(key)
                    for i in groups[index]:  # none came back: computed by who needs it
                        _land(plan.keys[i])
        finally:
            selector.close()
            for fd in running:
                try:
                    os.close(fd)
                except OSError:
                    pass
            for key in list(flights):  # failed or not sendable: computed by who needs it
                _land(key)

    collector = threading.Thread(target=_collect, name="pcapper-jobs-results", daemon=True)
    collector.start()
    finished = False
    try:
        if rest:
            prefetch(path, rest, show_status=show_status)
        if sinks:
            # The copies no read here took up (no analysis left to run here,
            # or its pass ended before the capture did): read on for them.
            pcap_cache.feed_tees(path, parts=True)
        collector.join()
        finished = True
    finally:
        if not finished:  # interrupted: stop the workers
            for sink in sinks:
                sink.abandon()
                sink.finish()
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            collector.join(5.0)
        for key in list(flights):
            _land(key)
    if debug:
        sys.stderr.write(
            f"[pcapper] --jobs: {len(leaves)} independent analyses in {len(groups)} processes"
            f"{' fed a copy of this read' if sinks else ''}, {len(rest)} more here meanwhile, "
            f"{time.monotonic() - started:.1f}s\n"
        )
    left = [plan.calls[i] for i, key in enumerate(plan.keys) if key not in memo]
    if left:  # a worker that failed: its analyses, and what waited for them
        prefetch(path, left, show_status=show_status)


def _compute_in_child(path: Path, call: tuple[Callable, tuple, dict]) -> bytes:
    """In a forked worker: compute one analysis (what it needs is memoised
    already) and pickle every result it added, each on its own so one that
    cannot be pickled -- the parent then computes it itself -- spoils none."""
    import pickle

    func, args, kwargs = call
    before = set(utils._ANALYSIS_MEMO)
    call_kwargs = dict(kwargs)
    if utils._call_accepts_kwarg(func, "show_status"):
        call_kwargs["show_status"] = False
    try:
        func(path, *args, **call_kwargs)
    except Exception:  # noqa: BLE001 - the parent's own call reports it
        pass
    blobs: dict = {}
    for key, value in list(utils._ANALYSIS_MEMO.items()):
        if key in before:
            continue
        try:
            blobs[key] = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:  # noqa: BLE001
            continue
    return pickle.dumps(blobs, protocol=pickle.HIGHEST_PROTOCOL)


def _fork_analysis(path: Path, call: tuple[Callable, tuple, dict]) -> tuple[int, int]:
    """Start one analysis in a forked worker: (read end of its pipe, pid)."""
    import warnings

    read_end, write_end = os.pipe()
    with warnings.catch_warnings():
        # "This process is multi-threaded, use of fork() may lead to
        # deadlocks": the threads here (the bar's ticker) hold no lock a
        # worker takes -- progress hands its write lock over a fork.
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
    if pid == 0:
        status = 1
        try:
            os.close(read_end)
            pcap_cache.forget_primed()
            pcap_cache.forget_tees()
            data = memoryview(_compute_in_child(path, call))
            while data:
                data = data[os.write(write_end, data):]
            status = 0
        except BaseException:  # noqa: BLE001 - never unwind into the parent's code
            pass
        finally:
            os._exit(status)
    os.close(write_end)
    return read_end, pid


def _parallel_in_memory(path: Path, plan: Plan, jobs: int) -> int:
    """The plan over a capture held in memory, ``jobs`` analyses at a time,
    each in a process forked once every analysis it needs is done: it finds
    them -- and the packets -- in the memory it shares with this one (no
    read, no copy of the packets), and sends back only what it computed.
    The analyses the longest chains wait for start first. Returns how many
    results came back; what failed or could not be sent stays for the run."""
    import gc
    import pickle
    import selectors
    import signal

    memo = utils._ANALYSIS_MEMO
    todo = {i for i, key in enumerate(plan.keys) if key not in memo}
    if len(todo) < 2:
        return 0
    parents: list[list[int]] = [[] for _ in plan.calls]
    for i, kids in enumerate(plan.children):
        for kid in kids:
            parents[kid].append(i)
    height: dict[int, int] = {}

    def _height(i: int, depth: int = 0) -> int:
        if i in height:
            return height[i]
        if depth > 64:
            return 0
        height[i] = 0
        height[i] = 1 + max((_height(p, depth + 1) for p in parents[i]), default=0)
        return height[i]

    for i in todo:
        _height(i)
    with utils._MEMO_LOCK:
        utils._ANALYSIS_MEMO_MAX = max(utils._ANALYSIS_MEMO_MAX, len(memo) + 2 * len(plan) + 64)
    debug = os.environ.get("PCAPPER_SHARED_PASS_DEBUG") == "1"
    started = time.monotonic()
    selector = selectors.DefaultSelector()
    running: dict[int, list] = {}  # pipe -> [pid, plan index, chunks]
    returned = forked = 0
    # Frozen: the collector never walks (and so never copies into a worker)
    # the objects that exist now -- above all the packets.
    gc.freeze()
    try:
        while True:
            ready = sorted(
                (i for i in todo if all(plan.keys[k] in memo for k in plan.children[i])),
                key=lambda i: (-height[i], i),
            )
            for i in ready:
                if len(running) >= jobs:
                    break
                todo.discard(i)
                read_end, pid = _fork_analysis(path, plan.calls[i])
                forked += 1
                running[read_end] = [pid, i, []]
                selector.register(read_end, selectors.EVENT_READ)
            if not running:
                break  # all done, or the rest wait for an analysis that failed
            for selected, _events in selector.select():
                read_end = selected.fd
                entry = running[read_end]
                chunk = os.read(read_end, 1 << 20)
                if chunk:
                    entry[2].append(chunk)
                    continue
                selector.unregister(read_end)
                os.close(read_end)
                del running[read_end]
                os.waitpid(entry[0], 0)
                try:
                    blobs = pickle.loads(b"".join(entry[2])) if entry[2] else {}
                except Exception:  # noqa: BLE001 - a worker that died mid-write
                    blobs = {}
                for key, blob in blobs.items():
                    if key in memo:
                        continue
                    try:
                        value = pickle.loads(blob)
                    except Exception:  # noqa: BLE001
                        continue
                    utils._memo_store(key, value, False)
                    returned += 1
                    progress.subtask_done(module=str(key[0]) if isinstance(key, tuple) and key else "")
    finally:
        for read_end, entry in running.items():  # interrupted: stop the rest
            try:
                os.kill(entry[0], signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(entry[0], 0)
            except OSError:
                pass
            try:
                os.close(read_end)
            except OSError:
                pass
        selector.close()
        gc.unfreeze()
    if debug:
        sys.stderr.write(
            f"[pcapper] --jobs {jobs} (in memory): {forked} analyses in forked workers, "
            f"{returned} results, {len(todo)} left to the run, {time.monotonic() - started:.1f}s\n"
        )
    return returned


def _run_in_memory(path: Path, roots: list[tuple[Callable, tuple, dict]]) -> bool:
    """A plan over a capture held in memory has nothing to read: it runs only
    to spread its analyses over processes (--jobs). True when it did."""
    view = pcap_cache.get_forced_packet_view(path)
    if _JOBS == 1 or os.getpid() != _MAIN_PID or not parallel_available() or view is None:
        return False
    if _JOBS is None and len(view) * _MAX_PLAN_ANALYSES < AUTO_JOBS_MIN_WORK:
        return False  # too small to gain whatever the plan: no dry run
    plan = discover(path, roots)
    todo = sum(1 for key in plan.keys if key not in utils._ANALYSIS_MEMO)
    jobs = 1 if _JOBS is None and _looks_up(plan) else jobs_for(path, analyses=todo)
    if jobs < 2 or todo < 2:
        return False
    try:
        _parallel_in_memory(path, plan, jobs)
    except Exception as exc:  # noqa: BLE001 - fall back to one process
        sys.stderr.write(f"--jobs: parallel analysis failed ({type(exc).__name__}: {exc}); continuing in one process.\n")
    return True


def run_plan(
    path: Path,
    roots: list[tuple[Callable, tuple, dict]],
    *,
    show_status: bool = False,
    decode_ports: bool = True,
    ahead: bool = False,
) -> bool:
    """Compute everything ``roots`` will need from ``path``: one shared read
    per dependency round, over ``set_jobs()`` processes. True when a plan ran.

    ``decode_ports``: first find OT protocols on non-standard ports (a read of
    its own, cached per capture), since what OT analyzers see -- and the memo
    keys -- depend on it. A plan of analyses that never consult the port
    overrides (the file analysis an --http or --tls run nests) skips it.
    ``ahead``: even a plan of one analysis, now -- a copy of the run's read
    (Suricata, tshark) waits for it, and a step before that analysis's own
    would otherwise read the capture for the copy, and the analysis again."""
    if not enabled() or getattr(_local, "consumer", None) is not None:
        return False
    path = Path(path)
    if not _streams_from_disk(path):
        return _run_in_memory(path, roots)
    if decode_ports:
        try:
            from .port_heuristics import auto_decode

            auto_decode(path)  # register non-standard ports before the plan is made
        except Exception:  # noqa: BLE001
            pass
    plan = discover(path, roots)
    if len(plan) < (1 if ahead else 2):
        return False
    if len(plan) == 1:
        # One analysis, read now (no pass to share): its own read, earlier.
        func, call_args, call_kwargs = plan.calls[0]
        kwargs = dict(call_kwargs)
        if utils._call_accepts_kwarg(func, "show_status"):
            kwargs["show_status"] = show_status
        func(path, *call_args, **kwargs)
        return True
    jobs = (
        1 if _JOBS is None and _looks_up(plan)
        else jobs_for(path, analyses=sum(1 for key in plan.keys if key not in utils._ANALYSIS_MEMO))
    )
    if jobs > 1 and parallel_available() and os.getpid() == _MAIN_PID:
        try:
            _parallel(path, plan, jobs, show_status)
            return True
        except Exception as exc:  # noqa: BLE001 - fall back to one process
            sys.stderr.write(f"--jobs: parallel analysis failed ({type(exc).__name__}: {exc}); continuing in one process.\n")
    return prefetch(path, plan.calls, show_status=show_status) is not None


_MAIN_PID = os.getpid()


# Orchestrators none of whose analyses consult the decode-as port overrides:
# their plan needs no port-detection read first.
_PORT_INSENSITIVE_ORCHESTRATORS = frozenset({"analyze_files"})


def consuming(path: Path) -> bool:
    """This thread runs an analysis of a shared pass over ``path``: a read of
    the capture from here is served by the pass (iter_packets), not the disk."""
    consumer = getattr(_local, "consumer", None)
    return (
        consumer is not None
        and not consumer.session.aborted
        and consumer.session.key == pcap_cache._path_key(Path(path))
    )


def ahead(path: Path, call: Callable[[], Any]) -> Optional[Callable[[], Any]]:
    """Start ``call`` -- a packet loop of the running analysis that needs none
    of the results it is about to wait for -- now, on a consumer thread of its
    own, when the analysis runs in a shared pass over ``path``: the loop then
    reads in the round that computes those results instead of in a round (a
    read of the capture) of its own after them. Returns the function that hands
    over its result; None outside a shared pass, where the caller runs
    ``call`` at its place as before."""
    if not consuming(path):
        return None
    consumer = _local.consumer
    return consumer.session.spawn(consumer, call)


def _fan_out_hook(func: Callable, path: Path, args: tuple, kwargs: dict) -> bool:
    """``utils.fan_out`` calls this before running an orchestrator."""
    if kwargs.get("packets") is not None:
        return False
    if hasattr(func, "__wrapped__"):  # memoised orchestrator already computed?
        key = utils._memo_key(func, Path(path), args, kwargs)
        if key is not None and key in utils._ANALYSIS_MEMO:
            return False
    return run_plan(
        Path(path), [(func, args, dict(kwargs))], show_status=bool(kwargs.get("show_status", False)),
        decode_ports=getattr(func, "__name__", "") not in _PORT_INSENSITIVE_ORCHESTRATORS,
    )


def install() -> None:
    utils._FAN_OUT_HOOK = _fan_out_hook
    # A CLI run shares each dissected packet between its analyzers: build a
    # TLS-family layer's bytes once for all of them (_cached_tls_bytes), and
    # keep each in-memory packet's layer lookups (pcap_cache.install_layer_memo).
    _guard_scapy_builds()
    pcap_cache.install_layer_memo()
