"""Rendered output for --pcapmeta: the capture file itself -- format, size,
link type, snap length, the capturing interfaces (pcapng IDBs: name, OS,
hardware) and any drops the capturing host recorded."""

from __future__ import annotations

from ..pcapmeta import PcapMetaSummary
from ..utils import is_gzip_file
from . import _style as st

# The common DLT/LINKTYPE values (tcpdump.org/linktypes.html).
LINKTYPES = {
    0: "BSD loopback", 1: "Ethernet", 6: "Token Ring", 9: "PPP", 10: "FDDI", 12: "raw IP", 101: "raw IP", 104: "Cisco HDLC",
    105: "802.11", 108: "OpenBSD loopback", 113: "Linux cooked (SLL)", 119: "802.11 Prism", 127: "802.11 radiotap",
    143: "DOCSIS", 187: "Bluetooth HCI H4", 189: "USB (Linux)", 195: "802.15.4", 201: "Bluetooth HCI H4 + pseudo-header",
    220: "USB (Linux mmapped)", 228: "raw IPv4", 229: "raw IPv6", 230: "802.15.4 (no FCS)", 239: "Netlink", 249: "USBPcap",
    276: "Linux cooked v2 (SLL2)",
}
# pcapng IDB options in the order an analyst reads them; the rest follow.
_IDB_ORDER = ("id", "if_name", "if_description", "linktype", "snaplen", "if_os", "if_hardware", "if_speed", "if_tsresol",
              "if_filter", "dropcount")


def linktype_text(value: object, *, number: bool = True) -> str:
    """``Ethernet (1)``; scapy's table names the rarer link types."""
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value)
    if not isinstance(value, int):
        return str(value) if value not in (None, "") else "-"
    name = LINKTYPES.get(value)
    if name is None:
        try:
            from scapy.data import l2types  # type: ignore

            mapped = l2types.get(value)
            name = getattr(mapped, "__name__", None) or (str(mapped) if mapped is not None else None)
        except Exception:
            name = None
    if name is None:
        return f"LINKTYPE_{value}"
    return f"{name} ({value})" if number else name


def render_pcapmeta_summary(summary: PcapMetaSummary) -> str:
    rep = st.Report("Capture file", summary.path)
    gzipped = " (gzip)" if is_gzip_file(summary.path) else ""
    rep.headline(False, st.join([f"{summary.file_type}{gzipped}", st.size(summary.size_bytes), linktype_text(summary.linktype),
                                 f"snaplen {summary.snaplen}" if summary.snaplen else ""]),
                 st.join([st.plural(summary.interface_count, "interface") if summary.interface_count else "",
                          (st.bad(f"{summary.dropcount} packets dropped") if summary.dropcount else "no drops recorded")
                          if summary.dropcount is not None else ""]))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    details = [d for d in (summary.interface_details or []) if isinstance(d, dict)]
    keys = [k for k in _IDB_ORDER if any(k in d for d in details)]
    keys += sorted({k for d in details for k in d} - set(keys))
    if not st.verbose():
        keys = [k for k in keys if k in ("if_name", "if_description", "linktype", "snaplen", "if_os", "if_hardware", "dropcount")]
    rep.section("Interfaces", st.table(
        [k.removeprefix("if_").replace("_", " ").capitalize() for k in keys],
        [[linktype_text(d.get(k)) if k == "linktype" else ("-" if d.get(k) in (None, "") else d.get(k)) for k in keys] for d in details],
        max_rows=10, noun="interface",
    ))
    rep.section("File", st.kv([("Path", str(summary.path)), ("Size", f"{summary.size_bytes} bytes"),
                               ("Interface names", ", ".join(summary.interface_names))]), detail=True)
    return rep.render()
