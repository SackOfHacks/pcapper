"""Registry of the table-driven OT analyzers (KNXnet/IP, XGT FEnet, ROC Plus ...).

Each entry is everything the CLI, ``--overview``, ``--threats`` and
``--ot-commands`` need to wire one analyzer in: the step/flag name, labels,
registered ports, inventory tokens and the analyzer function. All of them
return :class:`~pcapper.industrial_helpers.IndustrialAnalysis`, so the shared
renderer, merge and command plumbing apply unchanged. Adding a protocol is
one entry here.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class OtAnalyzerSpec:
    step: str
    flag: str
    label: str  # display / module label
    title: str  # report section title
    help: str
    ports: tuple[int, ...]  # registered ports (overview port hints)
    tokens: tuple[str, ...]  # protocol/service inventory tokens (overview)
    module: str
    function: str

    def analyzer(self) -> Callable[..., object]:
        return getattr(importlib.import_module(f"pcapper.{self.module}"), self.function)


OT_EXTRA: tuple[OtAnalyzerSpec, ...] = (
    OtAnalyzerSpec(
        "knx", "--knx", "KNXnet/IP", "KNXNET/IP ANALYSIS",
        "Include KNXnet/IP building-automation analysis (group writes, bus/net scans, device resets, fuzzing).",
        (3671,), ("knx", "knxnet", "knxip", "eib"), "knx", "analyze_knx",
    ),
    OtAnalyzerSpec(
        "xgt", "--xgt", "XGT FEnet", "LS XGT FEnet ANALYSIS",
        "Include LS ELECTRIC XGT FEnet analysis (variable reads/writes, written values).",
        (2004, 2005), ("xgt", "fenet", "lsis"), "xgt", "analyze_xgt",
    ),
    OtAnalyzerSpec(
        "rocplus", "--rocplus", "ROC Plus", "ROC PLUS ANALYSIS",
        "Include Emerson ROC Plus analysis (opcodes, cleartext logins, parameter writes, file transfer).",
        (4000,), ("roc plus", "rocplus", "roc800"), "rocplus", "analyze_rocplus",
    ),
    OtAnalyzerSpec(
        "ads", "--ads", "ADS/AMS", "BECKHOFF ADS/AMS ANALYSIS",
        "Include Beckhoff ADS/AMS analysis (TwinCAT commands, AddRoute credentials, state changes).",
        (48898, 48899), ("ads/ams", "beckhoff", "twincat", "ams"), "ads", "analyze_ads",
    ),
    OtAnalyzerSpec(
        "dlms", "--dlms", "DLMS/COSEM", "DLMS/COSEM ANALYSIS",
        "Include DLMS/COSEM smart-meter analysis (OBIS objects, LLS passwords, disconnect, firmware).",
        (4059,), ("dlms", "cosem"), "dlms", "analyze_dlms",
    ),
    OtAnalyzerSpec(
        "c1222", "--c1222", "C12.22", "ANSI C12.22 ANALYSIS",
        "Include ANSI C12.22 smart-meter analysis (EPSEM services, cleartext logon/security, table writes).",
        (1153,), ("c12.22", "c1222"), "c1222", "analyze_c1222",
    ),
    OtAnalyzerSpec(
        "lontalk", "--lontalk", "LonTalk", "LONTALK (CN/IP) ANALYSIS",
        "Include LonTalk/CN-IP building-automation analysis (NV updates, network management writes).",
        (1628, 1629), ("lontalk", "lonworks", "cn/ip", "cnip"), "lontalk", "analyze_lontalk",
    ),
    OtAnalyzerSpec(
        "powerlink", "--powerlink", "POWERLINK", "ETHERNET POWERLINK ANALYSIS",
        "Include Ethernet POWERLINK analysis (cycle frames, NMT stop/reset, SDO writes, rogue MN).",
        (3819,), ("powerlink", "epl", "0x88ab"), "powerlink", "analyze_powerlink",
    ),
)

BY_STEP: dict[str, OtAnalyzerSpec] = {spec.step: spec for spec in OT_EXTRA}
