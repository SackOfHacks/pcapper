"""TriStation (Triconex safety controller engineering protocol, UDP 1502).

TriStation is what TRITON/TRISIS spoke to the Triconex SIS at Petro Rabigh.
Frame layout and code tables follow Nozomi Networks' Wireshark dissector
(tricotools ``TriStation.lua``, the public reference):

    TCM frame:   type (1) | channel (1) | length (2, LE) | TS block | CRC16 (2)
    TS block:    direction (1: 0 = workstation->controller, 1 = reply)
                 | connection id (1) | command (1) | sequence (1)
                 | unknown (2) | checksum (2) | TS length (2, LE, incl. header)
                 | payload

The function names are the dissector's, kept verbatim except for obvious
typos; reply (0x64-0xAA) and reject (0xC8+) codes come from the same table.
"""

from __future__ import annotations

from dataclasses import dataclass

TRISTATION_PORT = 1502

TCM_TYPES = {
    0x01: "CONNECT REQUEST",
    0x02: "CONNECT REPLY",
    0x03: "DISCONNECT REPLY",
    0x04: "DISCONNECT REQUEST",
    0x05: "COMMAND",
    0x06: "PING",
    0x07: "CONNECTION LIMIT REACHED",
    0x08: "NOT CONNECTED",
    0x09: "MPS ARE DEAD",
    0x0A: "ACCESS DENIED",
    0x0B: "CONNECTION FAILED",
}

FUNCTIONS = {
    0x00: "Start download all", 0x01: "Start download change", 0x02: "Update configuration",
    0x03: "Upload configuration", 0x04: "Set I/O addresses", 0x05: "Allocate network",
    0x06: "Load vector table", 0x07: "Set calendar", 0x08: "Get calendar",
    0x09: "Set scan time", 0x0A: "End download all", 0x0B: "End download change",
    0x0C: "Cancel download change", 0x0D: "Attach TRICON", 0x0E: "Set I/O address limits",
    0x0F: "Configure module", 0x10: "Set multiple point values", 0x11: "Enable all points",
    0x12: "Upload vector table", 0x13: "Get CP status", 0x14: "Run program",
    0x15: "Halt program", 0x16: "Pause program", 0x17: "Do single scan",
    0x18: "Get chassis status", 0x19: "Get minimum scan time", 0x1A: "Set node number",
    0x1B: "Set I/O point values", 0x1C: "Get I/O point values", 0x1D: "Get MP status",
    0x1E: "Set retentive values", 0x1F: "Adjust clock calendar", 0x20: "Clear module alarms",
    0x21: "Get event log", 0x22: "Set SOE block", 0x23: "Record event log",
    0x24: "Get SOE data", 0x25: "Enable OVD", 0x26: "Disable OVD", 0x27: "Enable all OVDs",
    0x28: "Disable all OVDs", 0x29: "Process MODBUS", 0x2A: "Upload network",
    0x2B: "Set label", 0x2C: "Configure system variables", 0x2D: "Deconfigure module",
    0x2E: "Get system variables", 0x2F: "Get module types",
    0x30: "Begin conversion table download", 0x31: "Continue conversion table download",
    0x32: "End conversion table download", 0x33: "Get conversion table",
    0x34: "Set ICM status", 0x35: "Broadcast SOE data available", 0x36: "Get module versions",
    0x37: "Allocate program", 0x38: "Allocate function", 0x39: "Clear retentives",
    0x3A: "Set initial values", 0x3B: "Start TS2 program download", 0x3C: "Set TS2 data area",
    0x3D: "Get TS2 data", 0x3E: "Set TS2 data", 0x3F: "Set program information",
    0x40: "Get program information", 0x41: "Upload program", 0x42: "Upload function",
    0x43: "Get point groups", 0x44: "Allocate symbol table", 0x45: "Get I/O address",
    0x46: "Resend I/O address", 0x47: "Get program timing", 0x48: "Allocate multiple functions",
    0x49: "Get node number", 0x4A: "Get symbol table", 0x50: "Go to DOWNLOAD mode",
    # replies
    0x64: "Command rejected", 0x65: "Download all permitted", 0x66: "Download change permitted",
    0x67: "Modification accepted", 0x68: "Download cancelled", 0x69: "Program accepted",
    0x6A: "TRICON attached", 0x6B: "I/O addresses set", 0x6C: "Get CP status response",
    0x6D: "Program is running", 0x6E: "Program is halted", 0x6F: "Program is paused",
    0x70: "End of single scan", 0x71: "Get chassis configuration response",
    0x72: "Scan period modified", 0x75: "Module configured",
    0x77: "Get chassis status response", 0x78: "Vectors response",
    0x79: "Get I/O point values response", 0x7A: "Calendar changed",
    0x7B: "Configuration updated", 0x7C: "Get minimum scan time response",
    0x7E: "Node number set", 0x7F: "Get MP status response", 0x80: "Retentive values set",
    0x81: "SOE block set", 0x82: "Module alarms cleared", 0x83: "Get event log response",
    0x84: "Symbol table accepted", 0x85: "OVD enable accepted", 0x86: "OVD disable accepted",
    0x87: "Record event log response", 0x88: "Upload network response",
    0x89: "Get SOE data response", 0x8A: "Allocate network accepted",
    0x8B: "Load vector table accepted", 0x8C: "Get calendar response", 0x8D: "Label set",
    0x8E: "Get module types response", 0x8F: "System variables configured",
    0x90: "Module deconfigured", 0x93: "Get conversion table response",
    0x94: "ICM print data sent", 0x95: "Set ICM status response",
    0x96: "Get system variables response", 0x97: "Get module versions response",
    0x98: "Process MODBUS response", 0x99: "Allocate program response",
    0x9A: "Allocate function response", 0x9B: "Clear retentives response",
    0x9C: "Set initial values response", 0x9D: "Set TS2 data area response",
    0x9E: "Get TS2 data response", 0x9F: "Set TS2 data response",
    0xA0: "Set program information response", 0xA1: "Get program information response",
    0xA2: "Upload program response", 0xA3: "Upload function response",
    0xA4: "Get point groups response", 0xA5: "Allocate symbol table response",
    0xA6: "Program timing response", 0xA7: "Disable points full",
    0xA8: "Allocate multiple functions response", 0xA9: "Get node number response",
    0xAA: "Symbol table response",
    # rejects
    0xC8: "Wrong command", 0xC9: "Load is in progress", 0xCA: "Bad clock calendar data",
    0xCB: "Control program not halted", 0xCC: "Control program checksum error",
    0xCD: "No memory available", 0xCE: "Control program not valid",
    0xCF: "Not loading a control program", 0xD0: "Network is out of range",
    0xD1: "Not enough arguments", 0xD2: "A network is missing",
    0xD3: "The download time mismatches", 0xD4: "Key setting prohibits this operation",
    0xD5: "Bad control program version", 0xD6: "Command not in correct sequence",
    0xD8: "Bad index for a module", 0xD9: "Module address is invalid",
    0xDC: "Bad offset for an I/O point", 0xDD: "Invalid point type",
    0xDE: "Invalid point location", 0xDF: "Program name is invalid",
    0xE3: "Invalid module type", 0xE5: "Invalid table type",
    0xE7: "Invalid network continuation", 0xE8: "Invalid scan time", 0xE9: "Load is busy",
    0xEB: "Invalid chassis or slot", 0xEC: "Invalid SOE number", 0xED: "Invalid SOE type",
    0xEE: "Invalid SOE state", 0xEF: "The variable is write protected",
    0xF0: "Node number mismatch", 0xF1: "Command not allowed",
    0xF2: "Invalid sequence number", 0xF3: "Time change on non-master TRICON",
    0xF4: "No free TriStation ports", 0xF5: "Invalid TriStation I command",
    0xF6: "Invalid TriStation 1131 command", 0xF7: "Only one chassis allowed",
    0xF8: "Bad variable address", 0xF9: "Response overflow", 0xFA: "Invalid bus",
    0xFB: "Disable is not allowed", 0xFC: "Invalid length",
    0xFD: "Point cannot be disabled", 0xFE: "Too many retentive variables",
    0xFF: "LOADER_CONNECT",
}

KEY_STATES = {0: "STOP", 1: "PROGRAM", 2: "RUN", 3: "REMOTE"}
RUN_STATES = {0: "Running", 1: "Halted", 2: "Paused"}

# What each command does to a safety controller, for triage.
PROGRAM_CHANGE = {0x00, 0x01, 0x0A, 0x0B, 0x37, 0x38, 0x3B, 0x3C, 0x3E, 0x3F, 0x44, 0x48, 0x50}
MODE_CHANGE = {0x14, 0x15, 0x16, 0x17}
POINT_WRITE = {0x10, 0x1B, 0x1E, 0x39, 0x3A, 0x11}
SAFETY_DISABLE = {0x26, 0x28}
PROGRAM_UPLOAD = {0x03, 0x12, 0x2A, 0x33, 0x41, 0x42, 0x4A}
CONFIG_CHANGE = {0x02, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0E, 0x0F, 0x1A, 0x1F, 0x20, 0x22, 0x2B, 0x2C, 0x2D, 0x34}
STATUS_READ = {0x08, 0x13, 0x18, 0x19, 0x1C, 0x1D, 0x21, 0x24, 0x2E, 0x2F, 0x36, 0x40, 0x43, 0x45, 0x47, 0x49}


def function_name(code: int) -> str:
    return FUNCTIONS.get(code, f"Function 0x{code:02x}")


@dataclass(frozen=True)
class TriStationFrame:
    tcm_type: int
    channel: int
    direction: int | None  # 0 workstation->controller, 1 controller->workstation
    connection_id: int | None
    command: int | None
    sequence: int | None
    payload: bytes

    @property
    def tcm_name(self) -> str:
        return TCM_TYPES.get(self.tcm_type, f"TCM 0x{self.tcm_type:02x}")

    @property
    def is_reply(self) -> bool:
        return self.direction == 1

    @property
    def is_reject(self) -> bool:
        return self.command is not None and (self.command == 0x64 or self.command >= 0xC8)

    @property
    def key_state(self) -> str | None:
        """Key switch position from a 'Get CP status response'."""
        if self.command == 0x6C and len(self.payload) > 7:
            return KEY_STATES.get(self.payload[7])
        return None

    @property
    def run_state(self) -> str | None:
        if self.command == 0x6C and len(self.payload) > 8:
            return RUN_STATES.get(self.payload[8])
        return None

    @property
    def project_name(self) -> str | None:
        """Project name carried in a 'Get CP status response' (10 chars)."""
        if self.command != 0x6C or len(self.payload) < 76:
            return None
        raw = self.payload[66:76].split(b"\x00", 1)[0]
        text = raw.decode("ascii", errors="ignore").strip()
        return text if text and text.isprintable() else None


def parse_frame(data: bytes) -> TriStationFrame | None:
    """Parse one TCM frame; None when the bytes are not TriStation.

    Structural: the TCM length must account for the UDP payload exactly
    (header 4 + data + CRC 2), and a command frame's TS length must fit.
    """
    if len(data) < 6 or data[0] not in TCM_TYPES:
        return None
    length = data[2] | (data[3] << 8)
    if 4 + length + 2 != len(data):
        return None
    block = data[4:4 + length]
    if data[0] != 0x05 or len(block) < 10:
        return TriStationFrame(data[0], data[1], None, None, None, None, b"")
    ts_len = block[8] | (block[9] << 8)
    if block[0] not in (0, 1) or ts_len > len(block) or ts_len < 10:
        return None
    return TriStationFrame(
        tcm_type=data[0],
        channel=data[1],
        direction=block[0],
        connection_id=block[1],
        command=block[2],
        sequence=block[3],
        payload=bytes(block[10:ts_len]),
    )
