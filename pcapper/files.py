from __future__ import annotations

import re
import base64
import hashlib
import struct
import gzip
import zlib
import email
import socket
from email import policy
from collections import defaultdict, Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any, Set
from urllib.parse import unquote, urlsplit

from .pcap_cache import get_cached_packets, get_reader
from scapy.packet import Raw, Packet

try:
    import dpkt
except Exception:  # pragma: no cover
    dpkt = None

from .utils import safe_float, detect_file_type_bytes
from .cip import CIP_SERVICE_NAMES

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
except Exception:
    IP = TCP = UDP = IPv6 = None

# --- Dataclasses ---

@dataclass
class FileArtifact:
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    filename: str
    size_bytes: Optional[int]
    packet_index: int
    note: Optional[str]
    file_type: str = "UNKNOWN"
    payload: Optional[bytes] = None


@dataclass
class FileTransfer:
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    packets: int
    bytes: int
    first_seen: Optional[float]
    last_seen: Optional[float]
    note: Optional[str]


@dataclass
class FileTransferSummary:
    path: Path
    total_candidates: int
    candidates: List[FileTransfer]
    artifacts: List[FileArtifact]
    extracted: List[Path]
    views: List[Any]
    detections: List[Dict[str, str]]
    errors: List[str]

# --- Helper Functions ---

FILE_TRANSFER_PROTOCOLS = {
    "HTTP",
    "HTTPS/SSL",
    "FTP",
    "TFTP",
    "SMB",
    "IMAP",
    "POP3",
    "SMTP",
    "NFS",
    "ENIP",
}

FILE_TYPE_EXTENSIONS: dict[str, set[str]] = {
    "EXE/DLL": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"},
    "PDF": {".pdf"},
    "ZIP/Office": {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods", ".odp", ".docm", ".xlsm", ".pptm"},
    "ELF": {".elf", ".so", ".bin", ".out"},
    "PNG": {".png"},
    "JPG": {".jpg", ".jpeg"},
    "GIF": {".gif"},
    "GZIP": {".gz", ".tgz", ".gzip"},
    "HTML": {".html", ".htm", ".xhtml", ".shtml"},
    "X509": {".cer", ".crt", ".pem", ".der", ".p7b", ".pfx", ".p12"},
    "DICOM": {".dcm"},
}

ENIP_TCP_PORT = 44818
ENIP_UDP_PORT = 2222
ENIP_HEADER_LEN = 24

ENIP_COMMANDS = {
    0x0001: "NOP",
    0x0004: "ListServices",
    0x0063: "ListIdentity",
    0x0064: "ListInterfaces",
    0x0065: "RegisterSession",
    0x0066: "UnregisterSession",
    0x0067: "SendRRData",
    0x0068: "SendUnitData",
    0x0069: "IndicateStatus",
    0x006A: "Cancel",
    0x006B: "FindNextObjectInstance",
    0x006C: "ReadObjectInstanceAttributes",
    0x006D: "WriteObjectInstanceAttributes",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
}

def _flow_protocol(sport: Optional[int], dport: Optional[int]) -> str:
    ports = set(filter(None, [sport, dport]))
    if 80 in ports or 8080 in ports or 8000 in ports:
        return "HTTP"
    if 443 in ports or 8443 in ports:
        return "HTTPS/SSL"
    if 21 in ports:
        return "FTP"
    if 22 in ports:
        return "SSH"
    if 23 in ports:
        return "TELNET"
    if 25 in ports:
        return "SMTP"
    if 53 in ports:
        return "DNS"
    if 69 in ports:
        return "TFTP"
    if 445 in ports or 139 in ports:
        return "SMB"
    if 110 in ports:
        return "POP3"
    if 143 in ports:
        return "IMAP"
    if 2049 in ports:
        return "NFS"
    if 3389 in ports:
        return "RDP"
    if 3306 in ports:
        return "MYSQL"
    if ENIP_TCP_PORT in ports or ENIP_UDP_PORT in ports:
        return "ENIP"
    return "UNKNOWN"


def _extension_mismatch(filename: str, file_type: str) -> Optional[tuple[str, set[str]]]:
    if not filename or not file_type:
        return None
    expected = FILE_TYPE_EXTENSIONS.get(file_type.upper())
    if not expected:
        return None
    ext = Path(filename).suffix.lower()
    if not ext:
        return None
    if ext in expected:
        return None
    return ext, expected

def _normalize_filename(name: str) -> str:
    try:
        # Strip path traversal
        clean = Path(name).name
        # Remove nulls and suspicious chars
        clean = re.sub(r'[^\w\-.()\[\] ]', '_', clean)
        return clean if clean else "unknown_file"
    except Exception:
        return "unknown_file"


def _unique_output_path(base_dir: Path, filename: str) -> Path:
    candidate = base_dir / filename
    if not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    for idx in range(1, 10000):
        alt = base_dir / f"{stem}_{idx}{suffix}"
        if not alt.exists():
            return alt
    return base_dir / f"{stem}_{hashlib.sha256(filename.encode('utf-8', errors='ignore')).hexdigest()[:8]}{suffix}"

def _extract_tftp(payload: bytes) -> Optional[str]:
    if len(payload) < 4:
        return None
    opcode = int.from_bytes(payload[0:2], "big")
    if opcode not in {1, 2}:
        return None
    rest = payload[2:]
    if b"\x00" not in rest:
        return None
    name_bytes = rest.split(b"\x00", 1)[0]
    try:
        return name_bytes.decode("latin-1", errors="ignore")
    except Exception:
        return None

def _decode_chunked(body: bytes) -> bytes:
    out = bytearray()
    idx = 0
    while idx < len(body):
        line_end = body.find(b"\r\n", idx)
        if line_end == -1:
            break
        size_line = body[idx:line_end].split(b";", 1)[0]
        try:
            size_val = int(size_line.strip(), 16)
        except Exception:
            break
        idx = line_end + 2
        if size_val == 0:
            break
        if idx + size_val > len(body):
            out.extend(body[idx:]) # Partial
            break
        out.extend(body[idx:idx + size_val])
        idx += size_val + 2
    return bytes(out)

def _extract_request_filename(start_line: str, host: Optional[str] = None) -> Optional[str]:
    try:
        parts = start_line.split(" ")
        if len(parts) < 2:
            return None
        path_part = parts[1]

        if path_part.startswith("http://") or path_part.startswith("https://"):
            try:
                parsed = urlsplit(path_part)
                path_part = parsed.path or "/"
            except Exception:
                pass
        
        path_part = path_part.split('?')[0].split('#')[0]
        if path_part == "/":
            return None
            
        name = path_part.split("/")[-1]
        
        # Check query params in original
        if '?' in parts[1]:
            query = parts[1].split('?', 1)[1]
            for param in query.split('&'):
                if '=' in param:
                    key, val = param.split('=', 1)
                    if key.lower() in ('file', 'filename', 'download', 'name'):
                        fval = unquote(val)
                        if fval and '.' in fval:
                            return fval
        
        if name and '.' in name:
            return name
        
        return None
    except Exception:
        return None

def _assemble_stream(chunks: List[Tuple[int, bytes, int]], limit: int = 50_000_000) -> Tuple[bytes, int]:
    if not chunks:
        return b"", 0
    # Sort by seq
    chunks.sort(key=lambda item: item[0])
    
    assembled = bytearray()
    first_packet = min(item[2] for item in chunks)
    
    expected_seq = chunks[0][0] # Start with first available
    
    for seq, payload, _ in chunks:
        if not payload:
            continue
        
        if seq > expected_seq:
            # GAP - Pad with zeros to preserve offsets (important for PE extraction etc)
            gap = seq - expected_seq
            # Safety cap on gap size to prevent OOM on weird sequence jumps
            if gap < 1_000_000:
                assembled.extend(b"\x00" * gap)
            expected_seq = seq
        
        if seq < expected_seq:
            # Overlap
            overlap = expected_seq - seq
            if overlap >= len(payload):
                continue
            payload = payload[overlap:]
        
        assembled.extend(payload)
        expected_seq = seq + len(payload)
        
        if len(assembled) > limit:
            break
            
    return bytes(assembled), first_packet

def _detect_protocol_from_stream(stream: bytes, sport: int, dport: int) -> str:
    return _detect_app_protocol_from_stream(stream, sport, dport)


def _looks_like_http(stream: bytes) -> bool:
    head = stream[:256]
    return b"HTTP/1." in head or head.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH "))


def _looks_like_ftp_control(stream: bytes) -> bool:
    head = stream[:512]
    if b"\r\n" not in head:
        return False
    text = head.decode("latin-1", errors="ignore")
    for line in text.splitlines():
        upper = line.upper()
        if upper.startswith(("USER ", "PASS ", "RETR ", "STOR ", "PORT ", "PASV", "EPSV", "EPRT ", "LIST ", "NLST ")):
            return True
        if re.match(r"^\d{3} ", upper):
            return True
    return False


def _looks_like_smtp(stream: bytes) -> bool:
    head = stream[:512]
    text = head.decode("latin-1", errors="ignore")
    return any(tok in text.upper() for tok in ("HELO ", "EHLO ", "MAIL FROM:", "RCPT TO:", "DATA", "SMTP"))


def _looks_like_pop3(stream: bytes) -> bool:
    head = stream[:512]
    text = head.decode("latin-1", errors="ignore")
    return text.startswith("+OK") or any(tok in text.upper() for tok in ("USER ", "PASS ", "RETR ", "STAT", "LIST", "UIDL"))


def _looks_like_imap(stream: bytes) -> bool:
    head = stream[:512]
    text = head.decode("latin-1", errors="ignore")
    return "IMAP" in text.upper() or any(tok in text.upper() for tok in (" LOGIN ", " SELECT ", " FETCH ", " APPEND ", " OK ", " BAD "))


def _detect_app_protocol_from_stream(stream: bytes, sport: int, dport: int) -> str:
    # Content-based detection first (handles non-standard ports)
    if _looks_like_http(stream):
        return "HTTP"
    if b"\xfeSMB" in stream[:64] or b"\xffSMB" in stream[:64]:
        return "SMB"
    if _looks_like_ftp_control(stream):
        return "FTP"
    if _looks_like_smtp(stream):
        return "SMTP"
    if _looks_like_pop3(stream):
        return "POP3"
    if _looks_like_imap(stream):
        return "IMAP"

    proto = _flow_protocol(sport, dport)
    if proto != "UNKNOWN":
        return proto

    return "UNKNOWN"


def _is_tftp_payload(payload: bytes) -> bool:
    if len(payload) < 4:
        return False
    opcode = int.from_bytes(payload[0:2], "big")
    if opcode not in {1, 2, 3, 4, 5}:
        return False
    if opcode in {1, 2}:
        rest = payload[2:]
        return b"\x00" in rest[:256]
    return True


def _parse_enip_frames(stream: bytes) -> list[tuple[int, bytes]]:
    frames: list[tuple[int, bytes]] = []
    offset = 0
    while offset + ENIP_HEADER_LEN <= len(stream):
        header = stream[offset:offset + ENIP_HEADER_LEN]
        cmd = int.from_bytes(header[0:2], "little")
        length = int.from_bytes(header[2:4], "little")
        total_len = ENIP_HEADER_LEN + length
        if cmd not in ENIP_COMMANDS:
            break
        if length < 0 or offset + total_len > len(stream):
            break
        data = stream[offset + ENIP_HEADER_LEN:offset + total_len]
        frames.append((cmd, data))
        offset += total_len
    return frames


def _scan_enip_frames(stream: bytes) -> list[tuple[int, bytes]]:
    frames: list[tuple[int, bytes]] = []
    offset = 0
    max_len = len(stream)
    while offset + ENIP_HEADER_LEN <= max_len:
        cmd = int.from_bytes(stream[offset:offset + 2], "little")
        if cmd not in ENIP_COMMANDS:
            offset += 1
            continue
        length = int.from_bytes(stream[offset + 2:offset + 4], "little")
        total_len = ENIP_HEADER_LEN + length
        if length < 0 or total_len <= ENIP_HEADER_LEN:
            offset += 1
            continue
        if offset + total_len > max_len:
            offset += 1
            continue
        data = stream[offset + ENIP_HEADER_LEN:offset + total_len]
        frames.append((cmd, data))
        offset += total_len
    return frames


def _parse_enip_cpf(data: bytes) -> Optional[bytes]:
    if len(data) < 6:
        return None
    ptr = 0
    ptr += 4
    ptr += 2
    if ptr + 2 > len(data):
        return None
    item_count = int.from_bytes(data[ptr:ptr + 2], "little")
    ptr += 2
    cip_payload: Optional[bytes] = None
    for _ in range(item_count):
        if ptr + 4 > len(data):
            break
        item_type = int.from_bytes(data[ptr:ptr + 2], "little")
        item_length = int.from_bytes(data[ptr + 2:ptr + 4], "little")
        ptr += 4
        item_data = data[ptr:ptr + item_length]
        ptr += item_length
        if item_type in {0x00B1, 0x00B2, 0x00B4}:
            cip_payload = item_data
    return cip_payload


def _parse_cip_data(payload: bytes) -> tuple[Optional[int], bool, bytes]:
    if not payload:
        return None, True, b""
    service = payload[0]
    is_request = (service & 0x80) == 0
    if is_request:
        if len(payload) < 2:
            return service, True, b""
        path_size_words = payload[1]
        path_len = path_size_words * 2
        data_offset = 2 + path_len
        if data_offset <= len(payload):
            return service, True, payload[data_offset:]
        return service, True, b""
    if len(payload) >= 4:
        additional_size = payload[3]
        data_offset = 4 + (additional_size * 2)
        if data_offset <= len(payload):
            return service, False, payload[data_offset:]
    return service, False, b""

# --- Protocol Parsers ---

def _parse_http_stream(stream: bytes) -> List[Dict[str, Any]]:
    messages = []
    idx = 0
    # Simple parser looking for methods
    methods = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"HTTP/1."]
    
    while idx < len(stream):
        # Find next potential start
        indices = [stream.find(m, idx) for m in methods]
        indices = [i for i in indices if i != -1]
        
        # If we are strictly parsing, we should trust our position. 
        # But for reassembled streams with potential drops, scanning is safer.
        # However, if we just parsed a body, we should be at the start of the next message.
        if not indices:
            break
        start = min(indices)
        
        # header end
        header_end = stream.find(b"\r\n\r\n", start)
        if header_end == -1:
            break
            
        header_bytes = stream[start:header_end]
        try:
            header_str = header_bytes.decode("latin-1")
        except:
            idx = start + 1
            continue
            
        lines = header_str.split("\r\n")
        start_line = lines[0]
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
                
        is_request = not start_line.startswith("HTTP/1.")
        
        # Body
        body_start = header_end + 4
        content_len = None
        is_chunked = False
        
        if "content-length" in headers:
            try:
                content_len = int(headers["content-length"])
            except: pass
        
        transfer_enc = headers.get("transfer-encoding", "").lower()
        if "chunked" in transfer_enc:
            is_chunked = True
            # RFC 7230: Transfer-Encoding overrides Content-Length
            content_len = None
            
        body = b""
        next_idx = body_start
        
        if content_len is not None and content_len >= 0:
            if body_start + content_len <= len(stream):
                body = stream[body_start:body_start + content_len]
                next_idx = body_start + content_len
            else:
                body = stream[body_start:] # Truncated
                next_idx = len(stream)
        elif is_chunked:
            raw_body = stream[body_start:]
            body = _decode_chunked(raw_body)
            # Advance index logic...
            # Since we can't easily know exactly how many raw bytes were consumed 
            # without complex parsing of chunk headers in _decode_chunked,
            # we will try to find the "0\r\n\r\n" terminator.
            terminator = raw_body.find(b"0\r\n\r\n")
            if terminator != -1:
                consumed = terminator + 5
                next_idx = body_start + consumed
            else:
                # Fallback: assume rest of stream was chunks
                next_idx = len(stream) 
        else:
             # Identity encoding, no length specified.
             # For requests (GET/HEAD), implies no body.
             # For responses, implies read-until-close (rest of stream).
             # We previously scanned for next method, but that causes false truncation 
             # if the binary body contains bytes resembling "GET " or "HTTP/1.".
             
             if is_request:
                 # RFC 7230: Request without Content-Length or Transfer-Encoding => 0 length body 
                 # (unless it's an old HTTP/1.0 style, but extremely rare for requests to rely on close)
                 next_idx = body_start
                 body = b""
             else:
                 # Response: Consume everything
                 body = stream[body_start:]
                 next_idx = len(stream)

        # Handle compression
        if headers.get("content-encoding") == "gzip":
            try:
                body = gzip.decompress(body)
            except: pass
        elif headers.get("content-encoding") == "deflate":
            try:
                body = zlib.decompress(body)
            except: pass

        messages.append({
            "is_request": is_request,
            "start_line": start_line,
            "headers": headers,
            "body": body
        })
        
        if is_chunked:
             # Because our chunk decoder doesn't return consumed bytes, we have to re-scan
             idx = max(body_start + 1, next_idx)
             # But if next_idx wasn't updated (pass block), we force scan forward
             if idx == body_start + 1:
                  # Look for next method
                  sub_indices = [stream.find(m, body_start + 10) for m in methods] 
                  sub_indices = [i for i in sub_indices if i != -1]
                  if sub_indices:
                      idx = min(sub_indices)
                  else:
                      idx = len(stream)
        else:
             idx = max(idx + 1, next_idx)
             
    return messages

def _parse_smb2(stream: bytes) -> Tuple[Dict[bytes, str], Dict[bytes, bytes]]:
    # Partial SMB2 parser for file constructs
    file_map = {} # GUID/Handle -> Name
    file_data = defaultdict(bytearray)
    
    offset = 0
    while offset + 64 < len(stream):
        if stream[offset:offset+4] == b'\xfeSMB':
            # Header
            try:
                cmd = int.from_bytes(stream[offset+12:offset+14], "little")
                # flags = int.from_bytes(stream[offset+16:offset+20], "little")
                # Structure size = 64
                pass
            except: pass
            
        # Brute force scan for \xfeSMB since alignment varies
        next_sig = stream.find(b'\xfeSMB', offset + 1)
        
        offset = next_sig if next_sig != -1 else len(stream)

    return file_map, file_data

def _scan_filenames(data: bytes) -> List[str]:
    # Extract likely filenames from binary blob
    found = set()
    # Expanded regex to capture more file types and characters (spaces, brackets, parens)
    pattern = r'[\w\-.()\[\]]+\.(?:exe|dll|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|txt|bat|ps1|mkv|mp4|avi|mov|wmv|flv|webm|jpg|jpeg|png|gif|bmp|tiff|iso|img|tar|gz|7z|rar)'

    # UTF-16 strings
    try:
        text = data.decode("utf-16-le", errors="ignore")
        matches = re.findall(pattern, text, re.IGNORECASE)
        found.update(matches)
    except: pass
    
    # ASCII
    try:
        text = data.decode("latin-1", errors="ignore")
        matches = re.findall(pattern, text, re.IGNORECASE)
        found.update(matches)
    except: pass
    
    return list(found)


def _is_plausible_filename(name: str) -> bool:
    if not name or len(name) < 4:
        return False
    clean = _normalize_filename(name)
    if clean.count(".") == 0:
        return False
    base = Path(clean).name
    if len(base) < 4:
        return False
    if base.lower() in {"index.html", "default.html", "favicon.ico"}:
        return False
    if base.lower().startswith(("http_", "extracted_", "ftp_data_")):
        return False
    if re.fullmatch(r"\d+\.[a-z0-9]{1,5}", base.lower()):
        return False
    return True


def _iter_smb_records(payload: bytes) -> Tuple[List[bytes], bool]:
    records: List[bytes] = []
    netbios_present = False
    if len(payload) >= 4 and payload[0] == 0x00:
        offset = 0
        while offset + 4 <= len(payload):
            if payload[offset] != 0x00:
                break
            length = int.from_bytes(payload[offset + 1:offset + 4], "big")
            if length <= 0:
                break
            end = offset + 4 + length
            if end > len(payload):
                break
            records.append(payload[offset + 4:end])
            offset = end
            netbios_present = True
    if records:
        return records, netbios_present

    # Fallback: scan for SMB magic headers in the raw stream
    for magic in (b"\xfeSMB", b"\xffSMB"):
        start = 0
        while True:
            idx = payload.find(magic, start)
            if idx == -1:
                break
            records.append(payload[idx:])
            start = idx + len(magic)
    return records, netbios_present


def _parse_ftp_address(line: str) -> Optional[Tuple[str, int]]:
    # EPRT |1|ip|port|
    match = re.search(r"EPRT\s+\|\d+\|([^|]+)\|(\d+)\|", line, re.IGNORECASE)
    if match:
        return match.group(1), int(match.group(2))

    # EPSV (|||port|)
    match = re.search(r"\(\|\|\|(\d+)\|\)", line)
    if match:
        return "", int(match.group(1))

    # PORT/PASV h1,h2,h3,h4,p1,p2
    match = re.search(r"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", line)
    if not match:
        return None
    parts = [int(x) for x in match.groups()]
    ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}"
    port = parts[4] * 256 + parts[5]
    return ip, port


def _scan_smb2_create_filenames(stream: bytes) -> List[str]:
    names: List[str] = []
    offset = 0
    while True:
        idx = stream.find(b"\xfeSMB", offset)
        if idx == -1:
            break
        if idx + 64 > len(stream):
            break
        try:
            cmd = int.from_bytes(stream[idx + 12:idx + 14], "little")
            flags = int.from_bytes(stream[idx + 16:idx + 20], "little")
            is_response = (flags & 0x00000001) != 0
            if cmd == 0x05 and not is_response:
                data = stream[idx + 64:]
                if len(data) >= 56:
                    name_offset = int.from_bytes(data[48:50], "little")
                    name_length = int.from_bytes(data[50:52], "little")
                    real_off = name_offset - 64
                    if name_length > 0 and real_off >= 0 and real_off + name_length <= len(data):
                        try:
                            name = data[real_off:real_off + name_length].decode("utf-16le", errors="ignore")
                            if name:
                                names.append(name)
                        except Exception:
                            pass
        except Exception:
            pass
        offset = idx + 4
    return names


def _guess_extension_from_content_type(content_type: str) -> Optional[str]:
    if not content_type:
        return None
    ct = content_type.split(";", 1)[0].strip().lower()
    mapping = {
        "text/plain": "txt",
        "text/html": "html",
        "text/csv": "csv",
        "application/json": "json",
        "application/xml": "xml",
        "application/pdf": "pdf",
        "application/zip": "zip",
        "application/x-zip-compressed": "zip",
        "application/gzip": "gz",
        "application/x-gzip": "gz",
        "application/octet-stream": "bin",
        "image/jpeg": "jpg",
        "image/png": "png",
        "image/gif": "gif",
        "image/bmp": "bmp",
        "image/tiff": "tiff",
        "application/msword": "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        "application/vnd.ms-excel": "xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
        "application/vnd.ms-powerpoint": "ppt",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    }
    return mapping.get(ct)


def _append_extension_if_missing(name: str, content_type: str, fallback_ext: Optional[str] = None) -> str:
    if not name:
        return name
    if "." in Path(name).name:
        return name
    ext = _guess_extension_from_content_type(content_type) or fallback_ext
    if not ext:
        return name
    return f"{name}.{ext}"


def _imf_filename_from_headers(part: email.message.Message) -> Optional[str]:
    if part.get_filename():
        return part.get_filename()
    name = part.get_param("name", header="content-type")
    if name:
        return name
    cd = part.get("Content-Disposition", "") or ""
    match = re.search(r'filename\*?=["\']?([^"\';]+)', cd, re.IGNORECASE)
    if match:
        return match.group(1)
    cid = part.get("Content-ID")
    if cid:
        return cid.strip("<>")
    return None


def _parse_smb2_create_filename(record: bytes) -> Optional[str]:
    if len(record) < 120:
        return None
    if not record.startswith(b"\xfeSMB"):
        return None
    cmd = int.from_bytes(record[12:14], "little")
    flags = int.from_bytes(record[16:20], "little")
    is_response = (flags & 0x00000001) != 0
    if cmd != 0x05 or is_response:
        return None
    data = record[64:]
    if len(data) < 56:
        return None
    name_offset = int.from_bytes(data[48:50], "little")
    name_length = int.from_bytes(data[50:52], "little")
    real_off = name_offset - 64
    if name_length <= 0 or real_off < 0 or real_off + name_length > len(data):
        return None
    try:
        return data[real_off:real_off + name_length].decode("utf-16le", errors="ignore")
    except Exception:
        return None


def _extract_smb1_filename(record: bytes) -> Optional[str]:
    if len(record) < 32:
        return None
    if not record.startswith(b"\xffSMB"):
        return None
    # Attempt to find filename candidates within the SMB1 record
    candidates = _scan_filenames(record)
    if candidates:
        return candidates[0]
    return None


def _parse_ntlm_type3(payload: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    signature = b"NTLMSSP\x00"
    idx = payload.find(signature)
    if idx == -1 or len(payload) < idx + 64:
        return None, None, None
    try:
        msg_type = struct.unpack("<I", payload[idx + 8:idx + 12])[0]
        if msg_type != 3:
            return None, None, None
        def _read_field(offset: int) -> Tuple[int, int]:
            length = struct.unpack("<H", payload[offset:offset + 2])[0]
            field_offset = struct.unpack("<I", payload[offset + 4:offset + 8])[0]
            return length, field_offset
        domain_len, domain_off = _read_field(idx + 28)
        user_len, user_off = _read_field(idx + 36)
        workstation_len, workstation_off = _read_field(idx + 44)
        domain = payload[idx + domain_off:idx + domain_off + domain_len].decode("utf-16le", errors="ignore") if domain_len else None
        user = payload[idx + user_off:idx + user_off + user_len].decode("utf-16le", errors="ignore") if user_len else None
        workstation = payload[idx + workstation_off:idx + workstation_off + workstation_len].decode("utf-16le", errors="ignore") if workstation_len else None
        return user or None, domain or None, workstation or None
    except Exception:
        return None, None, None


def _extract_email_attachments(
    stream: bytes,
    proto: str,
    src: str,
    dst: str,
    sport: int,
    dport: int,
    idx: int,
    need_payload: bool,
    artifacts: List[FileArtifact],
) -> None:
    seen_payloads: set[str] = set()
    segments: List[bytes] = [stream]
    if b"MIME-Version" in stream or b"Content-Type" in stream:
        for marker in (b"MIME-Version", b"Content-Type"):
            start = stream.find(marker)
            if start != -1:
                segments.append(stream[start:])
    if b"\r\n.\r\n" in stream:
        segments.extend(seg for seg in stream.split(b"\r\n.\r\n") if seg)

    for seg in segments:
        try:
            msg = email.message_from_bytes(seg, policy=policy.default)
            for part in msg.walk():
                fn = part.get_filename()
                if fn:
                    payload = part.get_payload(decode=True)
                    if payload:
                        if len(payload) < 32:
                            continue
                        digest = hashlib.sha256(payload).hexdigest()
                        if digest in seen_payloads:
                            continue
                        seen_payloads.add(digest)
                        ft = detect_file_type_bytes(payload)
                        artifacts.append(FileArtifact(
                            protocol=proto, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                            filename=_normalize_filename(fn), size_bytes=len(payload), packet_index=idx,
                            note=f"{proto} Attachment", file_type=ft, payload=payload if need_payload else None
                        ))
        except Exception:
            continue

# --- Main Class ---

class FileExtractor:
    def __init__(self, path: Path):
        self.path = path
        self.tcp_streams: Dict[Tuple[str, str, int, int], List[Tuple[int, bytes, int]]] = defaultdict(list)
        self.tftp_sessions: Dict[frozenset[str], Dict[str, Any]] = defaultdict(lambda: {
            "filename": None, "blocks": {}, "first_packet": 0, "sport": 0, "dport": 0
        })
        self.artifacts: List[FileArtifact] = []
        self.candidates: List[FileTransfer] = []
        self.errors: List[str] = []
        self.detections: List[Dict[str, object]] = []
        self.smb_versions: Counter[str] = Counter()
        self.netbios_sources: Counter[str] = Counter()
        self.netbios_destinations: Counter[str] = Counter()
        self.ntlm_users: Counter[str] = Counter()
        self.ntlm_domains: Counter[str] = Counter()
        self.ntlm_sources: Counter[str] = Counter()
        self.ntlm_destinations: Counter[str] = Counter()
        self.http_ntlm_sources: Counter[str] = Counter()
        self.http_ntlm_destinations: Counter[str] = Counter()
        self.smb1_sources: Counter[str] = Counter()
        self.smb1_destinations: Counter[str] = Counter()
        self.flows: Dict[Tuple[str, str, str, int, int], Dict[str, Any]] = defaultdict(lambda: {
            "packets": 0, "bytes": 0, "first_seen": None, "last_seen": None
        })
        self.flow_protocol_hints: Dict[Tuple[str, str, str, int, int], Counter[str]] = defaultdict(Counter)
        self.smb_encrypted: Counter[str] = Counter()
        self.smb_signed: Counter[str] = Counter()

    def process_packet(self, pkt: Packet, idx: int):
        # IP/IPv6
        if IP and pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 and pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return

        proto = "IP"
        sport = 0
        dport = 0
        
        # Statistics
        ts = safe_float(getattr(pkt, "time", 0))
        
        if TCP and pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto = "TCP"
            sport, dport = int(tcp.sport), int(tcp.dport)
            payload = b""
            if Raw in pkt:
                payload = bytes(pkt[Raw])
            else:
                try:
                    payload = bytes(tcp.payload)
                except Exception:
                    payload = b""
            if payload:
                seq = int(tcp.seq)
                self.tcp_streams[(src, dst, sport, dport)].append((seq, payload, idx))

        elif UDP and pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto = "UDP"
            sport, dport = int(udp.sport), int(udp.dport)
            
            # TFTP
            if Raw in pkt:
                load = bytes(pkt[Raw])
                if _is_tftp_payload(load):
                    self._handle_tftp(load, src, dst, sport, dport, idx)
                    self.flow_protocol_hints[(src, dst, "UDP", sport, dport)]["TFTP"] += 1
        
        if proto != "IP":
            key = (src, dst, proto, sport, dport)
            f = self.flows[key]
            f["packets"] += 1
            f["bytes"] += len(pkt)
            if f["first_seen"] is None or ts < f["first_seen"]:
                f["first_seen"] = ts
            if f["last_seen"] is None or ts > f["last_seen"]:
                f["last_seen"] = ts

    def _handle_tftp(self, payload: bytes, src: str, dst: str, sport: int, dport: int, idx: int):
        if len(payload) < 4: return
        key = frozenset({src, dst})
        sess = self.tftp_sessions[key]
        if sess["first_packet"] == 0:
            sess["first_packet"] = idx
            sess["sport"] = sport
            sess["dport"] = dport

        opcode = int.from_bytes(payload[:2], 'big')
        if opcode in {1, 2}:
            fn = _extract_tftp(payload)
            if fn: sess["filename"] = fn
        elif opcode == 3:
            blk = int.from_bytes(payload[2:4], 'big')
            sess["blocks"][blk] = payload[4:]


    def finalize(self):
        # We need a two-pass approach for HTTP to correlate Requests with Responses
        # Pass 1: Scan for HTTP Requests and build pending_requests map
        pending_requests: Dict[Tuple[str, str, int, int], List[str]] = defaultdict(list)
        
        # Pre-assemble all streams once to avoid double work?
        # No, memory is tight, we iterate self.tcp_streams.
        # But we need to correlate.
        
        # Let's iterate over ALL streams for Pass 1 (Request Collection)
        for (src, dst, sport, dport), chunks in self.tcp_streams.items():
            # Check just the first chunk or two to see if it's HTTP Request
            if not chunks:
                continue

            # Optimization: Don't assemble everything yet, just peek
            head_payload = chunks[0][1]
            likely_http = _looks_like_http(head_payload) or _flow_protocol(sport, dport) == "HTTP"
            stream = b""
            if likely_http:
                stream, _ = _assemble_stream(chunks, limit=5_000_000) # Smaller check limit
            else:
                stream, _ = _assemble_stream(chunks, limit=65_536)
                if not _looks_like_http(stream):
                    continue

            msgs = _parse_http_stream(stream)
            for m in msgs:
                if m["is_request"]:
                    fn = _extract_request_filename(m["start_line"])
                    if fn:
                        # Store for the REVERSE direction
                        # Key: (Dst(Server), DstPort, Src(Client), SrcPort)
                        # Wait, my keys in tcp_streams are (src, dst, sport, dport)
                        # So from Client->Server.
                        # Response will be Server->Client.
                        # Response Key will be (dst, src, dport, sport)
                        # Wait, tcp_streams key is (src, dst, sport, dport)
                        # So I should store it under (dst, src, dport, sport)
                        pending_requests[(dst, src, dport, sport)].append(fn)

        # Pass 1b: FTP control parsing (supports non-standard ports)
        ftp_transfers: List[Dict[str, Any]] = []
        for (src, dst, sport, dport), chunks in self.tcp_streams.items():
            if not chunks:
                continue
            head_payload = chunks[0][1]
            if not _looks_like_ftp_control(head_payload) and 21 not in (sport, dport):
                continue
            stream, _ = _assemble_stream(chunks, limit=5_000_000)
            if not stream:
                continue
            try:
                text = stream.decode("latin-1", errors="ignore")
            except Exception:
                continue
            if dport == 21:
                client_ip, server_ip = src, dst
                is_response = False
            else:
                client_ip, server_ip = dst, src
                is_response = True
            session = {
                "last_cmd": None,
                "last_filename": None,
                "data_host": None,
                "data_port": None,
                "data_role": None,
            }
            for line in text.splitlines():
                upper = line.upper()
                if not is_response:
                    if upper.startswith("RETR "):
                        session["last_cmd"] = "RETR"
                        session["last_filename"] = line[5:].strip()
                    elif upper.startswith("STOR "):
                        session["last_cmd"] = "STOR"
                        session["last_filename"] = line[5:].strip()
                    elif upper.startswith("PORT ") or upper.startswith("EPRT "):
                        addr = _parse_ftp_address(line)
                        if addr:
                            data_host = addr[0] or server_ip
                            session["data_host"], session["data_port"] = data_host, addr[1]
                            session["data_role"] = "client"
                    elif upper.startswith("PASV") or upper.startswith("EPSV"):
                        addr = _parse_ftp_address(line)
                        if addr:
                            data_host = addr[0] or server_ip
                            session["data_host"], session["data_port"] = data_host, addr[1]
                            session["data_role"] = "server"
                else:
                    if "ENTERING PASSIVE MODE" in upper or upper.startswith("227 ") or upper.startswith("229 "):
                        addr = _parse_ftp_address(line)
                        if addr:
                            data_host = addr[0] or server_ip
                            session["data_host"], session["data_port"] = data_host, addr[1]
                            session["data_role"] = "server"

                if session.get("last_cmd") and session.get("last_filename") and session.get("data_port"):
                    ftp_transfers.append({
                        "client": client_ip,
                        "server": server_ip,
                        "data_host": session.get("data_host") or server_ip,
                        "data_port": int(session.get("data_port") or 0),
                        "data_role": session.get("data_role") or "server",
                        "filename": session.get("last_filename") or "ftp_transfer.bin",
                        "direction": "download" if session.get("last_cmd") == "RETR" else "upload",
                    })
                    session["last_cmd"] = None
                    session["last_filename"] = None

        # Pass 2: Process Everything
        for (src, dst, sport, dport), chunks in self.tcp_streams.items():
            stream, first_pkt = _assemble_stream(chunks)
            if not stream:
                continue
            protocol = _detect_protocol_from_stream(stream, sport, dport)
            if protocol != "UNKNOWN":
                self.flow_protocol_hints[(src, dst, "TCP", sport, dport)][protocol] += 1
            
            # Lookup Flow Stats for size estimation in SMB
            # Key used in flows: (src, dst, proto, sport, dport)
            # protocol variable here is "SMB" or "HTTP", but flows key uses "TCP" usually
            # But the flows dictate the transport.
            # Let's try to find the flow with matching tuples
            flow_bytes = 0
            # Try TCP
            f_info = self.flows.get((src, dst, "TCP", sport, dport))
            if f_info: flow_bytes = f_info["bytes"]
            
            # Protocol Handlers
            if protocol == "HTTP":
                # Check if we have pending filenames for this stream (Client <- Server)
                # Key matching current stream: (src, dst, sport, dport)
                # Because we stored it using that key.
                names = pending_requests.get((src, dst, sport, dport), [])
                self._extract_http(stream, src, dst, sport, dport, first_pkt, names)
            elif protocol == "SMB":
                self._extract_smb(stream, src, dst, sport, dport, first_pkt, flow_bytes)
            elif protocol in ("SMTP", "POP3", "IMAP"):
                self._extract_email(stream, protocol, src, dst, sport, dport, first_pkt)
            
            # Generic binary/PE extraction (only for unknown protocol to reduce noise)
            if protocol == "UNKNOWN":
                self._extract_pe(stream, protocol, src, dst, sport, dport, first_pkt)

            # FTP data flows (match control-derived ports)
            matched_ftp = False
            for transfer in ftp_transfers:
                if transfer["data_port"] in (sport, dport):
                    data_host = transfer.get("data_host")
                    if data_host and data_host not in (src, dst):
                        continue
                    if len(stream) < 256:
                        continue
                    self.flow_protocol_hints[(src, dst, "TCP", sport, dport)]["FTP"] += 1
                    self.artifacts.append(FileArtifact(
                        protocol="FTP", src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                        filename=_normalize_filename(transfer["filename"]), size_bytes=len(stream),
                        packet_index=first_pkt, note=f"FTP {transfer['direction']} data",
                        file_type=detect_file_type_bytes(stream), payload=stream
                    ))
                    matched_ftp = True

            # Heuristic raw file for FTP data when control channel unavailable
            if not matched_ftp and protocol == "FTP" and len(stream) > 2000:
                self.artifacts.append(FileArtifact(
                    protocol="FTP", src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                    filename=f"ftp_transfer_{first_pkt}.bin", size_bytes=len(stream), packet_index=first_pkt,
                    note="FTP Data Stream", file_type="BINARY", payload=stream
                ))

        # 2. Process TFTP
        for endpts, sess in self.tftp_sessions.items():
            if sess["filename"] and sess["blocks"]:
                ordered = sorted(sess["blocks"].items())
                data = b"".join(v for k, v in ordered)
                e_list = list(endpts)
                s = e_list[0]
                d = e_list[1] if len(e_list)>1 else s
                
                ftype = "BINARY"
                if sess["filename"].lower().endswith(".exe"): ftype = "EXE/DLL"
                elif sess["filename"].lower().endswith(".txt"): ftype = "TEXT"
                
                self.artifacts.append(FileArtifact(
                    protocol="TFTP", src_ip=s, dst_ip=d, src_port=sess["sport"], dst_port=sess["dport"],
                    filename=_normalize_filename(sess["filename"]), size_bytes=len(data),
                    packet_index=sess["first_packet"], note="TFTP Transfer", file_type=ftype, payload=data
                ))

        # 3. Candidates
        for (s, d, p, sp, dp), info in self.flows.items():
            # Check if this flow produced artifacts
            # This is O(N*M), maybe optimize later
            
            # Determine protocol
            proto = "UNKNOWN"
            hint = self.flow_protocol_hints.get((s, d, p, sp, dp))
            if hint:
                proto = hint.most_common(1)[0][0]
            if proto == "UNKNOWN":
                proto = _flow_protocol(sp, dp)

            if proto not in FILE_TRANSFER_PROTOCOLS:
                continue
            
            self.candidates.append(FileTransfer(
                protocol=proto, src_ip=s, dst_ip=d, src_port=sp, dst_port=dp,
                packets=info["packets"], bytes=info["bytes"],
                first_seen=info["first_seen"], last_seen=info.get("last_seen"),
                note=None
            ))
        
        self.candidates.sort(key=lambda x: x.bytes, reverse=True)
        
        # Sort artifacts to surface interesting files first
        # 1. Non generic filenames (not http_response.bin, not extracted_pe_N.exe if possible, but PEs are good)
        # 2. Known Extensions (exe, zip, pdf, etc)
        # 3. Size (Largest first)
        def artifact_score(a: FileArtifact) -> tuple:
            name_score = 0
            if "http_response" in a.filename: name_score = 3
            elif "extracted_" in a.filename: name_score = 2
            else: name_score = 1 # Specific name is best
            
            ext_score = 0
            # Priorities: Executables, Documents, Archives, Media
            priority_exts = (
                ".exe", ".dll", ".zip", ".pdf", ".docx", ".xlsx",
                ".mkv", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm",
                ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
                ".tar", ".gz", ".7z", ".rar", ".iso"
            )
            if a.filename.lower().endswith(priority_exts):
                ext_score = 2
            elif a.filename.lower().endswith(".bin"):
                ext_score = 0
            else:
                ext_score = 1
                
            size_val = a.size_bytes or 0
            
            # Sort Key: (NameQuality Desc, ExtQuality Desc, Size Desc)
            # Python sorts Ascending by default. We want descending quality.
            # So negate scores.
            return (name_score, -ext_score, -size_val)

        self.artifacts.sort(key=artifact_score)

        if self.smb_versions:
            smb_versions = ", ".join(f"{k}({v})" for k, v in self.smb_versions.items())
            self.detections.append({
                "severity": "info",
                "summary": "SMB traffic detected",
                "details": f"Versions observed: {smb_versions}",
                "source": "Files",
            })
            if self.smb_versions.get("SMB1"):
                self.detections.append({
                    "severity": "critical",
                    "summary": "SMBv1 detected",
                    "details": "Legacy SMBv1 traffic observed; susceptible to known exploits.",
                    "source": "Files",
                    "top_sources": self.smb1_sources.most_common(5),
                    "top_destinations": self.smb1_destinations.most_common(5),
                })

        if self.netbios_sources or self.netbios_destinations:
            self.detections.append({
                "severity": "warning",
                "summary": "NetBIOS/SMB over port 139 detected",
                "details": "NetBIOS session traffic observed in SMB streams.",
                "source": "Files",
                "top_sources": self.netbios_sources.most_common(5),
                "top_destinations": self.netbios_destinations.most_common(5),
            })

        if self.ntlm_users or self.ntlm_domains:
            user_text = ", ".join(f"{u}({c})" for u, c in self.ntlm_users.most_common(5)) or "-"
            domain_text = ", ".join(f"{d}({c})" for d, c in self.ntlm_domains.most_common(5)) or "-"
            self.detections.append({
                "severity": "info",
                "summary": "NTLM authentication observed",
                "details": f"Users: {user_text}; Domains: {domain_text}",
                "source": "Files",
                "top_sources": self.ntlm_sources.most_common(5),
                "top_destinations": self.ntlm_destinations.most_common(5),
            })

        if self.http_ntlm_sources or self.http_ntlm_destinations:
            self.detections.append({
                "severity": "info",
                "summary": "HTTP NTLM authentication observed",
                "details": "NTLM headers seen in HTTP authentication exchange.",
                "source": "Files",
                "top_sources": self.http_ntlm_sources.most_common(5),
                "top_destinations": self.http_ntlm_destinations.most_common(5),
            })

        if self.smb_encrypted:
            self.detections.append({
                "severity": "info",
                "summary": "SMB encryption observed",
                "details": "SMB3 encrypted sessions can hide filenames and payloads.",
                "source": "Files",
                "top_sources": self.smb_encrypted.most_common(5),
            })
        if self.smb_signed:
            self.detections.append({
                "severity": "info",
                "summary": "SMB signing observed",
                "details": "SMB signing is enabled on observed sessions.",
                "source": "Files",
                "top_sources": self.smb_signed.most_common(5),
            })


    def _extract_http(self, stream: bytes, src: str, dst: str, sport: int, dport: int, idx: int, known_filenames: List[str] = None):
        msgs = _parse_http_stream(stream)
        pending_names = list(known_filenames) if known_filenames else []
        
        for m in msgs:
            if m["is_request"]:
                fn = _extract_request_filename(m["start_line"])
                if fn: pending_names.append(fn)
                auth_header = m["headers"].get("authorization", "")
                if "ntlm" in auth_header.lower():
                    self.http_ntlm_sources[src] += 1
                    self.http_ntlm_destinations[dst] += 1
            else:
                # Response
                body = m.get("body", b"")

                auth_header = m["headers"].get("www-authenticate", "")
                if "ntlm" in auth_header.lower():
                    self.http_ntlm_sources[src] += 1
                    self.http_ntlm_destinations[dst] += 1
                
                fname = "http_response.bin"
                explicit_name = False
                # Robust Content-Disposition Parsing
                disp = m["headers"].get("content-disposition", "")
                if disp:
                    if "filename=" in disp.lower() or "attachment" in disp.lower():
                        explicit_name = True
                    # Look for filename* (RFC 5987)
                    match_star = re.search(r'filename\*=UTF-8\'\'(.+?)(?:;|$)', disp, re.IGNORECASE)
                    if match_star:
                        try:
                            fname = unquote(match_star.group(1))
                        except: pass
                    else:
                        # Look for filename="foo" or filename=foo
                        match = re.search(r'filename=["\']?([^"\';]+)["\']?', disp, re.IGNORECASE)
                        if match:
                            fname = match.group(1)

                if fname == "http_response.bin":
                    content_location = m["headers"].get("content-location", "")
                    if content_location:
                        fname = content_location
                        explicit_name = True
                
                # Check pending names (Sync logic: Consume regardless of body size/existence to keep order)
                if fname == "http_response.bin" and pending_names:
                    fname = pending_names.pop(0)
                    explicit_name = True

                if not body:
                    continue

                # Determine File Type (Early)
                ft = detect_file_type_bytes(body)
                content_type = m["headers"].get("content-type", "")

                if fname == "http_response.bin":
                    ext = _guess_extension_from_content_type(content_type)
                    if ext:
                        fname = f"http_{idx}.{ext}"

                if fname == "http_response.bin":
                    host = m["headers"].get("host", "")
                    req = m.get("request_line") or m.get("start_line", "")
                    candidate = _extract_request_filename(req, host)
                    if candidate:
                        fname = candidate
                        explicit_name = True

                if fname == "http_response.bin" and ft not in ("UNKNOWN", "BINARY"):
                    ext = ft.lower().split("/")[0]
                    fname = f"extracted_{ext}.bin"

                fname = _append_extension_if_missing(fname, content_type)

                if fname == "http_response.bin":
                    fname = f"http_{idx}.bin"

                # Check Size - Filter out noise unless we have a specific filename or valid type
                is_specific_name = fname != "http_response.bin" and not fname.startswith("extracted_")
                is_plausible = _is_plausible_filename(fname)
                content_type = m["headers"].get("content-type", "")
                is_binary_like = bool(content_type) and not content_type.startswith("text/")
                if len(body) < 32 and not is_specific_name:
                    continue
                if not explicit_name and not is_specific_name and fname.startswith("http_"):
                    continue
                if not explicit_name and not is_specific_name and len(body) < 1024:
                    continue
                if not explicit_name and fname.startswith("http_") and len(body) < 524288:
                    continue
                if not is_specific_name and not is_binary_like and ft in ("UNKNOWN", "BINARY"):
                    continue
                if not is_plausible and not is_specific_name:
                    continue

                if body.startswith(b"MZ") and not explicit_name:
                    exe_name = next((n for n in pending_names if n.lower().endswith(".exe")), None)
                    if exe_name:
                        fname = exe_name
                        explicit_name = True

                # Fix for Procmon or other PEs inside HTTP (Size > 1MB usually)
                # But keep check small for speed, just header signature
                if len(body) > 64 and body.startswith(b"MZ"):
                     # Double check PE signature
                     try:
                         pe_off = int.from_bytes(body[60:64], 'little')
                         if pe_off < len(body) and body[pe_off:pe_off+4] == b"PE\x00\x00":
                             if fname == "http_response.bin" or fname.endswith(".bin"):
                                 fname = "extracted_pe_http.exe"
                             ft = "EXE/DLL" # Detected
                     except: pass
                
                self.artifacts.append(FileArtifact(
                    protocol="HTTP", src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                    filename=_normalize_filename(fname), size_bytes=len(body), packet_index=idx,
                    note="HTTP Response Body", file_type=ft, payload=body
                ))
                
                # Double check for PEs inside HTTP bodies that might be wrapped or just to be sure
                # (although _extract_pe runs on the full stream, sometimes having it isolated in the body is better)
                if len(body) > 64 and body.startswith(b"MZ"):
                    # Already handled above
                    pass

    def _extract_smb(self, stream: bytes, src: str, dst: str, sport: int, dport: int, idx: int, flow_total_bytes: int = 0):
        records, netbios_present = _iter_smb_records(stream)
        if netbios_present or sport == 139 or dport == 139:
            self.netbios_sources[src] += 1
            self.netbios_destinations[dst] += 1

        if not records:
            records = [stream]

        for record in records:
            if record.startswith(b"\xfeSMB"):
                self.smb_versions["SMB2/3"] += 1
                filename = _parse_smb2_create_filename(record)
                if filename and _is_plausible_filename(filename):
                    self.artifacts.append(FileArtifact(
                        protocol="SMB2", src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                        filename=_normalize_filename(filename), size_bytes=None, packet_index=idx,
                        note="SMB2 Create", file_type="UNKNOWN", payload=None
                    ))
                user, domain, _ = _parse_ntlm_type3(record)
                if user:
                    self.ntlm_users[user] += 1
                    self.ntlm_sources[src] += 1
                    self.ntlm_destinations[dst] += 1
                if domain:
                    self.ntlm_domains[domain] += 1
                if len(record) >= 20:
                    flags = int.from_bytes(record[16:20], "little")
                    if flags & 0x00000008:
                        self.smb_signed[src] += 1
                    if flags & 0x00004000:
                        self.smb_encrypted[src] += 1
            elif record.startswith(b"\xffSMB"):
                self.smb_versions["SMB1"] += 1
                self.smb1_sources[src] += 1
                self.smb1_destinations[dst] += 1
                filename = _extract_smb1_filename(record)
                if filename and _is_plausible_filename(filename):
                    self.artifacts.append(FileArtifact(
                        protocol="SMB1", src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                        filename=_normalize_filename(filename), size_bytes=None, packet_index=idx,
                        note="SMB1 Create/Open", file_type="UNKNOWN", payload=None
                    ))
                user, domain, _ = _parse_ntlm_type3(record)
                if user:
                    self.ntlm_users[user] += 1
                    self.ntlm_sources[src] += 1
                    self.ntlm_destinations[dst] += 1
                if domain:
                    self.ntlm_domains[domain] += 1

        # Do not add heuristic filename scans for SMB streams (too noisy)

    def _extract_email(self, stream: bytes, proto: str, src: str, dst: str, sport: int, dport: int, idx: int):
        _extract_email_attachments(
            stream,
            proto,
            src,
            dst,
            sport,
            dport,
            idx,
            True,
            self.artifacts,
        )

    def _extract_pe(self, stream: bytes, protocol: str, src: str, dst: str, sport: int, dport: int, idx: int):
        # Look for MZ...PE
        pos = 0
        found_count = 0
        while True:
            mz = stream.find(b"MZ", pos)
            if mz == -1: break
            
            # Sanity check: if we found seemingly infinite MZs (e.g. ZMZMZMZM), break
            if found_count > 10: break

            if mz + 64 > len(stream): break
            if mz != 0:
                pos = mz + 2
                continue
            
            try:
                pe_off = int.from_bytes(stream[mz+60:mz+64], 'little')
                # PE header must be within reasonable distance (e.g. < 4096 bytes usually)
                if 0 < pe_off < 4096 and mz + pe_off + 4 <= len(stream):
                    if stream[mz + pe_off : mz + pe_off + 4] == b"PE\x00\x00":
                        # Found one
                        # Determine size (Optional Header -> SizeOfImage)
                        # Optional Header starts at PE + 24
                        # SizeOfImage is at offset 56 in Optional Header (Std+Win specific)
                        # PE(4) + FileHeader(20) + OptionalHeader(Standard fields...)
                        # Magic number in Optional Header determines PE32 vs PE32+
                        
                        # Just grab to end of stream or next large block of nulls for now
                        # Ideally we parse the SizeOfImage
                        
                        data = stream[mz:]
                        fname = f"extracted_pe_{found_count}.exe"
                        
                        # Check if we can parse SizeOfImage
                        opt_header_start = mz + pe_off + 24
                        if opt_header_start + 60 < len(stream):
                            # Magic: 0x10b (PE32), 0x20b (PE32+)
                            magic = int.from_bytes(stream[opt_header_start:opt_header_start+2], "little")
                            size_of_image = 0
                            if magic == 0x10b:
                                # Offset 56
                                size_of_image = int.from_bytes(stream[opt_header_start+56:opt_header_start+60], "little")
                            elif magic == 0x20b:
                                # Offset 56
                                size_of_image = int.from_bytes(stream[opt_header_start+56:opt_header_start+60], "little")
                            
                            if size_of_image > 4096 and size_of_image < 100_000_000:
                                # If we have enough data, slice it
                                if len(data) >= size_of_image:
                                    data = data[:size_of_image]
                                else:
                                    pos = mz + 2
                                    continue
                        
                        self.artifacts.append(FileArtifact(
                            protocol=protocol, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                            filename=fname, size_bytes=len(data), packet_index=idx,
                            note="PE Signature Detection", file_type="EXE/DLL", payload=data
                        ))
                        found_count += 1
                        # Advance past the PE header to avoid tiny loop
                        pos = mz + pe_off + 4
                        continue
            except: 
                pass
                
            pos = mz + 2


def _dpkt_ip_to_str(ip_obj: object) -> str:
    if isinstance(ip_obj, (bytes, bytearray)) and len(ip_obj) == 4:
        return socket.inet_ntoa(ip_obj)
    if isinstance(ip_obj, (bytes, bytearray)) and len(ip_obj) == 16:
        return socket.inet_ntop(socket.AF_INET6, ip_obj)
    return str(ip_obj)


def _extract_pem_certs(data: bytes) -> List[bytes]:
    certs: List[bytes] = []
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    start = 0
    while True:
        b_idx = data.find(begin, start)
        if b_idx == -1:
            break
        e_idx = data.find(end, b_idx)
        if e_idx == -1:
            break
        blob = data[b_idx:e_idx + len(end)]
        certs.append(blob)
        start = e_idx + len(end)
    return certs


def _extract_der_blobs(data: bytes) -> List[bytes]:
    blobs: List[bytes] = []
    idx = 0
    while idx + 4 < len(data):
        if data[idx] != 0x30:
            idx += 1
            continue
        length_byte = data[idx + 1]
        if length_byte == 0x82 and idx + 4 < len(data):
            length = (data[idx + 2] << 8) | data[idx + 3]
            total = 4 + length
        elif length_byte == 0x81 and idx + 3 < len(data):
            length = data[idx + 2]
            total = 3 + length
        elif length_byte < 0x80:
            total = 2 + length_byte
        else:
            idx += 1
            continue
        if total > 0 and idx + total <= len(data):
            blobs.append(data[idx:idx + total])
            idx += total
        else:
            idx += 1
    return blobs


def _normalize_x509_payload(payload: bytes) -> bytes:
    if not payload:
        return b""
    if b"BEGIN CERTIFICATE" in payload:
        try:
            text = payload.decode("ascii", errors="ignore")
            lines = [line.strip() for line in text.splitlines()]
            b64_lines = []
            in_cert = False
            for line in lines:
                if "BEGIN CERTIFICATE" in line:
                    in_cert = True
                    continue
                if "END CERTIFICATE" in line:
                    break
                if in_cert:
                    b64_lines.append(line)
            if b64_lines:
                return base64.b64decode("".join(b64_lines), validate=False)
        except Exception:
            return payload
    return payload


def _export_with_dpkt(
    path: Path,
    extract_name: Optional[str],
    output_dir: Optional[Path],
    view_name: Optional[str],
    show_status: bool,
    packets: Optional[List[Packet]] = None,
) -> Optional[FileTransferSummary]:
    artifacts: List[FileArtifact] = []
    extracted_paths: List[Path] = []
    views: List[Any] = []
    detections: List[Dict[str, str]] = []
    errors: List[str] = []
    need_payload = bool(extract_name or view_name)
    seen_x509: set[str] = set()
    seen_x509_meta: set[tuple[str, str, str, int]] = set()
    enip_buffers: Dict[tuple[str, str, int, int, str, str], Dict[str, object]] = {}
    enip_payload_hashes: set[str] = set()
    enip_best: Dict[tuple[str, str, str, str], tuple[int, str]] = {}
    enip_file_services = {0x73, 0x74, 0x75, 0x55, 0x4C, 0x4E, 0x4D, 0x4F}
    max_enip_bytes = 50_000_000
    min_enip_bytes = 1024
    min_enip_named_bytes = 2048

    def _add_artifact(artifact: FileArtifact) -> None:
        artifacts.append(artifact)

    tcp_streams: Dict[Tuple[str, str, int, int], List[Tuple[int, bytes, int]]] = defaultdict(list)
    udp_packets: List[Tuple[str, str, int, int, bytes, int]] = []

    if packets is None:
        if dpkt is None:
            return None
        try:
            with path.open("rb") as handle:
                try:
                    reader = dpkt.pcapng.Reader(handle)
                except Exception:
                    handle.seek(0)
                    reader = dpkt.pcap.Reader(handle)
                idx = 0
                for ts, buf in reader:
                    idx += 1
                    ip = None
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP) or isinstance(eth.data, dpkt.ip6.IP6):
                            ip = eth.data
                    except Exception:
                        ip = None

                    if ip is None:
                        try:
                            ip = dpkt.ip.IP(buf)
                        except Exception:
                            try:
                                ip = dpkt.ip6.IP6(buf)
                            except Exception:
                                continue

                    if isinstance(ip, dpkt.ip.IP):
                        src_ip = _dpkt_ip_to_str(ip.src)
                        dst_ip = _dpkt_ip_to_str(ip.dst)
                    elif isinstance(ip, dpkt.ip6.IP6):
                        src_ip = _dpkt_ip_to_str(ip.src)
                        dst_ip = _dpkt_ip_to_str(ip.dst)
                    else:
                        continue

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        payload = bytes(tcp.data or b"")
                        if payload:
                            tcp_streams[(src_ip, dst_ip, int(tcp.sport), int(tcp.dport))].append(
                                (int(tcp.seq), payload, idx)
                            )
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        payload = bytes(udp.data or b"")
                        if payload:
                            udp_packets.append((src_ip, dst_ip, int(udp.sport), int(udp.dport), payload, idx))
        except Exception as exc:
            return FileTransferSummary(path, 0, [], [], [], [], [], [str(exc)])
    else:
        idx = 0
        for pkt in packets:
            idx += 1
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", ""))
                dst_ip = str(getattr(ip_layer, "dst", ""))
            else:
                continue

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                payload = bytes(getattr(tcp, "payload", b""))
                if payload:
                    seq = int(getattr(tcp, "seq", 0) or 0)
                    tcp_streams[(src_ip, dst_ip, int(tcp.sport), int(tcp.dport))].append((seq, payload, idx))
            elif UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                payload = bytes(getattr(udp, "payload", b""))
                if payload:
                    udp_packets.append((src_ip, dst_ip, int(udp.sport), int(udp.dport), payload, idx))

    # FTP control parsing
    ftp_transfers: List[Dict[str, Any]] = []
    for (src, dst, sport, dport), chunks in tcp_streams.items():
        if 21 not in (sport, dport):
            continue
        stream, first_pkt = _assemble_stream(chunks)
        if not stream:
            continue
        try:
            text = stream.decode("latin-1", errors="ignore")
        except Exception:
            continue
        if dport == 21:
            client_ip, server_ip = src, dst
            is_response = False
        else:
            client_ip, server_ip = dst, src
            is_response = True
        session = {"last_cmd": None, "last_filename": None, "data_host": None, "data_port": None, "data_role": None}
        for line in text.splitlines():
            upper = line.upper()
            if not is_response:
                if upper.startswith("RETR "):
                    session["last_cmd"] = "RETR"
                    session["last_filename"] = line[5:].strip()
                elif upper.startswith("STOR "):
                    session["last_cmd"] = "STOR"
                    session["last_filename"] = line[5:].strip()
                elif upper.startswith("PORT ") or upper.startswith("EPRT "):
                    addr = _parse_ftp_address(line)
                    if addr:
                        data_host = addr[0] or server_ip
                        session["data_host"], session["data_port"] = data_host, addr[1]
                        session["data_role"] = "client"
            else:
                if "ENTERING PASSIVE MODE" in upper or upper.startswith("227 ") or upper.startswith("229 "):
                    addr = _parse_ftp_address(line)
                    if addr:
                        data_host = addr[0] or server_ip
                        session["data_host"], session["data_port"] = data_host, addr[1]
                        session["data_role"] = "server"

            if session.get("last_cmd") and session.get("last_filename") and session.get("data_port"):
                ftp_transfers.append({
                    "client": client_ip,
                    "server": server_ip,
                        "data_host": session.get("data_host") or server_ip,
                    "data_port": int(session.get("data_port") or 0),
                    "data_role": session.get("data_role") or "server",
                    "filename": session.get("last_filename") or "ftp_transfer.bin",
                    "direction": "download" if session.get("last_cmd") == "RETR" else "upload",
                })
                session["last_cmd"] = None
                session["last_filename"] = None

    # HTTP request correlation
    pending_requests: Dict[Tuple[str, str, int, int], List[str]] = defaultdict(list)
    for (src, dst, sport, dport), chunks in tcp_streams.items():
        stream, first_pkt = _assemble_stream(chunks)
        if not stream:
            continue
        if not _looks_like_http(stream):
            continue
        msgs = _parse_http_stream(stream)
        for m in msgs:
            if m["is_request"]:
                host = m["headers"].get("host")
                fn = _extract_request_filename(m["start_line"], host)
                if fn:
                    pending_requests[(dst, src, dport, sport)].append(fn)

    # HTTP/IMF/SMB/DICOM/X509/FTP data extraction
    for (src, dst, sport, dport), chunks in tcp_streams.items():
        stream, first_pkt = _assemble_stream(chunks)
        if not stream:
            continue

        protocol = _detect_app_protocol_from_stream(stream, sport, dport)

        # ENIP/CIP extraction (firmware or large object transfers)
        is_enip = ENIP_TCP_PORT in (sport, dport) or stream[:2] in {b"\x04\x00", b"\x63\x00", b"\x6f\x00", b"\x70\x00"}
        if is_enip:
            enip_frames = _parse_enip_frames(stream)
            if not enip_frames:
                enip_frames = _scan_enip_frames(stream)
            for cmd, data in enip_frames:
                if cmd in {0x006F, 0x0070}:
                    cip_payload = _parse_enip_cpf(data)
                else:
                    cip_payload = data
                if not cip_payload:
                    continue
                service, is_request, cip_data = _parse_cip_data(cip_payload)
                if service is None:
                    continue
                service_code = service & 0x7F
                if service_code not in enip_file_services and len(cip_data) < 1024:
                    continue
                service_name = CIP_SERVICE_NAMES.get(service_code, f"service_0x{service_code:02x}")
                direction = "request" if is_request else "response"
                key = (src, dst, sport, dport, service_name, direction)
                if key not in enip_buffers:
                    enip_buffers[key] = {
                        "data": bytearray(),
                        "first_pkt": first_pkt,
                        "service": service_name,
                        "direction": direction,
                        "src": src,
                        "dst": dst,
                        "sport": sport,
                        "dport": dport,
                    }
                buf = enip_buffers[key]["data"]
                if isinstance(buf, bytearray) and len(buf) < max_enip_bytes:
                    remaining = max_enip_bytes - len(buf)
                    buf.extend(cip_data[:remaining])
            

        # HTTP
        if protocol == "HTTP":
            names = pending_requests.get((src, dst, sport, dport), [])
            msgs = _parse_http_stream(stream)
            for m in msgs:
                if m["is_request"]:
                    continue
                body = m.get("body", b"")
                fname = "http_response.bin"
                explicit_name = False
                disp = m["headers"].get("content-disposition", "")
                if disp:
                    if "filename=" in disp.lower() or "attachment" in disp.lower():
                        explicit_name = True
                    match_star = re.search(r'filename\*=UTF-8\'\'(.+?)(?:;|$)', disp, re.IGNORECASE)
                    if match_star:
                        fname = unquote(match_star.group(1))
                    else:
                        match = re.search(r'filename=["\']?([^"\';]+)["\']?', disp, re.IGNORECASE)
                        if match:
                            fname = match.group(1)
                if fname == "http_response.bin":
                    content_location = m["headers"].get("content-location", "")
                    if content_location:
                        fname = content_location
                        explicit_name = True
                if fname == "http_response.bin" and names:
                    fname = names.pop(0)
                    explicit_name = True
                if fname == "http_response.bin":
                    content_type = m["headers"].get("content-type", "")
                    ext = _guess_extension_from_content_type(content_type) or "bin"
                    fname = f"http_{first_pkt}.{ext}"
                if fname == "http_response.bin":
                    fname = f"http_{first_pkt}.bin"
                ftype = detect_file_type_bytes(body) if body else "UNKNOWN"
                content_type = m["headers"].get("content-type", "")
                fname = _append_extension_if_missing(fname, content_type)
                if fname == "http_response.bin":
                    fname = f"http_{first_pkt}.bin"
                is_specific_name = fname != "http_response.bin" and not fname.startswith("extracted_")
                is_plausible = _is_plausible_filename(fname)
                is_binary_like = bool(content_type) and not content_type.startswith("text/")
                if not body:
                    continue
                if len(body) < 32 and not is_specific_name:
                    continue
                if not explicit_name and not is_specific_name and fname.startswith("http_"):
                    continue
                if not explicit_name and not is_specific_name and len(body) < 1024:
                    continue
                if not explicit_name and fname.startswith("http_") and len(body) < 524288:
                    continue
                if not is_specific_name and not is_binary_like and ftype in ("UNKNOWN", "BINARY"):
                    continue
                if not is_plausible and not is_specific_name:
                    continue

                if body.startswith(b"MZ") and not explicit_name:
                    exe_name = next((n for n in names if n.lower().endswith(".exe")), None)
                    if exe_name:
                        fname = exe_name
                        explicit_name = True
                _add_artifact(FileArtifact(
                    protocol="HTTP",
                    src_ip=src,
                    dst_ip=dst,
                    src_port=sport,
                    dst_port=dport,
                    filename=fname,
                    size_bytes=len(body) if body else None,
                    packet_index=first_pkt,
                    note="HTTP Response Body",
                    file_type=ftype,
                    payload=body if need_payload else None,
                ))

        # IMF (email attachments)
        if protocol in ("SMTP", "POP3", "IMAP") or (b"Content-Type" in stream and b"multipart" in stream):
            _extract_email_attachments(
                stream,
                protocol if protocol in ("SMTP", "POP3", "IMAP") else "IMF",
                src,
                dst,
                sport,
                dport,
                first_pkt,
                need_payload,
                artifacts,
            )

        # SMB (v1/2/3) filename discovery
        if protocol == "SMB" or sport in (445, 139) or dport in (445, 139) or b"\xfeSMB" in stream or b"\xffSMB" in stream:
            smb_records, _ = _iter_smb_records(stream)
            if not smb_records:
                smb_records = [stream]

            for record in smb_records:
                for name in _scan_smb2_create_filenames(record):
                    _add_artifact(FileArtifact(
                        protocol="SMB2",
                        src_ip=src,
                        dst_ip=dst,
                        src_port=sport,
                        dst_port=dport,
                        filename=name,
                        size_bytes=None,
                        packet_index=first_pkt,
                        note="SMB2 Create",
                        file_type="UNKNOWN",
                        payload=None,
                    ))
                # Skip heuristic SMB filename scans (too noisy)

        # DICOM
        dicm_positions = []
        start = 0
        while True:
            pos = stream.find(b"DICM", start)
            if pos == -1:
                break
            dicm_positions.append(pos)
            start = pos + 4
        for i, pos in enumerate(dicm_positions):
            start_idx = max(0, pos - 128)
            end_idx = dicm_positions[i + 1] - 128 if i + 1 < len(dicm_positions) else len(stream)
            blob = stream[start_idx:end_idx]
            _add_artifact(FileArtifact(
                protocol="DICOM",
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                filename=f"dicom_{first_pkt}_{i}.dcm",
                size_bytes=len(blob),
                packet_index=first_pkt,
                note="DICOM payload",
                file_type="DICOM",
                payload=blob if need_payload else None,
            ))

        # X509AF
        for pem in _extract_pem_certs(stream):
            digest = hashlib.sha256(_normalize_x509_payload(pem)).hexdigest()
            meta_key = (src, dst, f"x509_{first_pkt}.pem", len(pem))
            if digest in seen_x509 or meta_key in seen_x509_meta:
                continue
            seen_x509.add(digest)
            seen_x509_meta.add(meta_key)
            _add_artifact(FileArtifact(
                protocol="X509AF",
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                filename=f"x509_{first_pkt}.pem",
                size_bytes=len(pem),
                packet_index=first_pkt,
                note="X509 PEM",
                file_type="X509",
                payload=pem if need_payload else None,
            ))
        for der in _extract_der_blobs(stream):
            digest = hashlib.sha256(_normalize_x509_payload(der)).hexdigest()
            meta_key = (src, dst, f"x509_{first_pkt}.cer", len(der))
            if digest in seen_x509 or meta_key in seen_x509_meta:
                continue
            seen_x509.add(digest)
            seen_x509_meta.add(meta_key)
            _add_artifact(FileArtifact(
                protocol="X509AF",
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                filename=f"x509_{first_pkt}.cer",
                size_bytes=len(der),
                packet_index=first_pkt,
                note="X509 DER",
                file_type="X509",
                payload=der if need_payload else None,
            ))

        # FTP data flows
        matched_ftp = False
        for transfer in ftp_transfers:
            if transfer["data_port"] in (sport, dport):
                data_host = transfer.get("data_host")
                if data_host and data_host not in (src, dst):
                    continue
                if len(stream) < 256:
                    continue
                fname = transfer["filename"]
                _add_artifact(FileArtifact(
                    protocol="FTP",
                    src_ip=src,
                    dst_ip=dst,
                    src_port=sport,
                    dst_port=dport,
                    filename=fname,
                    size_bytes=len(stream),
                    packet_index=first_pkt,
                    note=f"FTP {transfer['direction']} data",
                    file_type=detect_file_type_bytes(stream),
                    payload=stream if need_payload else None,
                ))
                matched_ftp = True

        if not matched_ftp and (sport == 20 or dport == 20 or protocol == "FTP") and len(stream) > 2000:
            _add_artifact(FileArtifact(
                protocol="FTP",
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                filename=f"ftp_data_{first_pkt}.bin",
                size_bytes=len(stream),
                packet_index=first_pkt,
                note="FTP data",
                file_type=detect_file_type_bytes(stream),
                payload=stream if need_payload else None,
            ))

    # TFTP
    tftp_sessions: Dict[frozenset[str], Dict[str, Any]] = defaultdict(lambda: {"filename": None, "blocks": {}, "first_packet": 0, "sport": 0, "dport": 0})
    for src, dst, sport, dport, payload, pidx in udp_packets:
        if not _is_tftp_payload(payload):
            continue
        opcode = int.from_bytes(payload[:2], "big")
        key = frozenset({src, dst})
        sess = tftp_sessions[key]
        if sess["first_packet"] == 0:
            sess["first_packet"] = pidx
            sess["sport"] = sport
            sess["dport"] = dport
        if opcode in {1, 2}:
            fn = _extract_tftp(payload)
            if fn:
                sess["filename"] = fn
        elif opcode == 3:
            blk = int.from_bytes(payload[2:4], "big")
            sess["blocks"][blk] = payload[4:]

    for endpts, sess in tftp_sessions.items():
        if sess["filename"] and sess["blocks"]:
            ordered = sorted(sess["blocks"].items())
            data = b"".join(v for _, v in ordered)
            e_list = list(endpts)
            s = e_list[0]
            d = e_list[1] if len(e_list) > 1 else s
            _add_artifact(FileArtifact(
                protocol="TFTP",
                src_ip=s,
                dst_ip=d,
                src_port=sess["sport"],
                dst_port=sess["dport"],
                filename=sess["filename"],
                size_bytes=len(data),
                packet_index=sess["first_packet"],
                note="TFTP Transfer",
                file_type=detect_file_type_bytes(data),
                payload=data if need_payload else None,
            ))

    # ENIP/CIP extraction for UDP payloads
    for src, dst, sport, dport, payload, pidx in udp_packets:
        if ENIP_UDP_PORT not in (sport, dport):
            continue
        if len(payload) < ENIP_HEADER_LEN:
            continue
        enip_frames = _parse_enip_frames(payload)
        if not enip_frames:
            enip_frames = _scan_enip_frames(payload)
        for cmd, data in enip_frames:
            if cmd in {0x006F, 0x0070}:
                cip_payload = _parse_enip_cpf(data)
            else:
                cip_payload = data
            if not cip_payload:
                continue
            service, is_request, cip_data = _parse_cip_data(cip_payload)
            if service is None:
                continue
            service_code = service & 0x7F
            if service_code not in enip_file_services and len(cip_data) < 1024:
                continue
            service_name = CIP_SERVICE_NAMES.get(service_code, f"service_0x{service_code:02x}")
            direction = "request" if is_request else "response"
            key = (src, dst, sport, dport, service_name, direction)
            if key not in enip_buffers:
                enip_buffers[key] = {
                    "data": bytearray(),
                    "first_pkt": pidx,
                    "service": service_name,
                    "direction": direction,
                    "src": src,
                    "dst": dst,
                    "sport": sport,
                    "dport": dport,
                }
            buf = enip_buffers[key]["data"]
            if isinstance(buf, bytearray) and len(buf) < max_enip_bytes:
                remaining = max_enip_bytes - len(buf)
                buf.extend(cip_data[:remaining])

    # ENIP/CIP buffered artifacts
    for key, meta in enip_buffers.items():
        data = meta.get("data")
        if not isinstance(data, bytearray):
            continue
        if len(data) < min_enip_bytes:
            continue
        service_name = str(meta.get("service", "cip_data"))
        direction = str(meta.get("direction", "payload"))
        first_pkt = int(meta.get("first_pkt", 0) or 0)
        src = str(meta.get("src", ""))
        dst = str(meta.get("dst", ""))
        sport = int(meta.get("sport", 0) or 0)
        dport = int(meta.get("dport", 0) or 0)
        payload = bytes(data)
        digest = hashlib.sha256(payload).hexdigest()
        if digest in enip_payload_hashes:
            continue
        enip_payload_hashes.add(digest)

        candidate_names = _scan_filenames(payload)
        candidate_name = next((n for n in candidate_names if _is_plausible_filename(n)), None)
        if not candidate_name:
            alt_names = re.findall(r"[A-Za-z0-9_\-]{3,}\.(?:l5x|l5k|acd|bin|hex|fw|zip)", payload.decode("latin-1", errors="ignore"), re.IGNORECASE)
            candidate_name = next((n for n in alt_names if _is_plausible_filename(n)), None)
        file_type = detect_file_type_bytes(payload)
        if candidate_name:
            fname = _normalize_filename(candidate_name)
        else:
            if file_type in ("UNKNOWN", "BINARY") and len(payload) < min_enip_named_bytes:
                continue
            short_hash = hashlib.sha256(payload).hexdigest()[:10]
            if service_name in {"ProgramDownload", "ProgramUpload", "ProgramCommand"}:
                fname = _normalize_filename(
                    f"enip_{service_name}_{src}_to_{dst}_{direction}_{short_hash}.bin"
                )
            else:
                fname = _normalize_filename(
                    f"enip_{service_name}_{direction}_{short_hash}.bin"
                )
            if file_type not in ("UNKNOWN", "BINARY"):
                expected = _expected_extensions_for_type(file_type)
                if expected:
                    ext = sorted(expected)[0]
                    if not fname.lower().endswith(ext):
                        fname = f"{Path(fname).stem}{ext}"

        best_key = (service_name, direction, src, dst)
        best = enip_best.get(best_key)
        if best and len(payload) <= best[0]:
            continue
        enip_best[best_key] = (len(payload), fname)

        _add_artifact(FileArtifact(
            protocol="ENIP",
            src_ip=src,
            dst_ip=dst,
            src_port=sport,
            dst_port=dport,
            filename=fname,
            size_bytes=len(payload),
            packet_index=first_pkt,
            note=f"ENIP/CIP {service_name} payload ({direction})",
            file_type=file_type,
            payload=payload if need_payload else None,
        ))

    if artifacts:
        mismatch_seen: set[tuple[str, str, str]] = set()
        for art in artifacts:
            mismatch = _extension_mismatch(art.filename, art.file_type)
            if not mismatch:
                continue
            ext, expected = mismatch
            key = (art.filename, art.file_type, ext)
            if key in mismatch_seen:
                continue
            mismatch_seen.add(key)
            detections.append({
                "severity": "high",
                "summary": f"File extension/type mismatch: {art.filename}",
                "details": f"Extension {ext} does not match detected type {art.file_type}. Expected: {', '.join(sorted(expected))}.",
                "source": "Files",
            })

        if extract_name:
            out_root = output_dir or Path.cwd() / "files"
            out_root.mkdir(parents=True, exist_ok=True)
            search = extract_name.lower()
            for art in artifacts:
                if art.payload and search in art.filename.lower():
                    out_p = _unique_output_path(out_root, art.filename)
                    try:
                        out_p.write_bytes(art.payload)
                    except Exception:
                        pass
                    extracted_paths.append(out_p)

        if view_name:
            search = view_name.lower()
            for art in artifacts:
                if art.payload and search in art.filename.lower():
                    views.append({"filename": art.filename, "payload": art.payload, "size": len(art.payload)})

        detections.append({
            "severity": "info",
            "summary": "Files extracted via dpkt",
            "details": "Pure-Python protocol parsers used for discovery.",
            "source": "Files",
        })
        return FileTransferSummary(
            path=path,
            total_candidates=0,
            candidates=[],
            artifacts=artifacts,
            extracted=extracted_paths,
            views=views,
            detections=detections,
            errors=errors,
        )
    return None


def _dedupe_x509_artifacts(artifacts: List[FileArtifact]) -> List[FileArtifact]:
    seen: set[str] = set()
    unique: List[FileArtifact] = []
    for art in artifacts:
        if art.protocol != "X509AF":
            unique.append(art)
            continue
        payload = art.payload or b""
        if payload:
            key = hashlib.sha256(_normalize_x509_payload(payload)).hexdigest()
        else:
            key = f"{art.filename}|{art.src_ip}|{art.dst_ip}|{art.size_bytes}|{art.packet_index}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(art)
    return unique


def _dedupe_artifacts(artifacts: List[FileArtifact]) -> List[FileArtifact]:
    seen: set[tuple[str, str, str, str, int, int | None]] = set()
    unique: List[FileArtifact] = []
    for art in artifacts:
        key = (art.protocol, art.src_ip, art.dst_ip, art.filename, art.packet_index, art.size_bytes)
        if key in seen:
            continue
        seen.add(key)
        unique.append(art)
    return unique


def _expected_extensions_for_type(file_type: str) -> Optional[set[str]]:
    for key, value in FILE_TYPE_EXTENSIONS.items():
        if key.lower() == file_type.lower():
            return value
    return None


def _collect_extension_mismatches(artifacts: List[FileArtifact]) -> List[Tuple[str, str, str]]:
    mismatches: List[Tuple[str, str, str]] = []
    for art in artifacts:
        filename = art.filename or ""
        file_type = getattr(art, "file_type", "") or ""
        if not filename or not file_type:
            continue
        expected = _expected_extensions_for_type(file_type)
        if not expected:
            continue
        ext = Path(filename).suffix.lower()
        if not ext:
            continue
        if ext not in expected:
            mismatches.append((filename, file_type, ext))
    return mismatches


# --- Entry Point ---

def analyze_files(
    path: Path,
    extract_name: Optional[str] = None,
    output_dir: Optional[Path] = None,
    view_name: Optional[str] = None,
    show_status: bool = True,
    include_x509: bool = False,
) -> FileTransferSummary:
    if dpkt is None:
        return FileTransferSummary(path, 0, [], [], [], [], [], ["dpkt unavailable"])

    dpkt_summary = _export_with_dpkt(
        path,
        extract_name=extract_name,
        output_dir=output_dir,
        view_name=view_name,
        show_status=show_status,
        packets=None,
    )
    if dpkt_summary is None:
        return FileTransferSummary(path, 0, [], [], [], [], [], ["dpkt parsing failed"])

    if include_x509:
        artifacts = _dedupe_artifacts(_dedupe_x509_artifacts(dpkt_summary.artifacts))
        detections = list(dpkt_summary.detections)
        mismatches = _collect_extension_mismatches(artifacts)
        if mismatches:
            examples = "; ".join(
                f"{name} -> {ftype}" for name, ftype, _ in mismatches[:5]
            )
            detections.append({
                "severity": "high",
                "summary": "File extension/type mismatch detected",
                "details": f"{len(mismatches)} file(s) where extension does not match detected type. Examples: {examples}",
                "source": "Files",
            })
        return FileTransferSummary(
            path=dpkt_summary.path,
            total_candidates=dpkt_summary.total_candidates,
            candidates=dpkt_summary.candidates,
            artifacts=artifacts,
            extracted=dpkt_summary.extracted,
            views=dpkt_summary.views,
            detections=detections,
            errors=dpkt_summary.errors,
        )

    artifacts = [
        a for a in _dedupe_artifacts(_dedupe_x509_artifacts(dpkt_summary.artifacts))
        if a.protocol != "X509AF"
    ]
    detections = list(dpkt_summary.detections)
    mismatches = _collect_extension_mismatches(artifacts)
    if mismatches:
        examples = "; ".join(
            f"{name} -> {ftype}" for name, ftype, _ in mismatches[:5]
        )
        detections.append({
            "severity": "high",
            "summary": "File extension/type mismatch detected",
            "details": f"{len(mismatches)} file(s) where extension does not match detected type. Examples: {examples}",
            "source": "Files",
        })

    return FileTransferSummary(
        path=dpkt_summary.path,
        total_candidates=dpkt_summary.total_candidates,
        candidates=dpkt_summary.candidates,
        artifacts=artifacts,
        extracted=dpkt_summary.extracted,
        views=dpkt_summary.views,
        detections=detections,
        errors=dpkt_summary.errors,
    )
