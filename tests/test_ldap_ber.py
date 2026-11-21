"""BER decoding of cleartext LDAP (pcapper.ldap_ber) and what the LDAP
analyzer derives from it. Messages are built with a tiny encoder so each
test states exactly the bytes on the wire."""

from __future__ import annotations

from scapy.all import IP, TCP, Ether, Raw, wrpcap

from pcapper.ldap import analyze_ldap
from pcapper.ldap_ber import iter_ldap_messages


def tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + value


def octets(text: str, tag: int = 0x04) -> bytes:
    return tlv(tag, text.encode())


def message(msg_id: int, op: bytes) -> bytes:
    return tlv(0x30, tlv(0x02, bytes([msg_id])) + op)


def simple_bind(msg_id: int, name: str, password: str) -> bytes:
    return message(msg_id, tlv(0x60, tlv(0x02, b"\x03") + octets(name) + octets(password, 0x80)))


def search(msg_id: int, base: str, flt: bytes, attrs: list[str]) -> bytes:
    body = (octets(base) + tlv(0x0A, b"\x02") + tlv(0x0A, b"\x00") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00")
            + tlv(0x01, b"\x00") + flt + tlv(0x30, b"".join(octets(a) for a in attrs)))
    return message(msg_id, tlv(0x63, body))


def eq(attr: str, value: str) -> bytes:
    return tlv(0xA3, octets(attr) + octets(value))


def present(attr: str) -> bytes:
    return tlv(0x87, attr.encode())


def modify(msg_id: int, dn: str, op: int, attr: str, values: list[str]) -> bytes:
    change = tlv(0x30, tlv(0x0A, bytes([op])) + tlv(0x30, octets(attr) + tlv(0x31, b"".join(octets(v) for v in values))))
    return message(msg_id, tlv(0x66, octets(dn) + tlv(0x30, change)))


def entry(msg_id: int, dn: str, attrs: dict[str, list[str]]) -> bytes:
    parts = b"".join(tlv(0x30, octets(k) + tlv(0x31, b"".join(octets(v) for v in vals))) for k, vals in attrs.items())
    return message(msg_id, tlv(0x64, octets(dn) + tlv(0x30, parts)))


def result(msg_id: int, op_tag: int, code: int, diag: str = "") -> bytes:
    return message(msg_id, tlv(op_tag, tlv(0x0A, bytes([code])) + octets("") + octets(diag)))


def test_decodes_bind_search_filter_and_modify() -> None:
    flt = tlv(0xA0, eq("objectCategory", "person") + present("servicePrincipalName"))
    data = (simple_bind(1, "CORP\\alice", "Winter2024!") + search(2, "DC=corp,DC=local", flt, ["sAMAccountName"])
            + modify(3, "CN=SRV01,DC=corp,DC=local", 0, "msDS-AllowedToActOnBehalfOfOtherIdentity", ["x"]))
    msgs = list(iter_ldap_messages(data))
    assert [m.op for m in msgs] == ["BindRequest", "SearchRequest", "ModifyRequest"]
    assert (msgs[0].dn, msgs[0].auth, msgs[0].password) == ("CORP\\alice", "simple", "Winter2024!")
    assert msgs[1].filter == "(&(objectCategory=person)(servicePrincipalName=*))"
    assert (msgs[1].dn, msgs[1].scope, msgs[1].attributes) == ("DC=corp,DC=local", "sub", ("sAMAccountName",))
    assert msgs[2].changes == ("add:msDS-AllowedToActOnBehalfOfOtherIdentity",)


def test_resyncs_on_a_message_that_starts_mid_segment() -> None:
    tail = b"\x04\x03abc\x31\x00"  # the end of a previous, larger message
    data = tail + entry(7, "CN=bob,CN=Users,DC=corp,DC=local", {"sAMAccountName": ["bob"], "objectClass": ["user"]})
    msgs = list(iter_ldap_messages(data))
    assert [(m.op, m.dn) for m in msgs] == [("SearchResultEntry", "CN=bob,CN=Users,DC=corp,DC=local")]
    assert msgs[0].values["sAMAccountName"] == ["bob"]


def test_sealed_or_random_payload_yields_nothing() -> None:
    assert list(iter_ldap_messages(b"\x00\x00\x01\x02" + bytes(range(256)))) == []


def test_analyzer_counts_decoded_operations_not_substrings(tmp_path) -> None:
    capture = tmp_path / "ldap.pcap"

    def pkt(ts: float, payload: bytes, to_server: bool = True):
        ip = IP(src="10.0.0.5", dst="10.0.0.1") if to_server else IP(src="10.0.0.1", dst="10.0.0.5")
        tcp = TCP(sport=50000, dport=389, flags="PA") if to_server else TCP(sport=389, dport=50000, flags="PA")
        p = Ether() / ip / tcp / Raw(load=payload)
        p.time = ts
        return p

    flt = present("ms-Mcs-AdmPwd")
    wrpcap(str(capture), [
        pkt(1, simple_bind(1, "CORP\\alice", "Winter2024!")),
        pkt(2, result(1, 0x61, 0), to_server=False),
        pkt(3, search(2, "DC=corp,DC=local", flt, ["ms-Mcs-AdmPwd"])),
        # An entry whose DN names "Deleted Objects" was once counted as a
        # Delete operation.
        pkt(4, entry(2, "CN=Deleted Objects,DC=corp,DC=local", {"objectClass": ["container"]}), to_server=False),
        pkt(5, entry(2, "CN=WS01,OU=PCs,DC=corp,DC=local", {"sAMAccountName": ["WS01$"], "objectClass": ["computer"]}),
            to_server=False),
        pkt(6, result(2, 0x65, 0), to_server=False),
    ])

    result_summary = analyze_ldap(capture, show_status=False)

    assert result_summary.request_counts["Bind"] == 1
    assert result_summary.request_counts["Search"] == 1
    assert "Delete" not in result_summary.request_counts
    assert result_summary.entries_returned == 2
    assert result_summary.ldap_systems["WS01$"] == 1
    assert "simple bind CORP\\alice: Winter2024!" in result_summary.secrets
    assert result_summary.search_requests[0]["filter"] == "(ms-Mcs-AdmPwd=*)"
    titles = {d["summary"] for d in result_summary.detections}
    assert "LDAP queries for password attributes" in titles
