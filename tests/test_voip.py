"""Tests for phone-over-IP analysis.

Split between parser unit tests, which need no capture, and end-to-end
assertions against the three committed fixtures:

``voip.pcap``            a complete SIP call — register, digest auth, INVITE with
                         SDP carrying an SRTP key, G.711 media, RFC 4733 DTMF,
                         RTCP, BYE, and a TFTP config fetch.
``voip_multiproto.pcap`` the same site's other call control — Skinny, MGCP,
                         IAX2 and H.225.
``voip_attack.pcap``     an internet-facing PBX being enumerated and
                         brute-forced by SIPVicious.
"""

from __future__ import annotations

import wave
from pathlib import Path

import pytest

from pcapper.voip import (
    _looks_like_sip,
    _parse_auth,
    _parse_headers,
    _split_sip_messages,
    _uri_user,
    analyze_voip,
    classify_destination,
    hashcat_sip_digest,
    merge_voip_summaries,
    parse_sdp,
)
from pcapper.voip_media import (
    ALAW_TABLE,
    ULAW_TABLE,
    decode_dtmf_event,
    decode_g711,
    is_rtcp,
    is_rtp_candidate,
    is_stun,
    parse_rtcp,
    parse_rtp,
    parse_stun,
)
from pcapper.voip_signaling import (
    classify_provisioning,
    looks_like_sccp,
    parse_iax2,
    parse_mgcp,
    parse_q931,
    parse_sccp,
    parse_tftp_request,
)


# --- SIP parsing ------------------------------------------------------------
class TestSipParsing:
    def test_recognises_requests_and_responses(self) -> None:
        assert _looks_like_sip("INVITE sip:a@b SIP/2.0\r\n\r\n")
        assert _looks_like_sip("SIP/2.0 200 OK\r\n\r\n")

    def test_rejects_non_sip(self) -> None:
        assert not _looks_like_sip("GET / HTTP/1.1\r\n\r\n")
        assert not _looks_like_sip("")
        assert not _looks_like_sip("\x00\x01\x02")

    def test_compact_header_forms_are_expanded(self) -> None:
        """Real phones send these; a parser that only knows the long spellings
        loses the Call-ID, and every dialog with it."""
        raw = (
            "INVITE sip:2@pbx SIP/2.0\r\n"
            "i: abc123@phone\r\n"
            "f: <sip:1001@pbx>;tag=x\r\n"
            "t: <sip:2000@pbx>\r\n"
            "m: <sip:1001@10.0.0.1>\r\n"
            "v: SIP/2.0/UDP 10.0.0.1\r\n"
            "c: application/sdp\r\n\r\nv=0\r\n"
        )
        headers, body = _parse_headers(raw)
        assert headers["call-id"] == ["abc123@phone"]
        assert headers["from"] == ["<sip:1001@pbx>;tag=x"]
        assert headers["contact"] == ["<sip:1001@10.0.0.1>"]
        assert headers["content-type"] == ["application/sdp"]
        assert body.startswith("v=0")

    def test_folded_header_is_unfolded(self) -> None:
        raw = (
            "INVITE sip:2@pbx SIP/2.0\r\n"
            "Subject: a very\r\n"
            "  long subject\r\n"
            "Call-ID: x\r\n\r\n"
        )
        headers, _ = _parse_headers(raw)
        assert headers["subject"] == ["a very long subject"]

    def test_multiple_messages_in_one_payload(self) -> None:
        text = (
            "SIP/2.0 100 Trying\r\nCall-ID: a\r\n\r\n"
            "SIP/2.0 180 Ringing\r\nCall-ID: a\r\n\r\n"
        )
        assert len(_split_sip_messages(text)) == 2

    def test_uri_user_and_host(self) -> None:
        assert _uri_user("sip:1001@pbx.example.com") == ("1001", "pbx.example.com")
        assert _uri_user("sips:alice@example.org;transport=tls")[0] == "alice"
        assert _uri_user("garbage") == ("", "")

    def test_digest_parameters(self) -> None:
        value = (
            'Digest username="1001", realm="asterisk", nonce="abc", '
            'uri="sip:pbx", response="deadbeef", algorithm=MD5, qop=auth, '
            'nc=00000001, cnonce="xyz"'
        )
        params = _parse_auth(value)
        assert params["username"] == "1001"
        assert params["qop"] == "auth"
        assert params["nc"] == "00000001"

    def test_hashcat_line_has_the_expected_field_count(self) -> None:
        params = {
            "username": "1001", "realm": "asterisk", "nonce": "abc",
            "uri": "sip:pbx.example.com", "response": "deadbeef",
            "algorithm": "MD5", "cnonce": "xyz", "nc": "00000001", "qop": "auth",
        }
        line = hashcat_sip_digest(params, "REGISTER", "10.0.0.1", "10.0.0.2")
        assert line.startswith("$sip$*")
        # $sip$ plus the mode's 14 fields.
        assert len(line.split("*")) == 15
        assert line.endswith("*deadbeef")


class TestSdp:
    SDP = (
        "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n"
        "m=audio 40000 RTP/SAVP 0 8 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\n"
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Zm9vYmFyYmF6cXV4\r\n"
        "a=sendonly\r\n"
    )

    def test_media_line(self) -> None:
        media = parse_sdp(self.SDP, "call-1", "10.0.0.1")
        assert len(media) == 1
        entry = media[0]
        assert (entry.media_type, entry.port, entry.address) == ("audio", 40000, "10.0.0.1")
        assert entry.transport == "RTP/SAVP"
        assert entry.direction == "sendonly"
        assert "telephone-event/8000" in entry.codecs

    def test_cleartext_srtp_key_is_captured(self) -> None:
        entry = parse_sdp(self.SDP, "call-1", "10.0.0.1")[0]
        assert entry.crypto_suites == ("AES_CM_128_HMAC_SHA1_80",)
        assert entry.cleartext_keys == ("Zm9vYmFyYmF6cXV4",)

    def test_session_level_connection_is_inherited(self) -> None:
        sdp = "v=0\r\nc=IN IP4 192.0.2.9\r\nm=audio 5000 RTP/AVP 0\r\n"
        assert parse_sdp(sdp, "c", "x")[0].address == "192.0.2.9"

    def test_empty_body(self) -> None:
        assert parse_sdp("", "c", "x") == []


# --- media ------------------------------------------------------------------
class TestG711:
    def test_tables_cover_every_byte(self) -> None:
        assert len(ULAW_TABLE) == 256
        assert len(ALAW_TABLE) == 256

    def test_mu_law_silence_and_extremes(self) -> None:
        # 0xFF is mu-law silence; 0x00 is the largest negative excursion.
        assert ULAW_TABLE[0xFF] == 0
        assert ULAW_TABLE[0x00] == -32124
        assert ULAW_TABLE[0x80] == 32124

    def test_decode_produces_two_bytes_per_sample(self) -> None:
        assert len(decode_g711(b"\xff" * 160, 0)) == 320
        assert len(decode_g711(b"\xd5" * 160, 8)) == 320

    def test_unsupported_codec_decodes_to_nothing(self) -> None:
        # G.729 needs a real codec; returning noise would be worse than nothing.
        assert decode_g711(b"\x01" * 20, 18) == b""


class TestRtp:
    HEADER = bytes([0x80, 0x00]) + (7).to_bytes(2, "big") + (160).to_bytes(4, "big")
    PACKET = HEADER + (0xDEADBEEF).to_bytes(4, "big") + b"\xff" * 160

    def test_valid_packet_is_a_candidate(self) -> None:
        assert is_rtp_candidate(self.PACKET, 40000, 40002)

    def test_parsed_fields(self) -> None:
        parsed = parse_rtp(self.PACKET)
        assert parsed is not None
        assert parsed["sequence"] == 7
        assert parsed["ssrc"] == 0xDEADBEEF
        assert len(parsed["payload"]) == 160

    @pytest.mark.parametrize("sport,dport", [(53, 40000), (40000, 123), (5353, 40000)])
    def test_well_known_service_ports_are_never_rtp(self, sport, dport) -> None:
        assert not is_rtp_candidate(self.PACKET, sport, dport)

    def test_stun_on_a_media_port_is_not_rtp(self) -> None:
        stun = bytes([0x00, 0x01, 0x00, 0x00]) + b"\x21\x12\xa4\x42" + b"\x00" * 12
        assert not is_rtp_candidate(stun, 40000, 40002)

    def test_version_1_is_rejected(self) -> None:
        assert not is_rtp_candidate(b"\x40" + self.PACKET[1:], 40000, 40002)

    def test_rtcp_shadow_payload_types_are_rejected(self) -> None:
        # 72-76 are reserved so RTCP is never read as RTP.
        assert not is_rtp_candidate(bytes([0x80, 72]) + self.PACKET[2:], 40000, 40002)

    def test_csrc_list_is_skipped(self) -> None:
        packet = bytes([0x81, 0x00]) + self.PACKET[2:12] + b"\xaa\xbb\xcc\xdd" + b"\x11" * 20
        parsed = parse_rtp(packet)
        assert parsed is not None
        assert parsed["csrc_count"] == 1
        assert len(parsed["payload"]) == 20


class TestDtmf:
    def test_decodes_a_digit(self) -> None:
        assert decode_dtmf_event(bytes([7, 0x0A, 0x01, 0x40])) == ("7", 320, False)

    def test_end_flag(self) -> None:
        assert decode_dtmf_event(bytes([1, 0x8A, 0x00, 0x10]))[2] is True

    @pytest.mark.parametrize("code,digit", [(0, "0"), (9, "9"), (10, "*"), (11, "#"), (12, "A")])
    def test_full_keypad(self, code, digit) -> None:
        assert decode_dtmf_event(bytes([code, 0, 0, 0]))[0] == digit

    def test_short_payload(self) -> None:
        assert decode_dtmf_event(b"\x01") is None


class TestRtcp:
    SDES = (
        b"\x81\xca\x00\x05"
        + (0x11223344).to_bytes(4, "big")
        + bytes([1, 11])
        + b"alice@host1"
        # NUL terminator plus padding to the 24 bytes the header declares
        # ((length + 1) * 4 with length = 5).
        + b"\x00\x00\x00"
    )

    def test_recognised(self) -> None:
        assert is_rtcp(self.SDES)

    def test_cname_is_recovered(self) -> None:
        """The CNAME survives SSRC changes, so it is the one durable
        attribution handle the media plane offers."""
        parsed = parse_rtcp(self.SDES)
        assert ("CNAME", "alice@host1") in parsed["sdes"]

    def test_truncated_input_does_not_raise(self) -> None:
        assert parse_rtcp(b"\x81\xca\xff\xff")["sdes"] == []


class TestStun:
    BINDING = (
        bytes([0x01, 0x01, 0x00, 0x0C])
        + b"\x21\x12\xa4\x42"
        + b"\x00" * 12
        + bytes([0x00, 0x20, 0x00, 0x08])
        + bytes([0x00, 0x01])
        + (40000 ^ 0x2112).to_bytes(2, "big")
        + bytes([192 ^ 0x21, 0 ^ 0x12, 2 ^ 0xA4, 9 ^ 0x42])
    )

    def test_recognised(self) -> None:
        assert is_stun(self.BINDING)

    def test_xor_mapped_address_is_decoded(self) -> None:
        parsed = parse_stun(self.BINDING)
        assert parsed["method"] == "Binding"
        assert parsed["attributes"]["XOR-MAPPED-ADDRESS"] == "192.0.2.9:40000"


# --- non-SIP signalling ------------------------------------------------------
class TestSkinny:
    def _frame(self, message_id: int, body: bytes) -> bytes:
        return (
            (len(body) + 4).to_bytes(4, "little")
            + b"\x00\x00\x00\x00"
            + message_id.to_bytes(4, "little")
            + body
        )

    def test_little_endian_framing(self) -> None:
        """Skinny is little-endian throughout, which is the usual reason a
        hand-rolled parser reads it as garbage."""
        frame = self._frame(0x0003, (7).to_bytes(4, "little") + b"\x00" * 8)
        assert looks_like_sccp(frame)
        assert parse_sccp(frame)[0]["name"] == "KeypadButton"

    def test_keypad_digit(self) -> None:
        frame = self._frame(0x0003, (11).to_bytes(4, "little") + b"\x00" * 8)
        assert parse_sccp(frame)[0]["digit"] == "#"

    def test_device_registration(self) -> None:
        body = b"SEP001122334455".ljust(16, b"\x00") + b"\x00" * 8
        assert parse_sccp(self._frame(0x0001, body))[0]["device"] == "SEP001122334455"

    def test_multiple_messages_in_one_segment(self) -> None:
        frame = self._frame(0x0003, (1).to_bytes(4, "little") + b"\x00" * 8)
        assert len(parse_sccp(frame * 3)) == 3

    def test_garbage_is_rejected(self) -> None:
        assert not looks_like_sccp(b"\xff" * 32)


class TestMgcp:
    def test_notify_carries_dialled_digits(self) -> None:
        """NTFY ObservedEvents is where a media gateway reports the digits the
        caller pressed."""
        parsed = parse_mgcp(
            "NTFY 1201 aaln/1@gw.example.com MGCP 1.0\r\nO: D/5,D/1,D/9\r\n"
        )
        assert parsed is not None
        assert parsed["verb"] == "NTFY"
        assert parsed["digits"] == "519"
        assert parsed["endpoint"] == "aaln/1@gw.example.com"

    def test_response(self) -> None:
        parsed = parse_mgcp("200 1201 OK\r\n")
        assert parsed is not None and parsed["code"] == 200

    def test_non_mgcp(self) -> None:
        assert parse_mgcp("hello world") is None


class TestIax2:
    def _full(self, subclass: int, ies: bytes = b"") -> bytes:
        return (
            (0x8000 | 1).to_bytes(2, "big")
            + (2).to_bytes(2, "big")
            + (0).to_bytes(4, "big")
            + bytes([0, 1, 0x06, subclass])
            + ies
        )

    def test_new_frame_carries_the_numbers(self) -> None:
        ies = bytes([0x02, 4]) + b"1001" + bytes([0x01, 5]) + b"90210"
        frame = parse_iax2(self._full(0x01, ies))
        assert frame is not None
        assert frame["name"] == "NEW"
        assert frame["ies"]["CALLING_NUMBER"] == "1001"
        assert frame["ies"]["CALLED_NUMBER"] == "90210"

    def test_auth_response_is_recoverable(self) -> None:
        ies = bytes([0x11, 32]) + b"5f4dcc3b5aa765d61d8327deb882cf99"
        frame = parse_iax2(self._full(0x09, ies))
        assert frame is not None
        assert frame["name"] == "AUTHREP"
        assert frame["ies"]["MD5_RESULT"].startswith("5f4dcc3b")

    def test_mini_frame(self) -> None:
        assert parse_iax2(b"\x00\x01\x00\x02" + b"\x00" * 8)["kind"] == "mini"


class TestH323:
    def test_q931_setup_is_named(self) -> None:
        payload = b"\x03\x00\x00\x1e" + b"\x08\x02\x12\x34\x05" + b"1001call" * 2
        parsed = parse_q931(payload)
        assert parsed is not None
        assert parsed["message"] == "SETUP"

    def test_non_q931(self) -> None:
        assert parse_q931(b"\x01\x02\x03") is None


class TestProvisioning:
    def test_tftp_read_request(self) -> None:
        parsed = parse_tftp_request(b"\x00\x01SEP001122334455.cnf.xml\x00octet\x00")
        assert parsed is not None
        assert parsed["opcode"] == "RRQ"
        assert parsed["filename"] == "SEP001122334455.cnf.xml"

    @pytest.mark.parametrize(
        "name",
        [
            "SEP001122334455.cnf.xml",
            "001122334455.cfg",
            "y000000000000.cfg",
            "/provisioning/1001.xml",
        ],
    )
    def test_known_config_shapes(self, name: str) -> None:
        assert classify_provisioning(name)

    def test_unrelated_filename(self) -> None:
        assert classify_provisioning("holiday-photo.jpg") == ""


class TestDestinationClassification:
    def test_premium_prefix(self) -> None:
        assert "premium" in classify_destination("9005551234")

    def test_international(self) -> None:
        assert "international" in classify_destination("+441134960000")

    @pytest.mark.parametrize("number", ["", "1001", "200", "x"])
    def test_internal_extensions_are_not_flagged(self, number: str) -> None:
        assert classify_destination(number) == ""


# --- end to end --------------------------------------------------------------
class TestSipCallCapture:
    def test_protocol_mix(self, pcap) -> None:
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        assert summary.errors == []
        assert summary.protocols["SIP"] == 11
        assert summary.protocols["TFTP provisioning"] == 1
        assert summary.rtp_packets == 72
        assert summary.rtcp_packets == 1

    def test_call_is_reconstructed(self, pcap) -> None:
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        answered = [c for c in summary.calls if c.disposition.startswith("answered")]
        assert len(answered) == 1
        call = answered[0]
        assert call.from_user == "1001"
        assert call.to_user == "441134960000"
        assert call.duration_seconds is not None

    def test_registration(self, pcap) -> None:
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        assert len(summary.registrations) == 1
        reg = summary.registrations[0]
        assert reg.successes == 1 and reg.challenges == 1

    def test_digest_credential_is_recovered_with_a_hashcat_line(self, pcap) -> None:
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        assert len(summary.credentials) == 1
        cred = summary.credentials[0]
        assert (cred.protocol, cred.username, cred.realm) == ("SIP", "1001", "asterisk")
        assert cred.crackable.startswith("$sip$*")
        assert len(cred.crackable.split("*")) == 15

    def test_cleartext_srtp_key_is_flagged(self, pcap) -> None:
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        keyed = [m for m in summary.media if m.cleartext_keys]
        assert keyed
        assert any("SRTP master key" in str(d["summary"]) for d in summary.detections)

    def test_dtmf_digits_are_recovered(self, pcap) -> None:
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        assert [d.digits for d in summary.dtmf] == ["4827"]
        assert any("DTMF" in str(d["summary"]) for d in summary.detections)

    def test_rtp_streams_have_no_phantom_loss(self, pcap) -> None:
        """A contiguous stream must report zero loss; getting this wrong is how
        a clean call ends up looking like a network fault."""
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        assert len(summary.rtp_streams) == 2
        for stream in summary.rtp_streams:
            assert stream.loss_percent == 0.0
            assert stream.codec == "PCMU/8000"

    def test_rtcp_cname(self, pcap) -> None:
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        assert "1001@192.168.10.60" in summary.rtcp_cnames

    def test_provisioning_fetch_is_classified(self, pcap) -> None:
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        assert len(summary.provisioning) == 1
        assert summary.provisioning[0].classification == "Cisco phone config"
        assert any("configuration downloaded" in str(d["summary"]) for d in summary.detections)

    def test_audio_extraction(self, pcap, tmp_path: Path) -> None:
        out = tmp_path / "voip"
        summary = analyze_voip(pcap("voip.pcap"), show_status=False, output_dir=out)
        assert len(summary.extracted_audio) == 2
        for item in summary.extracted_audio:
            with wave.open(item) as handle:
                assert handle.getnchannels() == 1
                assert handle.getsampwidth() == 2
                assert handle.getframerate() == 8000
                # 30 G.711 packets x 160 samples; the telephone-event packets
                # must not be decoded as audio.
                assert handle.getnframes() == 4800

    def test_no_audio_written_without_an_output_dir(self, pcap) -> None:
        summary = analyze_voip(pcap("voip.pcap"), show_status=False)
        assert summary.extracted_audio == []


class TestMultiProtocolCapture:
    def test_every_signalling_protocol_is_seen(self, pcap) -> None:
        """The point of the module: a Cisco/Asterisk/H.323 site carries no SIP
        at all, and reading only SIP would report an empty capture."""
        summary = analyze_voip(pcap("voip_multiproto.pcap"), show_status=False)
        assert summary.errors == []
        assert summary.protocols["SCCP/Skinny"] == 7
        assert summary.protocols["MGCP"] == 2
        assert summary.protocols["IAX2"] == 3
        assert summary.protocols["H.323 (H.225)"] == 1
        assert "SIP" not in summary.protocols

    def test_skinny_keypad_digits(self, pcap) -> None:
        summary = analyze_voip(pcap("voip_multiproto.pcap"), show_status=False)
        digits = {d.protocol: d.digits for d in summary.dtmf}
        assert digits["SCCP"] == "91123"

    def test_mgcp_observed_digits(self, pcap) -> None:
        summary = analyze_voip(pcap("voip_multiproto.pcap"), show_status=False)
        digits = {d.protocol: d.digits for d in summary.dtmf}
        assert digits["MGCP"] == "5551212"

    def test_skinny_device_registration(self, pcap) -> None:
        summary = analyze_voip(pcap("voip_multiproto.pcap"), show_status=False)
        assert any(r.aor == "SEP020000000003" for r in summary.registrations)

    def test_iax2_credential(self, pcap) -> None:
        summary = analyze_voip(pcap("voip_multiproto.pcap"), show_status=False)
        creds = [c for c in summary.credentials if c.protocol == "IAX2"]
        assert len(creds) == 1
        assert creds[0].username == "trunk1"
        assert "challenge=483920175" in creds[0].crackable

    def test_iax2_full_frames_are_not_eaten_by_the_rtp_heuristic(self, pcap) -> None:
        """Regression: an IAX2 full frame sets the top bit of byte 0, which is
        exactly what an RTP version-2 header looks like. The generic media
        detector swallowed every one of them until the port-identified
        protocols were moved ahead of it."""
        summary = analyze_voip(pcap("voip_multiproto.pcap"), show_status=False)
        assert summary.protocols.get("IAX2") == 3
        assert summary.rtp_packets == 0

    def test_h323_setup(self, pcap) -> None:
        summary = analyze_voip(pcap("voip_multiproto.pcap"), show_status=False)
        assert summary.request_counts.get("H.225 SETUP") == 1


class TestAttackCapture:
    def test_scanner_is_identified(self, pcap) -> None:
        summary = analyze_voip(pcap("voip_attack.pcap"), show_status=False)
        assert any("scanning/attack tool" in str(d["summary"]) for d in summary.detections)

    def test_enumeration_and_brute_force(self, pcap) -> None:
        summary = analyze_voip(pcap("voip_attack.pcap"), show_status=False)
        titles = {str(d["summary"]) for d in summary.detections}
        assert "SIP extension enumeration" in titles
        assert "VoIP authentication brute force / password spray" in titles

    def test_no_false_non_standard_port_finding(self, pcap) -> None:
        """The scanner uses ephemeral source ports. Taking the source port as
        the server port whenever the destination was unrecognised labelled every
        reply as non-standard SIP."""
        summary = analyze_voip(pcap("voip_attack.pcap"), show_status=False)
        assert not any(
            "non-standard ports" in str(d["summary"]) for d in summary.detections
        )

    def test_deterministic_checks_are_populated(self, pcap) -> None:
        summary = analyze_voip(pcap("voip_attack.pcap"), show_status=False)
        assert summary.deterministic_checks["voip_scanning_or_enumeration"]
        assert summary.deterministic_checks["voip_authentication_attacks"]

    def test_hypotheses(self, pcap) -> None:
        summary = analyze_voip(pcap("voip_attack.pcap"), show_status=False)
        assert any(
            h["hypothesis"] == "VoIP account takeover" for h in summary.threat_hypotheses
        )


class TestNoVoipTraffic:
    def test_clean_capture_yields_nothing(self, pcap) -> None:
        summary = analyze_voip(pcap("dns.pcap"), show_status=False)
        assert summary.errors == []
        assert summary.protocols == {} or sum(summary.protocols.values()) == 0
        assert summary.calls == []
        assert summary.detections == []

    def test_modbus_is_not_mistaken_for_rtp(self, pcap) -> None:
        summary = analyze_voip(pcap("modbus.pcap"), show_status=False)
        assert summary.rtp_packets == 0


class TestMerge:
    def test_merges_counters_and_lists(self, pcap) -> None:
        first = analyze_voip(pcap("voip.pcap"), show_status=False)
        second = analyze_voip(pcap("voip_attack.pcap"), show_status=False)
        merged = merge_voip_summaries([first, second])
        assert merged.protocols["SIP"] == first.protocols["SIP"] + second.protocols["SIP"]
        assert len(merged.credentials) == len(first.credentials) + len(second.credentials)
        assert merged.path.name == "ALL_PCAPS"

    def test_benign_context_requires_agreement(self, pcap) -> None:
        """A "nothing seen" note only holds for the rollup if it held for every
        capture; one capture full of scanners must not be reported as clean."""
        first = analyze_voip(pcap("voip.pcap"), show_status=False)
        second = analyze_voip(pcap("voip_attack.pcap"), show_status=False)
        merged = merge_voip_summaries([first, second])
        assert not any("scanner" in note for note in merged.benign_context)

    def test_empty_merge(self) -> None:
        assert merge_voip_summaries([]).path.name == "ALL_PCAPS"
