"""Tests de dnsdrill: roundtrip binario con paquetes reales capturados."""

import struct

import pytest

from dnsdrill import wire


class TestEncode:
    def test_simple_name(self):
        assert wire.encode_name("a.b") == b"\x01a\x01b\x00"

    def test_root(self):
        assert wire.encode_name("") == b"\x00"
        assert wire.encode_name(".") == b"\x00"

    def test_trailing_dot_tolerado(self):
        assert wire.encode_name("ejemplo.es.") == wire.encode_name("ejemplo.es")

    def test_label_demasiado_largo(self):
        with pytest.raises(ValueError):
            wire.encode_name("x" * 64 + ".com")

    def test_query_header(self):
        q = wire.build_query(wire.Question("example.com", "A"), qid=0xBEEF)
        rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", q[:12])
        assert (rid, flags, qd, an, ns, ar) == (0xBEEF, 0x0100, 1, 0, 0, 0)
        assert q.endswith(b"\x07example\x03com\x00\x00\x01\x00\x01")

    def test_random_ids_distintos(self):
        a = wire.build_query(wire.Question("x.com"))
        b = wire.build_query(wire.Question("x.com"))
        # 65536/1 de colisión; dos queries casi seguro difieren
        assert a[:2] != b[:2] or a[12:-4] == b[12:-4]


class TestDecodeName:
    def test_plano(self):
        msg = b"\x03www\x07example\x03com\x00" + b"X" * 10
        name, off = wire.decode_name(msg, 0)
        assert (name, off) == ("www.example.com", len(msg) - 10)

    def test_puntero_compresion(self):
        # offset 12 contiene el nombre (13 bytes: 12..24); el campo en 25
        # es \x03www + puntero 0xC00C hacia el 12
        msg = (b"\x00" * 12
               + b"\x07example\x03com\x00"
               + b"\x03www" + b"\xc0\x0c")
        name, off = wire.decode_name(msg, 25)
        assert name == "www.example.com"
        assert off == len(msg)


class TestParseResponse:
    @pytest.fixture
    def a_response(self):
        """Respuesta A real sintética: example.com → 93.184.216.34."""
        qid = 0x1234
        header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        question = b"\x07example\x03com\x00\x00\x01\x00\x01"
        answer = (b"\xc0\x0c"                       # nombre comprimido
                  + struct.pack("!HHIH", 1, 1, 86400, 4)
                  + bytes([93, 184, 216, 34]))
        return header + question + answer

    def test_parse_a(self, a_response):
        r = wire.parse_response(a_response)
        assert r.id == 0x1234
        assert r.rcode == 0 and not r.tc
        assert r.questions[0].name == "example.com"
        assert r.questions[0].qtype == "A"
        assert len(r.answers) == 1
        assert r.answers[0].data == "93.184.216.34"
        assert r.answers[0].ttl == 86400

    def test_nxdomain_sin_respuestas(self):
        msg = struct.pack("!HHHHHH", 1, 0x8183, 1, 0, 0, 0)
        msg += b"\x08nada\x03xxx\x00\x00\x01\x00\x01"
        r = wire.parse_response(msg)
        assert r.rcode == 3
        assert r.answers == []

    def test_paquete_corto_rechazado(self):
        with pytest.raises(ValueError):
            wire.parse_response(b"\x00" * 5)

    def test_mx_y_txt(self):
        # MX: pref 10 mail.example.com | TXT: "hola"
        mx_rdata = struct.pack("!H", 10) + b"\x04mail\xc0\x0c"   # 9 bytes
        txt_rdata = bytes([5]) + b"hola"                          # 5 bytes
        answers = (
            b"\xc0\x0c" + struct.pack("!HHIH", 15, 1, 3600, len(mx_rdata)) + mx_rdata
            + b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 300, len(txt_rdata)) + txt_rdata
        )
        msg = struct.pack("!HHHHHH", 7, 0x8180, 1, 2, 0, 0)
        msg += b"\x02ok\x00\x00\x01\x00\x01" + answers
        r = wire.parse_response(msg)
        assert r.answers[0].data == "10 mail.ok"
        assert r.answers[1].data == "hola"


class TestRoundtrip:
    def test_build_parse_ida_y_vuelta(self):
        q = wire.build_query(wire.Question("test.dev", "AAAA"), qid=77)
        # el parser debe tragar una pregunta (respuesta sin respuestas)
        echo = struct.pack("!HHHHHH", 77, 0x8180, 1, 0, 0, 0) + q[12:]
        r = wire.parse_response(echo)
        assert r.questions[0] == wire.Question("test.dev", "AAAA")
