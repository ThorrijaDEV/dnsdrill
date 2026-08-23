"""Codec DNS binario: construcción y parseo de paquetes RFC 1035.

Solo struct + os.urandom — el objetivo educativo es ver el cable.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
CLASS_IN = 1

MAX_UDP = 512


@dataclass
class Question:
    name: str
    qtype: str = "A"


@dataclass
class RR:
    name: str
    rtype: int
    ttl: int
    data: str


@dataclass
class Response:
    id: int
    flags: int
    questions: list[Question] = field(default_factory=list)
    answers: list[RR] = field(default_factory=list)

    @property
    def rcode(self) -> int:
        return self.flags & 0xF

    @property
    def tc(self) -> bool:
        """Truncated: reintentar por TCP."""
        return bool(self.flags & 0x0200)


RCODE_TEXT = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}


def encode_name(name: str) -> bytes:
    out = b""
    if name in ("", "."):
        return b"\x00"
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if not label.isascii() else label.encode()
        if not 0 < len(raw) < 64:
            raise ValueError(f"etiqueta inválida: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(msg: bytes, off: int) -> tuple[str, int]:
    """Devuelve (nombre, offset_del_siguiente_campo). Sigue punteros 0xC0."""
    labels, cur, orig, jumped = [], off, off, False
    while True:
        length = msg[cur]
        if length & 0xC0 == 0xC0:  # puntero de compresión
            ptr = struct.unpack("!H", msg[cur:cur + 2])[0] & 0x3FFF
            if not jumped:
                orig = cur + 2  # tras los 2 bytes del puntero sigue el resto
            cur = ptr
            jumped = True
            continue
        cur += 1
        if length == 0:
            break
        labels.append(msg[cur:cur + length].decode("ascii", "replace"))
        cur += length
    return ".".join(labels), (orig if jumped else cur)


def build_query(q: Question, qid: int | None = None) -> bytes:
    qid = qid if qid is not None else int.from_bytes(os.urandom(2), "big")
    flags = 0x0100  # RD
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    qtype = TYPES[q.qtype.upper()]
    return header + encode_name(q.name) + struct.pack("!HH", qtype, CLASS_IN)


def _rr_data(msg: bytes, rtype: int, abs_off: int, rdlen: int) -> str:
    """Decodifica RDATA usando el mensaje completo (los nombres pueden
    llevar punteros de compresión que apuntan fuera de la propia RR)."""
    if rtype == TYPES["A"] and rdlen == 4:
        return ".".join(str(b) for b in msg[abs_off:abs_off + 4])
    if rtype == TYPES["AAAA"] and rdlen == 16:
        groups = [int.from_bytes(msg[abs_off+i:abs_off+i+2], "big")
                  for i in range(0, 16, 2)]
        return ":".join(f"{g:x}" for g in groups)
    if rtype == TYPES["MX"] and rdlen >= 3:
        pref = struct.unpack("!H", msg[abs_off:abs_off + 2])[0]
        host, _ = decode_name(msg, abs_off + 2)
        return f"{pref} {host}"
    if rtype == TYPES["TXT"]:
        chunks, i = [], abs_off
        end = abs_off + rdlen
        while i < end:
            n = msg[i]
            chunks.append(msg[i+1:i+1+n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(chunks)
    if rtype == TYPES["SOA"] and rdlen > 20:
        mname, o = decode_name(msg, abs_off)
        rname, o = decode_name(msg, o)
        nums = struct.unpack("!IIIII", msg[o:o+20])
        return f"{mname} {rname} " + " ".join(map(str, nums))
    if rtype in (TYPES["NS"], TYPES["CNAME"], TYPES["PTR"]):
        name, _ = decode_name(msg, abs_off)
        return name
    return "0x" + bytes(msg[abs_off:abs_off + rdlen]).hex()


def parse_response(msg: bytes) -> Response:
    if len(msg) < 12:
        raise ValueError("paquete demasiado corto")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    resp = Response(id=qid, flags=flags)
    off = 12
    for _ in range(qd):
        name, off = decode_name(msg, off)
        qtype, qclass = struct.unpack("!HH", msg[off:off+4])
        resp.questions.append(Question(name=name, qtype=TYPE_NAMES.get(qtype, str(qtype))))
        off += 4
    total_rr = an + ns + ar
    for i in range(total_rr):
        name, off = decode_name(msg, off)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off+10])
        off += 10
        if i < an:
            resp.answers.append(RR(name=name, rtype=rtype, ttl=ttl,
                                   data=_rr_data(msg, rtype, off, rdlen)))
        off += rdlen
    return resp
