"""Resolución UDP con fallback TCP + CLI estilo dig."""

from __future__ import annotations

import argparse
import json
import socket
import sys

from . import wire


def resolve(name: str, qtype: str = "A", server: str = "1.1.1.1",
            timeout: float = 3.0) -> wire.Response:
    """Consulta DNS por UDP; si la respuesta viene truncada (TC), TCP."""
    query = wire.build_query(wire.Question(name, qtype))
    resp = _udp(query, server, timeout)
    if resp.tc:
        resp = _tcp(query, server, timeout)
    return resp


def _udp(query: bytes, server: str, timeout: float) -> wire.Response:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(query, (server, 53))
        data, _ = s.recvfrom(4096)
    return wire.parse_response(data)


def _tcp(query: bytes, server: str, timeout: float) -> wire.Response:
    with socket.create_connection((server, 53), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(len(query).to_bytes(2, "big") + query)
        ln = int.from_bytes(_recv_exact(s, 2), "big")
        return wire.parse_response(_recv_exact(s, ln))


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("TCP cortado a mitad de mensaje")
        buf += chunk
    return buf


def format_text(resp: wire.Response) -> str:
    head = f"; <<<< dnsdrill >>> {resp.questions[0].name} IN {resp.questions[0].qtype}" \
        if resp.questions else "; respuesta vacía"
    status = wire.RCODE_TEXT.get(resp.rcode, f"RCODE{resp.rcode}")
    lines = [head, f"; estado: {status}, respuestas: {len(resp.answers)}"]
    for a in resp.answers:
        tname = wire.TYPE_NAMES.get(a.rtype, str(a.rtype))
        lines.append(f"{a.name:<32} {a.ttl:>7}  IN {tname:<6} {a.data}")
    return "\n".join(lines)


def to_json(resp: wire.Response) -> dict:
    status = wire.RCODE_TEXT.get(resp.rcode, f"RCODE{resp.rcode}")
    return {
        "status": status,
        "answers": [
            {"name": a.name, "type": wire.TYPE_NAMES.get(a.rtype, str(a.rtype)),
             "ttl": a.ttl, "data": a.data}
            for a in resp.answers
        ],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dnsdrill",
        description="Cliente DNS minimalista que construye los paquetes a mano.")
    ap.add_argument("name", help="dominio a consultar")
    ap.add_argument("qtype", nargs="?", default="A",
                    choices=list(wire.TYPES), help="tipo de registro (default A)")
    ap.add_argument("--server", default="1.1.1.1", help="resolver (default 1.1.1.1)")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--json", action="store_true", help="salida JSON")
    args = ap.parse_args(argv)

    try:
        resp = resolve(args.name, args.qtype, args.server, args.timeout)
    except (socket.timeout, ConnectionError, OSError) as exc:
        print(f"dnsdrill: sin respuesta de {args.server}: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"dnsdrill: paquete inválido: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(to_json(resp), indent=2) if args.json else format_text(resp))
    return 0 if resp.rcode == 0 and resp.answers else 1


if __name__ == "__main__":
    raise SystemExit(main())
