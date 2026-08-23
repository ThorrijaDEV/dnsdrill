# dnsdrill

Cliente DNS minimalista que **construye y parsea los paquetes RFC 1035 a mano** con `struct` — sin dnspython ni ninguna dependencia. Estilo dig, salida clara o JSON.

```
$ dnsdrill ejemplo.es MX
; <<<< dnsdrill >>> ejemplo.es IN MX
; estado: NOERROR, respuestas: 1
ejemplo.es                          3600  IN MX      10 correo.ejemplo.es
```

## Por qué

`dig` es una caja negra perfecta. `dnsdrill` es la caja transparente: ~200 líneas donde se VEN los headers de 12 bytes, las etiquetas length-prefixed, los punteros de compresión `0xC00C`, el bit TC que fuerza el fallback TCP. Para aprender DNS de verdad o depurar resolutores raros.

## Uso

```bash
pip install dnsdrill
dnsdrill ejemplo.es                 # A (default)
dnsdrill ejemplo.es MX
dnsdrill ejemplo.es TXT --server 9.9.9.9
dnsdrill ejemplo.es AAAA --json     # para pipelines
```

Exit codes: `0` respuesta con registros · `1` NOERROR sin respuestas / NXDOMAIN · `2` error de red.

## Qué implementa

| Pieza | Detalle |
|---|---|
| Codificación | header 12 bytes, QDCOUNT=1, flags RD, nombres length-prefixed con validación de etiquetas |
| Decodificación | nombres con punteros de compresión (offset correcto tras saltos) |
| Tipos | A, AAAA, CNAME, NS, PTR, MX (con preferencia), TXT (chunks), SOA |
| Transporte | UDP primero; si TC=1, reintenta por TCP con prefijo de longitud de 2 bytes |
| CLI | estilo dig + `--json` + servidores arbitrarios |

## Tests

```bash
pytest   # roundtrips binarios contra paquetes sintéticos: compresión,
         # punteros, NXDOMAIN, MX/TXT multi-answer, TCP truncado simulado
```

## Licencia

[MIT](LICENSE)
