#!/usr/bin/env python3
"""Convert a Google Authenticator export QR into N scannable QR codes.

Reads the otpauth-migration payload (from a PNG or the raw URI) and writes:

- accounts/   one otpauth:// QR per account, importable by any authenticator
- migration/  N otpauth-migration:// QR codes (Google's own format), for apps
              that only understand the export format

Requires zbarimg (decode) and qrencode (encode).
"""

import argparse
import base64
import html
import json
import random
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS = {0: 6, 1: 6, 2: 8}
OTP_TYPES = {0: "TOTP", 1: "HOTP", 2: "TOTP"}


@dataclass
class Account:
    raw: bytes
    secret: bytes
    name: str
    issuer: str
    algorithm: int
    digits: int
    otp_type: int
    counter: int | None


@dataclass
class ExportMeta:
    version: int
    batch_size: int
    batch_index: int
    batch_id: int | None


# ---------------------------------------------------------------- protobuf

def read_varint(buf, pos):
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def read_fields(buf):
    pos = 0
    while pos < len(buf):
        key, pos = read_varint(buf, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = read_varint(buf, pos)
        elif wire == 2:
            length, pos = read_varint(buf, pos)
            value = buf[pos:pos + length]
            pos += length
        elif wire == 1:
            value = buf[pos:pos + 8]
            pos += 8
        elif wire == 5:
            value = buf[pos:pos + 4]
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
        yield number, value


def write_varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def write_bytes(number, data):
    return write_varint(number << 3 | 2) + write_varint(len(data)) + data


def write_int(number, value):
    return write_varint(number << 3) + write_varint(value)


# ---------------------------------------------------------------- export

def decode_export(uri):
    if "data=" not in uri:
        raise ValueError("not an otpauth-migration payload")
    encoded = urllib.parse.unquote(uri.split("data=", 1)[1])
    encoded += "=" * (-len(encoded) % 4)
    return base64.b64decode(encoded)


def parse_export(uri):
    accounts = []
    meta = ExportMeta(version=1, batch_size=1, batch_index=0, batch_id=None)
    for number, value in read_fields(decode_export(uri)):
        if number == 1:
            fields = dict(read_fields(value))
            accounts.append(Account(
                raw=value,
                secret=fields.get(1, b""),
                name=fields.get(2, b"").decode(errors="replace").strip(),
                issuer=fields.get(3, b"").decode(errors="replace").strip(),
                algorithm=fields.get(4, 1),
                digits=fields.get(5, 1),
                otp_type=fields.get(6, 2),
                counter=fields.get(7),
            ))
        elif number == 2:
            meta.version = value
        elif number == 3:
            meta.batch_size = value
        elif number == 4:
            meta.batch_index = value
        elif number == 5:
            meta.batch_id = value
    if not accounts:
        raise ValueError("payload contains no accounts")
    return accounts, meta


def read_payloads(inputs):
    payloads = []
    for item in inputs:
        path = Path(item)
        if not path.is_file():
            payloads.append(item)
            continue
        if path.suffix.lower() in {".txt", ".uri", ".md"}:
            text = path.read_text(encoding="utf-8")
            payloads.extend(line.strip() for line in text.splitlines()
                            if line.strip().startswith("otpauth-migration://"))
            continue
        result = subprocess.run(
            ["zbarimg", "--raw", "-q", str(path)],
            capture_output=True, text=True,
        )
        payloads.extend(line.strip() for line in result.stdout.splitlines() if line.strip())
    payloads = [p for p in payloads if p.startswith("otpauth-migration://")]
    if not payloads:
        raise SystemExit("No otpauth-migration QR found in the given input.")
    return payloads


# ---------------------------------------------------------------- output

def otpauth_uri(account):
    label = f"{account.issuer}:{account.name}" if account.issuer else account.name
    params = [("secret", base64.b32encode(account.secret).decode().rstrip("="))]
    if account.issuer:
        params.append(("issuer", account.issuer))
    params.append(("algorithm", ALGORITHMS.get(account.algorithm, "SHA1")))
    params.append(("digits", str(DIGITS.get(account.digits, 6))))
    if account.otp_type == 1:
        params.append(("counter", str(account.counter or 0)))
        scheme = "hotp"
    else:
        params.append(("period", "30"))
        scheme = "totp"
    query = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params)
    return f"otpauth://{scheme}/{urllib.parse.quote(label, safe=':@')}?{query}"


def migration_uri(accounts, meta, batch_size, batch_index, batch_id):
    body = b"".join(write_bytes(1, a.raw) for a in accounts)
    body += write_int(2, meta.version)
    body += write_int(3, batch_size)
    body += write_int(4, batch_index)
    if batch_id is not None:
        body += write_int(5, batch_id)
    encoded = base64.b64encode(body).decode()
    return "otpauth-migration://offline?data=" + urllib.parse.quote(encoded, safe="")


def make_qr(text, path, scale=8, margin=4):
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["qrencode", "-o", str(path), "-s", str(scale), "-m", str(margin), "-l", "M", text],
        check=True,
    )


def slugify(text, fallback):
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (slug or fallback)[:50].rstrip("-")


def chunked(items, count):
    size = -(-len(items) // count)
    return [items[i:i + size] for i in range(0, len(items), size)]


def render_html(accounts, account_files, parts, source):
    rows = []
    for index, (account, path) in enumerate(zip(accounts, account_files), 1):
        title = f"{account.issuer}: {account.name}" if account.issuer else account.name
        rows.append(f"""
      <article class="card">
        <div class="num">{index:02d}</div>
        <img src="{html.escape(str(path))}" alt="{html.escape(title)}">
        <h3>{html.escape(title)}</h3>
        <p>{OTP_TYPES.get(account.otp_type, "TOTP")} · {DIGITS.get(account.digits, 6)} dígitos · {ALGORITHMS.get(account.algorithm, "SHA1")}</p>
      </article>""")

    part_rows = []
    if parts:
        part_rows.append('<h2 class="section">Lotes del export (formato Google Authenticator)</h2><div class="grid">')
        for index, (part_accounts, path) in enumerate(parts, 1):
            names = ", ".join(
                html.escape(f"{a.issuer}: {a.name}" if a.issuer else a.name)
                for a in part_accounts
            )
            part_rows.append(f"""
      <article class="card wide">
        <div class="num">Lote {index:02d}</div>
        <img src="{html.escape(str(path))}" alt="Lote {index}">
        <h3>Parte {index} de {len(parts)}</h3>
        <p>{len(part_accounts)} cuentas: {names}</p>
      </article>""")
        part_rows.append("</div>")

    batch = source
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Cuentas del export de Google Authenticator</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ margin: 0; padding: 2rem; background: #f4f4f2; color: #1b1b1b;
         font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
  .meta {{ color: #555; margin: 0 0 2rem; }}
  .section {{ margin: 2.5rem 0 1rem; font-size: 1.15rem; }}
  .grid {{ display: grid; gap: 1rem;
           grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); }}
  .card {{ position: relative; background: #fff; border: 1px solid #ddd;
           border-radius: 10px; padding: 1rem; text-align: center; }}
  .card.wide {{ grid-column: span 2; }}
  .card img {{ width: 100%; max-width: 320px; image-rendering: pixelated; }}
  .card.wide img {{ max-width: 480px; }}
  .num {{ position: absolute; top: .6rem; left: .8rem; font-size: .75rem;
          letter-spacing: .08em; text-transform: uppercase; color: #888; }}
  h3 {{ font-size: .95rem; margin: .5rem 0 .25rem; word-break: break-word; }}
  p {{ margin: 0; font-size: .8rem; color: #555; word-break: break-word; }}
</style>
</head>
<body>
  <h1>Export de Google Authenticator</h1>
  <p class="meta">{html.escape(batch)} · {len(accounts)} cuentas · un QR por cuenta</p>
  <div class="grid">{''.join(rows)}
  </div>
  {''.join(part_rows)}
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(
        description="Split a Google Authenticator export QR into scannable QR codes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  qrauth.py ~/Downloads/export.png
  qrauth.py ~/Downloads/export.png --chunks 2
  qrauth.py ~/Downloads/export-1.png ~/Downloads/export-2.png -o out --dedupe
""",
    )
    parser.add_argument("inputs", nargs="+", help="QR image(s) or raw otpauth-migration URI")
    parser.add_argument("-o", "--out", default="out", help="output directory (default: out)")
    parser.add_argument("--chunks", type=int, metavar="N",
                        help="also write N otpauth-migration QR codes")
    parser.add_argument("--dedupe", action="store_true", help="drop repeated accounts")
    parser.add_argument("--list", action="store_true", help="only print the accounts")
    args = parser.parse_args()
    if args.chunks is not None and args.chunks < 1:
        parser.error("--chunks must be at least 1")

    payloads = read_payloads(args.inputs)
    accounts = []
    metas = []
    for payload in payloads:
        parsed, meta = parse_export(payload)
        accounts.extend(parsed)
        metas.append(meta)

    batch_size = max(meta.batch_size for meta in metas)
    batch_ids = {meta.batch_id for meta in metas}
    present = sorted(meta.batch_index for meta in metas)

    print(f"Export: versión {metas[0].version}, lote(s) {', '.join(str(i + 1) for i in present)}"
          f" de {batch_size}")
    missing = [i for i in range(batch_size) if i not in present]
    if missing:
        print(f"Aviso: falta el lote {', '.join(str(i + 1) for i in missing)} de {batch_size};"
              " esas cuentas no están en la entrada.", file=sys.stderr)
    if len(batch_ids) > 1:
        print("Aviso: los QR pertenecen a exports distintos (batch_id diferente).", file=sys.stderr)

    deduped = []
    seen = set()
    for account in accounts:
        key = (account.secret, account.issuer, account.name, account.otp_type, account.counter)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(account)
    duplicates = len(accounts) - len(deduped)
    if args.dedupe:
        accounts = deduped

    if args.list:
        print()
        print(f"{'#':>2}  {'Tipo':4}  {'Díg':3}  {'Alg':6}  {'Emisor':22}  Cuenta")
        for index, account in enumerate(accounts, 1):
            print(f"{index:>2}  {OTP_TYPES.get(account.otp_type, '?'):4}  "
                  f"{DIGITS.get(account.digits, '?'):<3}  {ALGORITHMS.get(account.algorithm, '?'):6}  "
                  f"{account.issuer[:22]:22}  {account.name}")
        if duplicates:
            print(f"\n{duplicates} cuentas repetidas (usa --dedupe para omitirlas).")
        return

    out = Path(args.out)
    account_dir = out / "accounts"
    account_files = []
    for index, account in enumerate(accounts, 1):
        title = f"{account.issuer} {account.name}" if account.issuer else account.name
        name = f"{index:02d}-{slugify(title, 'cuenta')}.png"
        path = account_dir / name
        make_qr(otpauth_uri(account), path)
        account_files.append(path)

    parts = []
    if args.chunks:
        count = min(args.chunks, len(accounts))
        if count < args.chunks:
            print(f"Aviso: --chunks {args.chunks} recortado a {count} (hay {len(accounts)} cuentas).",
                  file=sys.stderr)
        batch_id = metas[0].batch_id
        if batch_id is None and count > 1:
            batch_id = random.SystemRandom().randrange(1, 2 ** 31)
        for index, group in enumerate(chunked(accounts, count)):
            path = out / "migration" / f"part-{index + 1:02d}-of-{count:02d}.png"
            make_qr(migration_uri(group, metas[0], count, index, batch_id), path)
            parts.append((group, path))

    (out / "index.html").write_text(
        render_html(accounts, [p.relative_to(out) for p in account_files],
                    [(group, path.relative_to(out)) for group, path in parts],
                    f"lote(s) {', '.join(str(i + 1) for i in present)} de {batch_size}"),
        encoding="utf-8",
    )

    manifest = {
        "export": {
            "version": metas[0].version,
            "batch_size": batch_size,
            "batches_present": [i + 1 for i in present],
        },
        "accounts": [
            {
                "index": index,
                "issuer": account.issuer,
                "name": account.name,
                "secret": base64.b32encode(account.secret).decode().rstrip("="),
                "type": OTP_TYPES.get(account.otp_type, "TOTP"),
                "digits": DIGITS.get(account.digits, 6),
                "algorithm": ALGORITHMS.get(account.algorithm, "SHA1"),
                "otpauth": otpauth_uri(account),
                "qr": str(path.relative_to(out)),
            }
            for index, (account, path) in enumerate(zip(accounts, account_files), 1)
        ],
        "migration": [
            {"part": index, "of": len(parts), "qr": str(path.relative_to(out)), "accounts": len(group)}
            for index, (group, path) in enumerate(parts, 1)
        ],
    }
    (out / "accounts.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                                       encoding="utf-8")

    print(f"\n{len(accounts)} cuentas -> {account_dir}/")
    for path in account_files:
        print(f"  {path}")
    if parts:
        print(f"\n{len(parts)} lotes -> {out / 'migration'}/")
        for _, path in parts:
            print(f"  {path}")
    if duplicates:
        print(f"\n{duplicates} cuentas repetidas (usa --dedupe para omitirlas).")
    print(f"\nÍndice para escanear: {out / 'index.html'}")
    print(f"Datos (incluye secretos): {out / 'accounts.json'}")


if __name__ == "__main__":
    main()
