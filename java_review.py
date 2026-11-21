"""Compare already-collected Java runtime metadata with a reviewed build catalog."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ("vendor", "runtime", "arch", "build")
MAX_BYTES = 1024 * 1024


def load_json(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError(f"{path.name}: limite de 1 MiB.")
    data = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(data, list) or len(data) > 1000:
        raise ValueError(f"{path.name}: informe uma lista de até 1.000 registros.")
    return data


def required(row, key):
    value = row.get(key) if isinstance(row, dict) else None
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ValueError(f"Campo obrigatório ou inválido: {key}")
    return value.strip()


def runtime_key(row):
    values = [required(row, name).casefold() for name in FIELDS]
    if values[2] in ("amd64", "x64"):
        values[2] = "x86_64"
    return tuple(values)


def review(assets, catalog):
    approved = {}
    for row in catalog:
        key = runtime_key(row)
        reference = required(row, "reference")
        if key in approved and approved[key] != reference:
            raise ValueError("O catálogo contém referências conflitantes para o mesmo build.")
        approved[key] = reference
    results = []
    for row in assets:
        asset = required(row, "asset")
        key = runtime_key(row)
        matched = approved.get(key)
        results.append({
            "asset": asset, **dict(zip(FIELDS, key)),
            "status": "catalog_match" if matched else "review_required",
            "reference": matched,
        })
    return results


def aurion_events(results):
    date = datetime.now(timezone.utc).isoformat()
    return [
        {
            "data": date, "ativo": item["asset"], "origem": "Revisão de runtimes Java",
            "mensagem": (
                f'{item["vendor"]} | {item["runtime"]} | {item["arch"]} | {item["build"]} | '
                + (f'Build no catálogo: {item["reference"]}' if item["reference"] else 'Revisão necessária')
            ),
        }
        for item in results
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("--format", choices=("report", "aurion"), default="report")
    args = parser.parse_args()
    try:
        results = review(load_json(args.inventory), load_json(args.catalog))
        body = aurion_events(results) if args.format == "aurion" else results
        payload = json.dumps(body, ensure_ascii=False)
        if args.format == "aurion" and len(payload.encode("utf-8")) + 1 > MAX_BYTES:
            raise ValueError("O resultado excede 1 MiB. Reduza o lote para importar no Aurion.")
        print(payload)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
