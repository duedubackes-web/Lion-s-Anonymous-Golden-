"""Create an auditable batch of SELinux reports and Aurion event files."""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, ZipFile

from avc_review import aurion_events, summarize

MAX_EVENTS = 1000
MAX_EVENT_BYTES = 1024 * 1024


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


def review_file(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        def lines():
            nonlocal size
            for line in stream:
                digest.update(line)
                size += len(line)
                yield line.decode("utf-8", errors="replace")

        report = summarize(lines())
    return report, digest.hexdigest(), size


def event_batches(events):
    records = []
    size = 2
    for event in events:
        record = json_bytes(event)
        added = len(record) + bool(records)
        if len(records) >= MAX_EVENTS or size + added > MAX_EVENT_BYTES:
            if records:
                yield b"[" + b",".join(records) + b"]"
            records = []
            size = 2
        if size + len(record) > MAX_EVENT_BYTES:
            raise ValueError("Evento individual excede o limite de importação.")
        size += len(record) + bool(records)
        records.append(record)
    if records:
        yield b"[" + b",".join(records) + b"]"


def write_batch(inputs, output, asset=None):
    entries = []
    temporary_path = None
    try:
        with NamedTemporaryFile(dir=output.parent, prefix=".avc-batch-", delete=False) as temporary:
            temporary_path = Path(temporary.name)
            with ZipFile(temporary, "w", compression=ZIP_DEFLATED) as archive:
                for position, path in enumerate(inputs, 1):
                    entry = {"source": path.name, "position": position}
                    entries.append(entry)
                    try:
                        report, digest, size = review_file(path)
                    except OSError as error:
                        entry.update(status="error", reason=error.strerror)
                        continue
                    label = f"{position:04d}"
                    report_name = f"reports/{label}.json"
                    events = aurion_events(report, asset or path.name)
                    event_files = []
                    for part, payload in enumerate(event_batches(events), 1):
                        name = f"aurion/{label}-{part:03d}.json"
                        archive.writestr(name, payload)
                        event_files.append(name)
                    archive.writestr(report_name, json_bytes(report))
                    entry.update(
                        status="processed", sha256=digest, size=size,
                        parsed=report["parsed"], incomplete=report["incomplete"],
                        groups_without_timestamp=len(report["findings"]) - len(events),
                        report=report_name, events=event_files,
                    )
                archive.writestr("provenance.json", json_bytes({"version": 1, "inputs": entries}))
        # Publish the completed ZIP only if another process has not claimed the name.
        os.link(temporary_path, output)
    finally:
        if temporary_path is not None:
            temporary_path.unlink()
    return sum(entry["status"] == "error" for entry in entries)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Processa registros AVC em lote.")
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path, help="Novo arquivo ZIP")
    parser.add_argument("--asset", help="Nome do ativo para todos os arquivos")
    args = parser.parse_args(argv)
    if args.asset is not None and not 1 <= len(args.asset.strip()) <= 120:
        parser.error("--asset deve conter de 1 a 120 caracteres")
    try:
        failed = write_batch(args.logs, args.output, args.asset.strip() if args.asset else None)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Falha ao criar o lote: {error}\n")
    print(f"Lote salvo em {args.output}. Arquivos com falha: {failed}.", file=sys.stderr)
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
