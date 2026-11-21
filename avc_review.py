"""Summarize SELinux AVC denial logs without changing policy."""
import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

RECORD_TYPE = re.compile(r"\btype=(?:AVC|USER_AVC|1400|1107)\b")
DENIAL = re.compile(r"\bavc:\s*denied\s*\{([^}]+)\}")
AUDIT_TIME = re.compile(r"\baudit\((\d{1,12})(?:\.(\d{1,6}))?:\d+\)")
PERMISSION = re.compile(r"[a-zA-Z0-9_]+")
CONTEXT_TYPE = re.compile(r"[^:\s]+:[^:\s]+:([a-zA-Z0-9_]+)(?::[^\s]+)?")


def field(line, name):
    pattern = rf'(?<!\S){name}=(?:"([^"]*)"|([^\s\'"]+))'
    match = re.search(pattern, line)
    return (match[1] or match[2]) if match else None


def context_type(context):
    match = CONTEXT_TYPE.fullmatch(context or "")
    return match[1] if match else None


def summarize(lines):
    groups = {}
    counts = Counter()
    for line in lines:
        if not RECORD_TYPE.search(line) or not (denial := DENIAL.search(line)):
            continue
        source = context_type(field(line, "scontext"))
        target = context_type(field(line, "tcontext"))
        object_class = field(line, "tclass")
        permissions = denial[1].split()
        if not source or not target or not PERMISSION.fullmatch(object_class or "") or not all(
            PERMISSION.fullmatch(permission) for permission in permissions
        ) or not permissions:
            counts["incomplete"] += 1
            continue
        mode = {"0": "enforcing", "1": "permissive"}.get(
            field(line, "permissive"), "unknown"
        )
        key = (source, target, object_class, tuple(sorted(set(permissions))), mode)
        entry = groups.setdefault(key, {"occurrences": 0, "first": None, "last": None})
        entry["occurrences"] += 1
        counts["parsed"] += 1
        if timestamp := AUDIT_TIME.search(line):
            seconds = int(timestamp[1])
            micros = int((timestamp[2] or "").ljust(6, "0"))
            try:
                when = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=micros)
            except (OverflowError, OSError, ValueError):
                continue
            when = when.isoformat(timespec="microseconds")
            entry["first"] = min(entry["first"] or when, when)
            entry["last"] = max(entry["last"] or when, when)
    findings = []
    for key, entry in sorted(groups.items(), key=lambda item: (-item[1]["occurrences"], item[0])):
        source, target, object_class, permissions, mode = key
        findings.append(dict(entry, source=source, target=target, object_class=object_class,
                             permissions=list(permissions), mode=mode))
    return {"parsed": counts["parsed"], "incomplete": counts["incomplete"], "findings": findings}


def aurion_events(report, asset):
    events = []
    for item in report["findings"]:
        if item["last"] is None:
            continue
        description = (
            f'{item["source"]} → {item["target"]} | {item["object_class"]} | '
            f'{", ".join(item["permissions"])} | {item["mode"]} | {item["occurrences"]} registros'
        )
        events.append(dict(data=item["last"], ativo=asset, origem="SELinux AVC", mensagem=description))
    return events


def main(argv=None):
    parser = argparse.ArgumentParser(description="Agrupa registros AVC do SELinux.")
    parser.add_argument("log", help="Caminho do log bruto ou - para ler stdin")
    parser.add_argument("--format", choices=("report", "aurion"), default="report")
    parser.add_argument("--asset", default="Servidor SELinux")
    args = parser.parse_args(argv)
    if not args.asset.strip():
        parser.error("--asset deve conter um nome")
    try:
        if args.log == "-":
            report = summarize(sys.stdin)
        else:
            with Path(args.log).open(encoding="utf-8", errors="replace") as stream:
                report = summarize(stream)
    except OSError as error:
        parser.exit(1, f"Falha ao ler o log: {error}\n")
    result = report
    if args.format == "aurion":
        result = aurion_events(report, args.asset.strip())
        payload = json.dumps(result, ensure_ascii=False, indent=2)
        if len(result) > 1000 or len(payload.encode("utf-8")) + 1 > 1024 * 1024:
            parser.exit(1, "Exportação excede os limites do Aurion. Use um recorte menor do log.\n")
        print(payload)
        omitted = len(report["findings"]) - len(result)
        if omitted:
            print(f"{omitted} grupos sem data válida ficaram fora da linha do tempo.", file=sys.stderr)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
