"""Command line entry point (standard library only).

Examples
--------
python -m forensic.cli analyze --journal data/demo.jsonl --queries data/queries.json \
    --watermark 6 --late-from 7 --report artifacts/report.json
python -m forensic.cli generate --kind small --outdir data
python -m forensic.cli generate --kind large --outdir artifacts
python -m forensic.cli verify --report artifacts/report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .generator import large_journal, small_fixtures
from .journal import build_report, verify_report_hash, write_report
from .model import load_records


def _load_queries(path: str | None) -> list[dict]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("queries file must contain a JSON list")
    return data


def _write_jsonl(path: str, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            fh.write("\n")


def cmd_analyze(args: argparse.Namespace) -> int:
    records = load_records(args.journal)
    queries = _load_queries(args.queries)
    report = build_report(
        records,
        queries,
        watermark=args.watermark,
        late_from_seq=args.late_from,
        include_per_edge=not args.no_per_edge,
    )
    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        write_report(report, args.report)
    print(json.dumps(_summary(report), ensure_ascii=False, indent=2))
    if report["engine_consistency"]["distances_equal"] is False:
        print("ERROR: full vs incremental distance mismatch", file=sys.stderr)
        return 2
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    os.makedirs(args.outdir, exist_ok=True)
    if args.kind == "small":
        for name, fixture in small_fixtures().items():
            _write_jsonl(os.path.join(args.outdir, f"{name}.jsonl"), fixture["records"])
            with open(
                os.path.join(args.outdir, f"{name}.queries.json"),
                "w", encoding="utf-8", newline="\n",
            ) as fh:
                json.dump(fixture["queries"], fh, ensure_ascii=False, indent=2)
        print(f"wrote small fixtures to {args.outdir}")
    else:
        records, queries = large_journal()
        jpath = os.path.join(args.outdir, "large.jsonl")
        qpath = os.path.join(args.outdir, "large.queries.json")
        _write_jsonl(jpath, records)
        with open(qpath, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(queries, fh, ensure_ascii=False, indent=2)
        print(f"wrote {len(records)} records and {len(queries)} queries to {args.outdir}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    with open(args.report, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    ok = verify_report_hash(report)
    print(json.dumps({"report": args.report, "hash_valid": ok}, ensure_ascii=False))
    return 0 if ok else 3


def _summary(report: dict) -> dict:
    summary = {
        "watermark": report["watermark"],
        "feasible": report["feasible"],
        "nodes": report["nodes"],
        "edges": report["edges"],
        "engine_consistency": report["engine_consistency"],
        "late_evidence": report["late_evidence"],
    }
    if report["feasible"]:
        summary["queries"] = [
            {
                "pair": f"{q['a']} -> {q['b']}",
                "connected": q["connected"],
                "lower": q.get("lower"),
                "upper": q.get("upper"),
                "verdict": q.get("verdict"),
                "label": q.get("label"),
            }
            for q in report["queries"]
        ]
    else:
        summary["conflicts"] = [
            {
                "length_edges": c["length_edges"],
                "total_weight": c["total_weight"],
                "exact_shortest": c["exact_shortest"],
                "nodes": c["nodes"],
            }
            for c in report["conflicts"]
        ]
    summary["report_sha256"] = report["report_sha256"]
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic",
        description="Offline integer difference-constraint evidence verifier.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_an = sub.add_parser("analyze", help="verify a journal and emit a report")
    p_an.add_argument("--journal", required=True)
    p_an.add_argument("--queries")
    p_an.add_argument("--watermark", type=int, default=None,
                      help="sealed ledger prefix length to replay")
    p_an.add_argument("--late-from", type=int, default=None,
                      help="1-based sequence from which records are late evidence")
    p_an.add_argument("--no-per-edge", action="store_true",
                      help="omit the verbose per-edge incremental trace")
    p_an.add_argument("--report")
    p_an.set_defaults(func=cmd_analyze)

    p_gen = sub.add_parser("generate", help="write deterministic synthetic data")
    p_gen.add_argument("--kind", choices=["small", "large"], default="small")
    p_gen.add_argument("--outdir", required=True)
    p_gen.set_defaults(func=cmd_generate)

    p_vf = sub.add_parser("verify", help="check a report's embedded sha256")
    p_vf.add_argument("--report", required=True)
    p_vf.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < (3, 12):
        print("Python 3.12 or newer is required.", file=sys.stderr)
        return 4
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
