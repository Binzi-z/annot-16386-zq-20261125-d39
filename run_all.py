"""End-to-end driver: generate data, run both suites and emit demo reports.

Usage:  python run_all.py
Everything is offline and uses only the standard library.
"""

from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from forensic.cli import _write_jsonl  # noqa: E402
from forensic.generator import large_journal, small_fixtures  # noqa: E402
from forensic.journal import build_report, verify_report_hash, write_report  # noqa: E402
from forensic.model import load_records  # noqa: E402

DATA_DIR = os.path.join(ROOT, "data")
ARTIFACT_DIR = os.path.join(ROOT, "artifacts")


def _write_queries(path: str, queries: list[dict]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(queries, fh, ensure_ascii=False, indent=2)


def step(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> int:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    started = time.perf_counter()

    step("1. generate deterministic synthetic journals")
    fixtures = small_fixtures()
    for name, fx in fixtures.items():
        _write_jsonl(os.path.join(DATA_DIR, f"{name}.jsonl"), fx["records"])
        _write_queries(os.path.join(DATA_DIR, f"{name}.queries.json"),
                       fx["queries"])
    records, queries = large_journal()
    _write_jsonl(os.path.join(ARTIFACT_DIR, "large.jsonl"), records)
    _write_queries(os.path.join(ARTIFACT_DIR, "large.queries.json"), queries)
    n_events = sum(1 for r in records if r["type"] == "event")
    print(f"small fixtures: {', '.join(fixtures)}")
    print(f"large journal : {len(records)} records, {n_events} events")

    step("2. small-fixture reports (feasible cases + one contradiction)")
    for name, fx in fixtures.items():
        report = build_report(fx["records"], fx["queries"])
        path = os.path.join(ARTIFACT_DIR, f"report_{name}.json")
        write_report(report, path)
        assert verify_report_hash(report), f"{name}: report hash invalid"
        status = "FEASIBLE" if report["feasible"] else "CONTRADICTION"
        print(f"{name:16s} {status:13s} sha256={report['report_sha256'][:16]}...")

    step("3. sealed watermark rerun with late evidence (rollback fixture)")
    base = fixtures["rollback"]["records"]
    late = [
        {"type": "manual", "src_event": "a1", "dst_event": "b2",
         "min_delay": 1, "max_delay": 30, "booking_lag": 200},
    ]
    sealed = build_report(base, fixtures["rollback"]["queries"],
                          watermark=len(base), late_from_seq=len(base) + 1)
    rerun = build_report(base + late, fixtures["rollback"]["queries"],
                         watermark=len(base), late_from_seq=len(base) + 1)
    assert sealed["report_sha256"] == rerun["report_sha256"]
    print(f"sealed-rerun hash stable: {sealed['report_sha256'][:24]}...")
    full = build_report(base + late, fixtures["rollback"]["queries"],
                        late_from_seq=len(base) + 1)
    write_report(full, os.path.join(ARTIFACT_DIR, "report_rollback_with_late.json"))
    print("late evidence components:",
          json.dumps(full["late_evidence"], ensure_ascii=False))

    step("4. 60k-event full vs incremental consistency")
    large_report = build_report(records, queries, include_per_edge=False)
    write_report(large_report, os.path.join(ARTIFACT_DIR, "report_large.json"))
    assert large_report["feasible"], "large journal unexpectedly infeasible"
    assert large_report["engine_consistency"]["distances_equal"] is True
    assert large_report["engine_consistency"]["predecessor_trees_valid"] is True
    print("full stats       :", json.dumps(large_report["full_stats"]))
    print("incremental stats:", json.dumps(large_report["incremental_stats"]))
    sample = large_report["queries"][0]
    print("sample query     :", sample["a"], "->", sample["b"],
          "bounds", (sample["lower"], sample["upper"]), sample["verdict"])

    step("5. rerun the formal test suites")
    import tests.test_exhaustive as exhaustive
    import tests.test_stress as stress

    exhaustive.main()
    stress.main()

    print(f"\nrun_all finished in {time.perf_counter() - started:.1f}s")
    print(f"artifacts: {ARTIFACT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
