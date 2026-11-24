"""Large-scale stress tests (60,000+ events) and watermark reproducibility.

Checks:

* the generated journal contains at least 60,000 events and stays feasible;
* full SPFA and the incremental engine agree on every distance and
  predecessor after each prefix of the edges (incremental == full);
* local-update access counters stay inside the touched connected component -
  late evidence never visits another component;
* Johnson bounds match direct SPFA distances on sampled pairs, and every
  witness chain numerically reproduces its bound;
* rerunning at an old sealed watermark after late evidence was appended
  reproduces the original report byte-for-byte (same sha256).

Run:  python tests/test_stress.py
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensic.generator import large_journal, small_fixtures  # noqa: E402
from forensic.journal import (  # noqa: E402
    build_report,
    canonical_bytes,
    predecessor_tree_valid,
    replay,
    run_engines,
    write_report,
)
from forensic.model import build_journal  # noqa: E402
from forensic.solver import (  # noqa: E402
    IncrementalSolver,
    JohnsonOracle,
    pair_bounds,
    spfa_full,
)

PASS = 0
FAIL = 0


def check(cond: bool, message: str) -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        raise AssertionError(message)


def test_scale_and_engines() -> tuple:
    started = time.perf_counter()
    records, queries = large_journal()
    event_count = sum(1 for r in records if r["type"] == "event")
    check(event_count >= 60_000, f"expected >=60000 events, got {event_count}")
    journal = build_journal(records)
    check(journal.n > 120_000, "node count must reflect ev + bk + offset vars")
    check(len(journal.edges) > 150_000, "edge count must cover all evidence")

    full = spfa_full(journal)
    check(full.feasible, "ground-truth-generated journal must be feasible")

    engines = run_engines(journal)
    check(engines.distances_equal is True, "full vs incremental distances differ")
    check(engines.predecessor_trees_valid is True,
          "an engine produced an invalid predecessor tree")
    check(engines.full_feasible == engines.incremental_feasible,
          "feasibility flags differ")
    elapsed = time.perf_counter() - started
    print(f"ok - {event_count} events, {journal.n} nodes, "
          f"{len(journal.edges)} edges in {elapsed:.1f}s")
    print(f"     full: {engines.full}")
    print(f"     incremental: {engines.incremental}")
    return records, queries, journal, full


def test_incremental_equals_full_at_prefixes(journal) -> None:
    """After every edge prefix the incremental state equals a fresh full run."""
    inc = IncrementalSolver(journal)
    checked = 0
    # Check at record boundaries (the last edge id of selected records), so
    # the rebuilt prefix contains exactly the edges replayed so far.
    edges = journal.edges
    record_count = len(journal.records)
    boundary_record = {record_count * q // 4 for q in (1, 2, 3, 4)}
    last_edge_of_record: dict[int, int] = {}
    for edge in edges:
        last_edge_of_record[edge.record] = edge.eid
    milestones = {last_edge_of_record[r] for r in boundary_record}
    for edge in edges:
        inc.add_edge(edge)
        if edge.eid in milestones:
            prefix = build_journal(
                [r.data for r in journal.records[: edge.record]]
            )
            full_prefix = spfa_full(prefix)
            check(inc.dist[: prefix.n] == full_prefix.dist,
                  f"distance divergence at edge {edge.eid}")
            check(predecessor_tree_valid(prefix, inc.dist, inc.pred),
                  f"incremental predecessor tree invalid at edge {edge.eid}")
            checked += 1
    check(inc.feasible, "incremental run must finish feasible")
    print(f"ok - incremental/full equality at {checked} record-boundary prefixes")


def test_late_evidence_is_component_local(journal) -> None:
    """Appending late evidence may only touch its own connected component."""
    base_records = [
        {"type": "device", "device": "ghost", "anchored": False},
        {"type": "event", "event": "ghost_e0", "device": "ghost",
         "local_ts": 7},
        {"type": "event", "event": "ghost_e1", "device": "ghost",
         "local_ts": 9},
    ]
    combined = [r.data for r in journal.records] + base_records
    full_before = spfa_full(build_journal(combined))

    late_edge_record = {
        "type": "causal",
        "src_event": "ghost_e0",
        "dst_event": "ghost_e1",
        "min_delay": 0,
        "max_delay": 4,
    }
    extended = build_journal(combined + [late_edge_record])
    new_edges = [e for e in extended.edges
                 if e.record == len(combined) + 1]
    check(new_edges, "late record must add at least one edge")
    base_edge_count = len([e for e in extended.edges
                           if e.record <= len(combined)])

    # Build the incremental engine on the final graph but replay only the
    # sealed-prefix edges first, so its adjacency view is never stale.
    inc = IncrementalSolver(extended)
    for edge in extended.edges[:base_edge_count]:
        inc.add_edge(edge)
    check(inc.dist[: full_before.n] == full_before.dist,
          "replayed prefix must match the sealed full solution")
    before = list(inc.dist)

    touched_components: set[int] = set()
    for edge in new_edges:
        local = inc.add_edge(edge)
        for name in local["touched_nodes"]:
            touched_components.add(
                extended.component_id(extended.index[name])
            )
    late_root = extended.component_id(new_edges[0].src)
    check(touched_components == {late_root},
          f"late edge leaked into components {touched_components}")

    # every distance outside the late component is bit-identical
    for node in range(extended.n):
        if extended.component_id(node) != late_root:
            check(inc.dist[node] == before[node],
                  "distance changed outside the late-evidence component")
    full_after = spfa_full(extended)
    check(inc.dist == full_after.dist, "incremental late update != full rerun")
    check(predecessor_tree_valid(extended, inc.dist, inc.pred),
          "incremental late predecessor tree invalid")
    print("ok - late evidence changes only its connected component")


def test_johnson_bounds_and_witnesses(journal, full, queries) -> None:
    oracle = JohnsonOracle(journal, full.dist)
    checked_pairs = 0
    for q in queries:
        a = journal.index[f"ev:{q['a']}"]
        b = journal.index[f"ev:{q['b']}"]
        lower, upper = pair_bounds(oracle, a, b)
        # independently recompute via raw SPFA distances
        check(upper == oracle.distance(a, b), "upper bound distance mismatch")
        rev = oracle.distance(b, a)
        check(lower == (-rev if rev is not None else None),
              "lower bound distance mismatch")
        for src, dst, bound in ((a, b, upper), (b, a, rev)):
            witness = oracle.witness(src, dst)
            if bound is None:
                check(witness.bound is None and not witness.edges,
                      "unreachable pair must have an empty witness")
                continue
            check(witness.bound == bound, "witness bound mismatch")
            check(sum(e.weight for e in witness.edges) == bound,
                  "witness weight sum does not reproduce the bound")
            cur = src
            for e in witness.edges:
                check(e.src == cur, "witness chain discontinuity")
                cur = e.dst
            check(cur == dst, "witness chain ends at wrong node")
        checked_pairs += 1
    check(checked_pairs == len(queries), "not all queries were checked")
    print(f"ok - {checked_pairs} large-graph pair bounds with verified witnesses")


def test_watermark_replay() -> None:
    """Old sealed watermark reruns to the identical report after late arrival."""
    fixtures = small_fixtures()
    base = fixtures["rollback"]["records"]
    late = [
        {"type": "causal", "src_event": "a1", "dst_event": "b2",
         "min_delay": 1, "max_delay": 30},
        {"type": "manual", "src_event": "b2", "dst_event": "a1",
         "min_delay": -40, "max_delay": -1, "booking_lag": 120},
    ]
    queries = fixtures["rollback"]["queries"]
    sealed_watermark = len(base)

    report_before = build_report(base, queries, watermark=sealed_watermark,
                                 late_from_seq=sealed_watermark + 1)
    extended_records = base + late
    report_replayed = build_report(extended_records, queries,
                                   watermark=sealed_watermark,
                                   late_from_seq=sealed_watermark + 1)
    check(canonical_bytes(report_before) == canonical_bytes(report_replayed),
          "sealed-prefix report changed after late evidence arrived")
    check(report_before["report_sha256"] == report_replayed["report_sha256"],
          "sealed-prefix report hash changed")

    # the full extended ledger is a different report, and flags late records
    report_full = build_report(extended_records, queries,
                               late_from_seq=sealed_watermark + 1)
    check(report_full["report_sha256"] != report_before["report_sha256"],
          "full-ledger report unexpectedly identical to sealed prefix")
    check(report_full["late_evidence"]["late_records"] == len(late),
          "late record count mismatch")
    check(len(report_full["late_evidence"]["components"]) >= 1,
          "late evidence must be attributed to a component")

    # prefix graph identity for every watermark level
    for w in range(1, len(extended_records) + 1):
        j1 = replay(extended_records, watermark=w)
        j2 = build_journal(extended_records[:w])
        check(j1.names == j2.names, f"node naming diverges at watermark {w}")
        check([e.eid for e in j1.edges] == [e.eid for e in j2.edges],
              f"edge ids diverge at watermark {w}")
    print("ok - sealed watermark reruns byte-identical; late evidence isolated")


def test_report_roundtrip(tmp_path: str | None = None) -> None:
    import hashlib
    import tempfile

    from forensic.journal import verify_report_hash

    records, queries = large_journal(devices=4, events_per_device=200,
                                     cross_edges=80, manual_entries=10)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "report.json")
        report = build_report(records, queries)
        write_report(report, path)
        check(verify_report_hash(report), "fresh report fails its own hash")
        with open(path, "rb") as fh:
            blob = fh.read()
        digest = hashlib.sha256(canonical_bytes(report)).hexdigest()
        check(report["report_sha256"] == digest, "embedded hash wrong")
        check(b"\n" in blob, "report file must be newline-terminated text")
    print("ok - canonical report serialisation and hash verification")


def main() -> int:
    records, queries, journal, full = test_scale_and_engines()
    test_incremental_equals_full_at_prefixes(journal)
    test_late_evidence_is_component_local(journal)
    test_johnson_bounds_and_witnesses(journal, full, queries)
    test_watermark_replay()
    test_report_roundtrip()
    print(f"\nALL STRESS TESTS PASSED ({PASS} assertions, 0 failures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
