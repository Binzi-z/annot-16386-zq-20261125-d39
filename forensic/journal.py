"""Append-only journal replay, sealed watermarks and canonical reports.

The ledger and the effective-time model are separate concepts:

* records are ingested in ledger order and every edge remembers the 1-based
  record sequence that introduced it;
* a *watermark* is simply a prefix length - replaying ``records[:w]`` rebuilds
  byte-identical node indices, edge ids and reports, so a run against an old
  sealed watermark reproduces the original report even after late evidence has
  been appended;
* late evidence is tracked per connected component: it cannot change any
  distance in a component it does not touch.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass

from .model import Journal, build_journal
from .solver import (
    IncrementalSolver,
    JohnsonOracle,
    classify_pair,
    extract_conflict_chains,
    pair_bounds,
    spfa_full,
)

CANONICAL_JSON_KWARGS = {
    "ensure_ascii": False,
    "sort_keys": True,
    "separators": (",", ":"),
}


def canonical_bytes(obj: dict | list) -> bytes:
    """Deterministic serialisation used both for the report and its hash."""
    return json.dumps(obj, **CANONICAL_JSON_KWARGS).encode("utf-8")


def replay(
    records: list[dict],
    *,
    watermark: int | None = None,
    late_from_seq: int | None = None,
) -> Journal:
    """Rebuild the model from a ledger prefix.

    ``watermark`` truncates the ledger; ``late_from_seq`` flags late records
    but never alters the graph.
    """
    if watermark is not None:
        records = records[:watermark]
    return build_journal(records, late_from_seq=late_from_seq)


@dataclass
class EngineComparison:
    full_feasible: bool
    incremental_feasible: bool
    distances_equal: bool | None
    predecessors_equal: bool | None
    predecessor_trees_valid: bool | None
    full: dict
    incremental: dict
    per_edge: list[dict]


def predecessor_tree_valid(journal: Journal, dist: list[int],
                           pred: list[int]) -> bool:
    """Verify every chosen predecessor edge is tight and reaches a root.

    A predecessor tree is a valid shortest-path witness when, for each node
    with a predecessor, ``dist[dst] == dist[src] + weight`` and following the
    predecessors terminates (no cycle). This is the correct cross-engine check
    because equal-length shortest paths may legitimately pick different
    predecessors while sharing identical distances.
    """
    for v, eid in enumerate(pred):
        if eid < 0:
            continue  # root / still at the zero virtual-source distance
        edge = journal.edge_by_id(eid)
        if dist[v] != dist[edge.src] + edge.weight:
            return False
    # acyclicity of the predecessor pointers
    state = [0] * journal.n  # 0 unseen, 1 on-stack, 2 done
    for start in range(journal.n):
        if state[start] or pred[start] < 0:
            continue
        cur = start
        path: list[int] = []
        while cur >= 0 and pred[cur] >= 0 and state[cur] == 0:
            state[cur] = 1
            path.append(cur)
            cur = journal.edge_by_id(pred[cur]).src
        if cur >= 0 and pred[cur] >= 0 and state[cur] == 1:
            return False  # predecessor cycle
        for node in path:
            state[node] = 2
    return True


def run_engines(journal: Journal) -> EngineComparison:
    """Run the full SPFA and the incremental engine on the same graph.

    On a feasible graph the tight distances must match element by element;
    each engine's predecessor tree is independently checked for tightness and
    acyclicity rather than pointer equality, because several shortest paths can
    have the same length. On an infeasible graph both engines stop at a
    negative cycle by design, and their partial distances at the stopping
    instant are not expected to coincide; consistency then means *both*
    report infeasible.
    """
    full = spfa_full(journal)

    inc = IncrementalSolver(journal)
    inc.run_all()

    if full.feasible and inc.feasible:
        dist_equal = full.dist == inc.dist
        # Pointer equality is recorded as informational only.
        pred_equal = full.predecessor == inc.predecessor
        trees_valid = (
            predecessor_tree_valid(journal, full.dist, full.predecessor)
            and predecessor_tree_valid(journal, inc.dist, inc.pred)
        )
    else:
        dist_equal = None
        pred_equal = None
        trees_valid = None
    return EngineComparison(
        full.feasible,
        inc.feasible,
        dist_equal,
        pred_equal,
        trees_valid,
        {
            "relaxations": full.relaxations,
            "node_visits": full.node_visits,
            "edge_scans": full.edge_scans,
            "enqueues": full.enqueues,
        },
        {
            "edges_added": inc.stats.edges_added,
            "propagations": inc.stats.propagations,
            "relaxed_edges": inc.stats.relaxed_edges,
            "node_visits": inc.stats.node_visits,
            "edge_scans": inc.stats.edge_scans,
            "enqueues": inc.stats.enqueues,
        },
        copy.deepcopy(inc.stats.per_edge),
    )


def _witness_dict(oracle: JohnsonOracle, src: int, dst: int, journal: Journal) -> dict:
    return oracle.witness(src, dst).to_dict(journal.names)


def answer_queries(journal: Journal, queries: list[dict]) -> list[dict]:
    """Tight bounds, verdict and reviewable witnesses for each event pair."""
    full = spfa_full(journal)
    oracle = JohnsonOracle(journal, full.dist)
    answers: list[dict] = []
    for q in queries:
        a_name = f"ev:{q['a']}"
        b_name = f"ev:{q['b']}"
        if a_name not in journal.index or b_name not in journal.index:
            raise ValueError(f"query references unknown event: {q}")
        a = journal.index[a_name]
        b = journal.index[b_name]
        connected = journal.connected(a, b)
        entry: dict = {
            "a": q["a"],
            "b": q["b"],
            "connected": connected,
        }
        if not connected:
            entry.update(
                {
                    "lower": None,
                    "upper": None,
                    "verdict": "disconnected",
                    "label": "不连通：两个分量之间不存在任何约束路径",
                    "witness_lower": None,
                    "witness_upper": None,
                }
            )
            answers.append(entry)
            continue
        lower, upper = pair_bounds(oracle, a, b)
        verdict = classify_pair(lower, upper)
        entry.update(
            {
                "lower": lower,
                "upper": upper,
                **verdict,
                "witness_upper": _witness_dict(oracle, a, b, journal),
                "witness_lower": _witness_dict(oracle, b, a, journal),
            }
        )
        answers.append(entry)
    return answers


def conflict_report(journal: Journal) -> list[dict]:
    chains = extract_conflict_chains(journal)
    out: list[dict] = []
    for idx, chain in enumerate(chains):
        out.append(
            {
                "chain_index": idx,
                "length_edges": len(chain.edges),
                "total_weight": chain.total_weight,
                "nodes": [journal.names[i] for i in chain.nodes],
                "steps": [e.as_chain_step(journal.names) for e in chain.edges],
                "exact_shortest": not chain.fallback,
            }
        )
    return out


def late_component_stats(journal: Journal) -> dict:
    """Which components late evidence actually reached, and how often."""
    touched: dict[int, dict] = {}
    for rec in journal.records:
        if not rec.late:
            continue
        nodes = _record_nodes(journal, rec.data)
        roots = sorted({journal.component_id(v) for v in nodes})
        for root in roots:
            item = touched.setdefault(
                root,
                {"component_root": journal.names[root], "records": 0, "edges": 0},
            )
            item["records"] += 1
        late_edges = [
            e for e in journal.edges if e.record == rec.seq
        ]
        for e in late_edges:
            root = journal.component_id(e.src)
            item = touched.setdefault(
                root,
                {"component_root": journal.names[root], "records": 0, "edges": 0},
            )
            item["edges"] += 1
    return {
        "late_records": sum(1 for r in journal.records if r.late),
        "components": [touched[k] for k in sorted(touched)],
    }


def _record_nodes(journal: Journal, rec: dict) -> list[int]:
    rtype = rec["type"]
    nodes: list[int] = []
    if rtype == "device":
        name = f"off:{rec['device']}"
        if name in journal.index:
            nodes.append(journal.index[name])
    elif rtype in ("event",):
        name = f"ev:{rec['event']}"
        if name in journal.index:
            nodes.append(journal.index[name])
    elif rtype in ("causal", "manual"):
        for key in ("src_event", "dst_event"):
            name = f"ev:{rec[key]}"
            if name in journal.index:
                nodes.append(journal.index[name])
    return nodes


def build_report(
    records: list[dict],
    queries: list[dict],
    *,
    watermark: int | None = None,
    late_from_seq: int | None = None,
    include_per_edge: bool = True,
) -> dict:
    """Assemble the full canonical report for one sealed run.

    ``include_per_edge`` toggles the verbose per-edge incremental trace; very
    large journals normally keep only the aggregate access counters.
    """
    journal = replay(
        records, watermark=watermark, late_from_seq=late_from_seq
    )
    engines = run_engines(journal)
    report: dict = {
        "schema": "forensic-clock-report/1",
        "watermark": watermark if watermark is not None else len(records),
        "ledger_records": len(journal.records),
        "nodes": journal.n,
        "edges": len(journal.edges),
        "events": len(journal.events),
        "devices": len(journal.devices),
        "feasible": engines.full_feasible,
        "engine_consistency": {
            "full_feasible": engines.full_feasible,
            "incremental_feasible": engines.incremental_feasible,
            "distances_equal": engines.distances_equal,
            "predecessors_equal": engines.predecessors_equal,
            "predecessor_trees_valid": engines.predecessor_trees_valid,
        },
        "full_stats": engines.full,
        "incremental_stats": engines.incremental,
        "incremental_per_edge": engines.per_edge if include_per_edge else [],
        "late_evidence": late_component_stats(journal),
        "queries": [],
        "conflicts": [],
    }
    if engines.full_feasible:
        report["queries"] = answer_queries(journal, queries)
    else:
        report["conflicts"] = conflict_report(journal)
    report["report_sha256"] = hashlib.sha256(canonical_bytes(report)).hexdigest()
    return report


def write_report(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        fh.write("\n")


def verify_report_hash(report: dict) -> bool:
    """Recompute the canonical hash embedded in a report."""
    stored = report.get("report_sha256")
    if not stored:
        return False
    clone = dict(report)
    clone.pop("report_sha256")
    return hashlib.sha256(canonical_bytes(clone)).hexdigest() == stored
