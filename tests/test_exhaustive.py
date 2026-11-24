"""Exhaustive cross-validation against a brute-force offset enumerator.

The production solvers reason about shortest paths; these tests deliberately
use a completely independent method: enumerate *every* integer offset
assignment inside the declared (small) ranges and check every constraint
directly. Tight bounds and ordering verdicts from the two approaches must
agree exactly. Coverage explicitly includes:

* clocks that move backwards (rollback timestamps),
* equality attainable at a boundary,
* genuinely disconnected components (unanchored devices),
* contradictory journals and their shortest negative cycles,
* random fuzzing of small constraint graphs.

Run:  python tests/test_exhaustive.py
"""

from __future__ import annotations

import itertools
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensic.generator import small_fixtures  # noqa: E402
from forensic.journal import build_report, replay, run_engines  # noqa: E402
from forensic.model import build_journal  # noqa: E402
from forensic.solver import (  # noqa: E402
    classify_pair,
    extract_conflict_chains,
    pair_bounds,
    spfa_full,
    JohnsonOracle,
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


# ---------------------------------------------------------------------- #
# independent brute-force reference
# ---------------------------------------------------------------------- #


class BruteForce:
    """Enumerates offset-segment assignments and checks constraints directly.

    Devices with a fixed offset have one variable; every clock_adjust adds
    another segment variable. Each variable is enumerated over a bounded
    integer window derived from the declared ranges, and the adjust bounds are
    checked as ordinary constraints.
    """

    WINDOW = 4  # half-width used for unanchored (floating) root variables

    def __init__(self, records: list[dict]):
        self.records = records
        self.devices: dict[str, dict] = {}
        self.events: dict[str, dict] = {}
        self.order: list[str] = []
        self.causal: list[dict] = []
        self.lag: dict[str, int] = {}
        # variable name -> (lo, hi, anchored); one entry per offset segment
        self.variables: dict[str, tuple[int, int, bool]] = {}
        self.adjusts: list[dict] = []
        segment_counter: dict[str, int] = {}
        for rec in records:
            rtype = rec["type"]
            if rtype == "device":
                anchored = rec.get("anchored", True)
                self.devices[rec["device"]] = {
                    "lo": rec.get("offset_min", 0),
                    "hi": rec.get("offset_max", 0),
                    "anchored": anchored,
                }
                segment_counter[rec["device"]] = 0
                name = f"off:{rec['device']}"
                if anchored:
                    self.variables[name] = (
                        rec.get("offset_min", 0),
                        rec.get("offset_max", 0),
                        True,
                    )
                else:
                    self.variables[name] = (-self.WINDOW, self.WINDOW, False)
            elif rtype == "clock_adjust":
                device = rec["device"]
                k = segment_counter[device] + 1
                segment_counter[device] = k
                old_name = (f"off:{device}" if k == 1
                            else f"off:{device}#{k - 1}")
                name = f"off:{device}#{k}"
                old_lo, old_hi, anchored = self.variables[old_name]
                # interval propagation: the exact possible range of this
                # segment, so enumeration never truncates the feasible region
                self.variables[name] = (
                    old_lo + rec.get("delta_min", -10**9),
                    old_hi + rec.get("delta_max", 10**9),
                    anchored,
                )
                self.adjusts.append(
                    {
                        "old": old_name,
                        "new": name,
                        "lo": rec.get("delta_min", -10**9),
                        "hi": rec.get("delta_max", 10**9),
                    }
                )
            elif rtype == "event":
                stored = dict(rec)
                stored["segment"] = segment_counter.get(rec["device"], 0)
                self.events[rec["event"]] = stored
                self.order.append(rec["event"])
                if rec.get("booking_lag") is not None:
                    self.lag[rec["event"]] = rec["booking_lag"]
            elif rtype in ("causal", "manual"):
                self.causal.append(rec)
                if rtype == "manual" and rec.get("booking_lag") is not None:
                    self.lag[rec["dst_event"]] = min(
                        self.lag.get(rec["dst_event"], 10**12),
                        rec["booking_lag"],
                    )

    def assignments(self):
        names = list(self.variables)
        choices = [range(self.variables[n][0], self.variables[n][1] + 1)
                   for n in names]
        for values in itertools.product(*choices):
            yield dict(zip(names, values))

    def _var_for_event(self, event: str) -> str:
        rec = self.events[event]
        device = rec["device"]
        seg = rec.get("segment", 0)
        return f"off:{device}" if seg == 0 else f"off:{device}#{seg}"

    def effective(self, offsets: dict[str, int], event: str):
        return self.events[event]["local_ts"] + offsets[self._var_for_event(event)]

    def _adjust_ok(self, offsets: dict[str, int]) -> bool:
        for adj in self.adjusts:
            delta = offsets[adj["new"]] - offsets[adj["old"]]
            if not (adj["lo"] <= delta <= adj["hi"]):
                return False
        return True

    def _causal_ok(self, offsets: dict[str, int]) -> bool:
        for c in self.causal:
            delta = (self.effective(offsets, c["dst_event"])
                     - self.effective(offsets, c["src_event"]))
            if delta < c.get("min_delay", 0):
                return False
            if c.get("max_delay") is not None and delta > c["max_delay"]:
                return False
        return True

    def _booking_ok(self, offsets: dict[str, int]) -> bool:
        # Difference-constraint semantics: choose strictly increasing integer
        # booking positions greedily; each entry with a lag cap must sit within
        # its cap. An entry without a cap only has to follow its predecessor.
        prev_bk = None
        for event in self.order:
            ev = self.effective(offsets, event)
            earliest = ev if prev_bk is None else max(ev, prev_bk + 1)
            if event in self.lag:
                cap = ev + self.lag[event]
                if earliest > cap:
                    return False
                prev_bk = earliest
            else:
                prev_bk = earliest
        return True

    def _valid(self, offsets: dict[str, int]) -> bool:
        return (self._adjust_ok(offsets)
                and self._causal_ok(offsets)
                and self._booking_ok(offsets))

    def feasible(self) -> bool:
        return any(self._valid(o) for o in self.assignments())

    def pair_bounds(self, a: str, b: str) -> tuple[int | None, int | None]:
        lows: list[int] = []
        highs: list[int] = []
        for offsets in self.assignments():
            if not self._valid(offsets):
                continue
            delta = self.effective(offsets, b) - self.effective(offsets, a)
            lows.append(delta)
            highs.append(delta)
        if not lows:
            return None, None
        return min(lows), max(highs)


# ---------------------------------------------------------------------- #
# helpers
# ---------------------------------------------------------------------- #


def solver_bounds(records: list[dict], a: str, b: str):
    journal = build_journal(records)
    result = spfa_full(journal)
    assert result.feasible, "fixture expected feasible"
    oracle = JohnsonOracle(journal, result.dist)
    ia = journal.index[f"ev:{a}"]
    ib = journal.index[f"ev:{b}"]
    return journal, oracle, pair_bounds(oracle, ia, ib)


def assert_pair_matches(records: list[dict], a: str, b: str) -> None:
    brute = BruteForce(records)
    b_lo, b_hi = brute.pair_bounds(a, b)
    journal, oracle, (s_lo, s_hi) = solver_bounds(records, a, b)
    check((b_lo, b_hi) == (s_lo, s_hi),
          f"bounds mismatch {a},{b}: brute=({b_lo},{b_hi}) solver=({s_lo},{s_hi})")
    if b_lo is not None:
        verdict = classify_pair(s_lo, s_hi)
        neg_possible = b_lo < 0
        pos_possible = b_hi > 0
        equal = b_lo <= 0 <= b_hi
        check(verdict["strictly_before_possible"] == neg_possible,
              "strictly-before possibility mismatch")
        check(verdict["strictly_after_possible"] == pos_possible,
              "strictly-after possibility mismatch")
        check(verdict["equal_possible"] == equal, "equal_possible mismatch")
        # witnesses must reproduce the bound numerically and be real paths
        for src_name, dst_name, bound in (
            (f"ev:{a}", f"ev:{b}", s_hi),
            (f"ev:{b}", f"ev:{a}", -s_lo),
        ):
            w = oracle.witness(journal.index[src_name], journal.index[dst_name])
            check(w.bound == bound, "witness bound mismatch")
            check(sum(e.weight for e in w.edges) == bound, "witness sum check")
            cur = journal.index[src_name]
            for e in w.edges:
                check(e.src == cur, "witness chain not contiguous")
                cur = e.dst
            check(cur == journal.index[dst_name], "witness chain ends wrong")


# ---------------------------------------------------------------------- #
# 1. hand-built edge-case fixtures
# ---------------------------------------------------------------------- #


def test_named_fixtures() -> None:
    fixtures = small_fixtures()
    expected_verdict = {
        "equality": "possible_both_orders",
        "exact_equality": "necessary_equal",
        "necessary_before": "necessary_a_before",
        "manual_backfill": None,  # checked via brute-force bounds only
        "rollback": None,
    }
    for name, fx in fixtures.items():
        brute = BruteForce(fx["records"])
        report = build_report(fx["records"], fx["queries"])
        consistency = report["engine_consistency"]
        if report["feasible"]:
            check(consistency["distances_equal"] is True,
                  f"{name}: full/incremental distance divergence")
            check(consistency["predecessor_trees_valid"] is True,
                  f"{name}: a predecessor tree is not tight/acyclic")
        else:
            check(consistency["full_feasible"] is False
                  and consistency["incremental_feasible"] is False,
                  f"{name}: engines must agree on infeasibility")
        check(brute.feasible() == report["feasible"],
              f"{name}: feasibility disagrees with brute force")
        if name == "contradiction":
            check(not report["feasible"], "contradiction must be infeasible")
            chains = extract_conflict_chains(build_journal(fx["records"]))
            check(len(chains) >= 1, "contradiction must yield a conflict chain")
            for chain in chains:
                check(chain.total_weight < 0, "conflict chain must be negative")
                check(not chain.fallback, "tiny SCC must enumerate exactly")
                # chain contiguity
                cur = chain.edges[0].src
                for e in chain.edges:
                    check(e.src == cur, "conflict chain not contiguous")
                    cur = e.dst
                check(cur == chain.edges[0].src, "conflict chain not closed")
            # the fixture's contradiction is a 2-edge cycle: must be shortest
            check(chains[0].edges and len(chains[0].edges) == 2,
                  "shortest contradiction should use two edges")
            continue
        for q in fx["queries"]:
            if name == "disconnected":
                entry = next(x for x in report["queries"]
                             if x["a"] == q["a"] and x["b"] == q["b"])
                check(entry["verdict"] == "disconnected",
                      "unanchored island must be disconnected")
                journal = build_journal(fx["records"])
                check(not journal.connected(journal.index[f"ev:{q['a']}"],
                                            journal.index[f"ev:{q['b']}"]),
                      "DSU must report the two islands as disconnected")
                check(brute.feasible(), "floating island is still feasible")
            else:
                assert_pair_matches(fx["records"], q["a"], q["b"])
        if expected_verdict.get(name) is not None:
            entry = report["queries"][0]
            check(entry["verdict"] == expected_verdict[name],
                  f"{name}: expected {expected_verdict[name]}, "
                  f"got {entry['verdict']}")
            if name == "exact_equality":
                check(entry["lower"] == 0 and entry["upper"] == 0,
                      "exact equality must pin both bounds to 0")
            if name == "necessary_before":
                check(entry["lower"] >= 2 and entry["lower"] > 0,
                      "necessary-before must have a strictly positive lower")
    print("ok - named fixtures (rollback, equality, exact equality, "
          "necessary order, disconnected, conflict, manual)")


# ---------------------------------------------------------------------- #
# 2. exhaustive small random graphs vs brute force
# ---------------------------------------------------------------------- #


def random_journal(rng: random.Random) -> tuple[list[dict], list[tuple[str, str]]]:
    device_count = rng.randint(2, 3)
    span = rng.randint(1, 2)
    records: list[dict] = []
    devices = [f"d{i}" for i in range(device_count)]
    for d in devices:
        lo = rng.randint(-span, 0)
        records.append({"type": "device", "device": d,
                        "offset_min": lo, "offset_max": lo + rng.randint(0, span * 2)})
    events: list[str] = []
    for d in devices:
        count = rng.randint(2, 3)
        ts = rng.randint(0, 6)
        for i in range(count):
            # ~1/4 of devices get a bounded clock adjustment (rollback test);
            # delta stays inside the brute-force enumeration window.
            if i == 1 and rng.random() < 0.25:
                jump = rng.randint(-3, 3)
                records.append(
                    {"type": "clock_adjust", "device": d,
                     "delta_min": jump - 1, "delta_max": jump + 1}
                )
            event = f"{d}_e{i}"
            if i and rng.random() < 0.34:
                ts -= rng.randint(1, 3)  # backwards local stamp
            else:
                ts += rng.randint(0, 4)
            rec = {"type": "event", "event": event, "device": d, "local_ts": ts}
            if rng.random() < 0.6:
                rec["booking_lag"] = rng.randint(2, 8)
            records.append(rec)
            events.append(event)
    pairs = list(itertools.combinations(events, 2))
    rng.shuffle(pairs)
    for a, b in pairs[: rng.randint(0, min(4, len(pairs)))]:
        rec = {"type": "causal", "src_event": a, "dst_event": b,
               "min_delay": rng.choice([-2, -1, 0, 0, 1]),
               "max_delay": rng.choice([None, 3, 5, 8])}
        if rec["max_delay"] is None:
            rec.pop("max_delay")
        if rec["min_delay"] <= (rec.get("max_delay") or 10**9):
            records.append(rec)
    queries = list(itertools.combinations(events, 2))
    return records, queries


def test_random_exhaustive() -> None:
    rng = random.Random(424242)
    feasible_cases = 0
    contradiction_cases = 0
    for case in range(300):
        records, queries = random_journal(rng)
        brute = BruteForce(records)
        journal = build_journal(records)
        result = spfa_full(journal)
        check(brute.feasible() == result.feasible,
              f"fuzz case {case}: feasibility mismatch")
        engines = run_engines(journal)
        if result.feasible:
            check(engines.distances_equal is True,
                  f"fuzz case {case}: distance divergence")
            check(engines.predecessor_trees_valid is True,
                  f"fuzz case {case}: invalid predecessor tree")
        else:
            check(engines.full_feasible is False
                  and engines.incremental_feasible is False,
                  f"fuzz case {case}: infeasibility disagreement")
        if not result.feasible:
            contradiction_cases += 1
            chains = extract_conflict_chains(journal)
            check(chains and all(c.total_weight < 0 for c in chains),
                  f"fuzz case {case}: bad conflict chains")
            continue
        feasible_cases += 1
        oracle = JohnsonOracle(journal, result.dist)
        for a, b in queries:
            b_lo, b_hi = brute.pair_bounds(a, b)
            s_lo, s_hi = pair_bounds(oracle,
                                     journal.index[f"ev:{a}"],
                                     journal.index[f"ev:{b}"])
            check((b_lo, b_hi) == (s_lo, s_hi),
                  f"fuzz case {case} pair {a},{b}: ({b_lo},{b_hi}) vs ({s_lo},{s_hi})")
    check(feasible_cases > 200, "too few feasible fuzz cases")
    check(contradiction_cases > 0, "fuzz never produced a contradiction")
    print(f"ok - 300 random journals exhaustively checked "
          f"({feasible_cases} feasible, {contradiction_cases} contradictory)")


# ---------------------------------------------------------------------- #
# 3. disconnected random cases with unanchored devices
# ---------------------------------------------------------------------- #


def test_disconnected_exhaustive() -> None:
    rng = random.Random(9090)
    for case in range(40):
        records = [
            {"type": "device", "device": "A", "offset_min": -2, "offset_max": 2},
            {"type": "device", "device": "B", "anchored": False},
        ]
        records.append({"type": "event", "event": "a0", "device": "A",
                        "local_ts": rng.randint(0, 10)})
        records.append({"type": "event", "event": "b0", "device": "B",
                        "local_ts": rng.randint(0, 10)})
        journal = build_journal(records)
        check(not journal.connected(journal.index["ev:a0"],
                                    journal.index["ev:b0"]),
              "islands must be disconnected")
        result = spfa_full(journal)
        check(result.feasible, "disconnected islands are still feasible")
        report = build_report(records, [{"a": "a0", "b": "b0"}])
        check(report["queries"][0]["verdict"] == "disconnected",
              "query across islands must report disconnected")
    print("ok - 40 disconnected (unanchored) journals")


# ---------------------------------------------------------------------- #
# 4. watermark prefix replay stability on the small fixtures
# ---------------------------------------------------------------------- #


def test_prefix_replay() -> None:
    for name, fx in small_fixtures().items():
        records = fx["records"]
        for w in range(1, len(records) + 1):
            j1 = replay(records, watermark=w)
            j2 = build_journal(records[:w])
            check(j1.names == j2.names and len(j1.edges) == len(j2.edges),
                  f"{name}@{w}: prefix replay diverged")
            check([e.kind for e in j1.edges] == [e.kind for e in j2.edges],
                  f"{name}@{w}: edge order diverged")
    print("ok - watermark prefix replay is graph-identical")


def main() -> int:
    test_named_fixtures()
    test_random_exhaustive()
    test_disconnected_exhaustive()
    test_prefix_replay()
    print(f"\nALL EXHAUSTIVE TESTS PASSED ({PASS} assertions, 0 failures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
