"""Deterministic synthetic journal generation (local data, no network).

All randomness comes from :class:`random.Random` seeded explicitly, so every
generated fixture is reproducible byte-for-byte. Two builders are exposed:

* :func:`small_fixtures` - hand-designed edge cases (rollback, equality,
  disconnected, contradiction) used by the exhaustive tests;
* :func:`large_journal` - a 60k+ event multi-device journal for stress tests.
"""

from __future__ import annotations

import random


def small_fixtures() -> dict[str, dict]:
    """Return named small journals plus queries and expected annotations."""
    fixtures: dict[str, dict] = {}

    # A. clock rollback: device B's clock moves backwards between its events.
    # The jump is an explicit clock_adjust: the second offset segment may be
    # much larger, so a smaller local timestamp can still mean a later time.
    fixtures["rollback"] = {
        "records": [
            {"type": "device", "device": "A", "offset_min": -3, "offset_max": 3},
            {"type": "device", "device": "B", "offset_min": -3, "offset_max": 3},
            {"type": "event", "event": "a1", "device": "A", "local_ts": 10,
             "booking_lag": 5},
            {"type": "event", "event": "b1", "device": "B", "local_ts": 12,
             "booking_lag": 5},
            # rollback: new offset segment, offset may jump up by 3..12
            {"type": "clock_adjust", "device": "B",
             "delta_min": 3, "delta_max": 12},
            # b2 is stamped earlier than b1 although it happens later
            {"type": "event", "event": "b2", "device": "B", "local_ts": 8,
             "booking_lag": 5},
            # real-world causal assertion restores the true order
            {"type": "causal", "src_event": "b1", "dst_event": "b2",
             "min_delay": 1, "max_delay": 20},
            {"type": "causal", "src_event": "a1", "dst_event": "b1",
             "min_delay": 0, "max_delay": 10},
        ],
        "queries": [
            {"a": "b1", "b": "b2"},
            {"a": "a1", "b": "b2"},
            {"a": "a1", "b": "b1"},
        ],
    }

    # B. both directions remain possible; equality at zero is attainable too.
    fixtures["equality"] = {
        "records": [
            {"type": "device", "device": "A", "offset_min": -2, "offset_max": 2},
            {"type": "device", "device": "B", "offset_min": -2, "offset_max": 2},
            {"type": "event", "event": "e1", "device": "A", "local_ts": 5},
            {"type": "event", "event": "e2", "device": "B", "local_ts": 5},
            # -2 <= e2 - e1 <= 2: negative, zero and positive are all attainable
            {"type": "causal", "src_event": "e1", "dst_event": "e2",
             "min_delay": -2, "max_delay": 2},
        ],
        "queries": [{"a": "e1", "b": "e2"}],
    }

    # B2. exact equality boundary: the difference is pinned to zero.
    fixtures["exact_equality"] = {
        "records": [
            {"type": "device", "device": "A", "offset_min": 0, "offset_max": 0},
            {"type": "device", "device": "B", "offset_min": 0, "offset_max": 0},
            {"type": "event", "event": "s1", "device": "A", "local_ts": 7},
            {"type": "event", "event": "s2", "device": "B", "local_ts": 7},
            {"type": "causal", "src_event": "s1", "dst_event": "s2",
             "min_delay": 0, "max_delay": 0},
        ],
        "queries": [{"a": "s1", "b": "s2"}],
    }

    # B3. necessary ordering: a must be strictly before b (delta >= 2).
    fixtures["necessary_before"] = {
        "records": [
            {"type": "device", "device": "A", "offset_min": 0, "offset_max": 0},
            {"type": "device", "device": "B", "offset_min": 0, "offset_max": 0},
            {"type": "event", "event": "k1", "device": "A", "local_ts": 1},
            {"type": "event", "event": "k2", "device": "B", "local_ts": 5},
            {"type": "causal", "src_event": "k1", "dst_event": "k2",
             "min_delay": 2},
        ],
        "queries": [{"a": "k1", "b": "k2"}],
    }

    # C. disconnected: the second island's clock is uncalibrated (its offset
    # variable has no edge to the reference), so no constraint path exists.
    fixtures["disconnected"] = {
        "records": [
            {"type": "device", "device": "A", "offset_min": -1, "offset_max": 1},
            {"type": "device", "device": "C", "anchored": False},
            {"type": "event", "event": "x1", "device": "A", "local_ts": 3},
            {"type": "event", "event": "z1", "device": "C", "local_ts": 99},
        ],
        "queries": [{"a": "x1", "b": "z1"}],
    }

    # D. contradiction: causal edges demand a strict cycle with negative sum.
    fixtures["contradiction"] = {
        "records": [
            {"type": "device", "device": "A", "offset_min": -5, "offset_max": 5},
            {"type": "device", "device": "B", "offset_min": -5, "offset_max": 5},
            {"type": "event", "event": "p", "device": "A", "local_ts": 10},
            {"type": "event", "event": "q", "device": "B", "local_ts": 10},
            # q >= p + 2 and p >= q + 2 cannot both hold
            {"type": "causal", "src_event": "p", "dst_event": "q",
             "min_delay": 2},
            {"type": "causal", "src_event": "q", "dst_event": "p",
             "min_delay": 2},
        ],
        "queries": [{"a": "p", "b": "q"}],
    }

    # E. manual backfill with only local causality, plus a loose booking lag.
    fixtures["manual_backfill"] = {
        "records": [
            {"type": "device", "device": "A", "offset_min": 0, "offset_max": 0},
            {"type": "device", "device": "B", "offset_min": 0, "offset_max": 0},
            {"type": "event", "event": "m1", "device": "A", "local_ts": 0,
             "booking_lag": 2},
            {"type": "event", "event": "m2", "device": "A", "local_ts": 4,
             "booking_lag": 2},
            {"type": "event", "event": "n1", "device": "B", "local_ts": 2,
             "booking_lag": 2},
            {"type": "manual", "src_event": "m1", "dst_event": "n1",
             "min_delay": 1, "max_delay": 3, "booking_lag": 50},
        ],
        "queries": [{"a": "m1", "b": "n1"}, {"a": "m2", "b": "n1"}],
    }
    return fixtures


def large_journal(
    *,
    seed: int = 20261125,
    devices: int = 24,
    events_per_device: int = 2500,
    cross_edges: int = 4000,
    manual_entries: int = 400,
) -> tuple[list[dict], list[dict]]:
    """Generate a deterministic, guaranteed-feasible large journal.

    Total events = devices * events_per_device (60,000 by default). A hidden
    ground truth is generated first: strictly increasing effective times, a
    bounded offset per segment and explicit clock adjustments. Local
    timestamps are derived as ``effective - offset`` and therefore move
    backwards on every rollback while every emitted constraint stays
    satisfiable by construction.
    """
    rng = random.Random(seed)
    records: list[dict] = []

    offset_lo, offset_hi = -10, 10
    # hidden truth used only while generating; it is not part of the journal
    truth: dict[str, int] = {}
    event_ids: list[str] = []

    for d in range(devices):
        records.append(
            {
                "type": "device",
                "device": f"dev{d:02d}",
                "offset_min": offset_lo,
                "offset_max": offset_hi,
            }
        )

    for d in range(devices):
        offset = rng.randint(offset_lo, offset_hi)
        true_time = rng.randint(0, 100)
        for i in range(events_per_device):
            # Occasionally roll the clock back: emit a clock_adjust whose
            # bounds contain the true offset jump, then stamp a smaller local
            # timestamp than the previous event.
            if i and rng.random() < 0.10:
                new_offset = rng.randint(offset_lo, offset_hi)
                jump = new_offset - offset
                margin = rng.randint(1, 4)
                records.append(
                    {
                        "type": "clock_adjust",
                        "device": f"dev{d:02d}",
                        "delta_min": jump - margin,
                        "delta_max": jump + margin,
                    }
                )
                offset = new_offset
            true_time += rng.randint(1, 6)
            event = f"ev_{d:02d}_{i:05d}"
            local_ts = true_time - offset
            event_index[event] = len(event_ids)
            event_ids.append(event)
            truth[event] = true_time
            rec = {
                "type": "event",
                "event": event,
                "device": f"dev{d:02d}",
                "local_ts": local_ts,
            }
            # booking lag caps stay comfortably feasible; ledger order is the
            # ingestion order, separate from effective time.
            if rng.random() < 0.7:
                rec["booking_lag"] = rng.choice([20, 40, 80, 160])
            records.append(rec)

    def pick_event(device: int | None = None) -> str:
        if device is None:
            return event_ids[rng.randrange(len(event_ids))]
        base = device * events_per_device
        return event_ids[base + rng.randrange(events_per_device)]

    # same-device causal chains: bounds are centred on the true delay, so the
    # hidden assignment always satisfies them even across rollbacks.
    for d in range(devices):
        for i in range(1, events_per_device):
            if rng.random() < 0.4:
                src = f"ev_{d:02d}_{i - 1:05d}"
                dst = f"ev_{d:02d}_{i:05d}"
                delay = truth[dst] - truth[src]
                records.append(
                    {
                        "type": "causal",
                        "src_event": src,
                        "dst_event": dst,
                        "min_delay": max(0, delay - rng.randint(0, 3)),
                        "max_delay": delay + rng.randint(2, 8),
                    }
                )

    # cross-device causal edges (the provable inter-device edges); orient by
    # truth and bracket the true delay, so feasibility is preserved.
    made = 0
    attempts = 0
    while made < cross_edges and attempts < cross_edges * 4:
        attempts += 1
        d1, d2 = rng.sample(range(devices), 2)
        src = pick_event(d1)
        dst = pick_event(d2)
        if truth[src] >= truth[dst]:
            continue
        delay = truth[dst] - truth[src]
        records.append(
            {
                "type": "causal",
                "src_event": src,
                "dst_event": dst,
                "min_delay": max(0, delay - rng.randint(0, 4)),
                "max_delay": delay + rng.randint(2, 10),
            }
        )
        made += 1

    # sparse manual backfill entries: local causality only, loose booking lag
    for _ in range(manual_entries):
        d1, d2 = rng.sample(range(devices), 2)
        src = pick_event(d1)
        dst = pick_event(d2)
        if truth[src] >= truth[dst]:
            src, dst = dst, src
        delay = truth[dst] - truth[src]
        records.append(
            {
                "type": "manual",
                "src_event": src,
                "dst_event": dst,
                "min_delay": max(0, delay - rng.randint(0, 2)),
                "max_delay": delay + rng.randint(5, 20),
                "booking_lag": rng.randint(200, 800),
            }
        )

    queries = [{"a": pick_event(), "b": pick_event()} for _ in range(40)]
    return records, queries
