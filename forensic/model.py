"""Integer difference-constraint model for multi-device shutdown evidence.

Every piece of evidence (clock offset ranges, event local timestamps,
propagation/booking delay upper bounds, provable causal edges, ledger order)
is normalised into one uniform integer constraint::

    x_v - x_u <= w          (an edge u -> v of weight w in a graph)

Node kinds
----------
ref                the reference timeline variable, fixed to 0
off:<device>       integer clock offset of a device's first segment
off:<device>#<k>   offset after the k-th clock adjustment (rollback support)
ev:<event>         effective-time variable of an event
bk:<event>         ledger position variable of an event (booking order)

A clock that is rolled back is modelled as a new offset *segment*: the
``clock_adjust`` record bounds ``off_(k+1) - off_k``, so a backwards local
timestamp can still correspond to a later effective time without relaxing any
other evidence.

The effective-time layer and the booking-order layer are intentionally
separate variables; only the ``booking_lag`` constraints couple them, which is
what lets a late manual entry disturb booking order without rewriting the
effective-time facts.

Only the Python 3.12 standard library is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field

INF: int = 10**18
"""Sentinel used by the solvers for "no finite path / unbounded"."""

REF_NODE = "ref"


@dataclass(frozen=True)
class Edge:
    """One difference constraint ``dst - src <= weight``."""

    eid: int
    src: int
    dst: int
    weight: int
    kind: str
    record: int  # 1-based ledger sequence that introduced the edge

    def as_chain_step(self, names: list[str]) -> dict:
        """JSON-serialisable, human-reviewable description of one step."""
        return {
            "edge": self.eid,
            "from": names[self.src],
            "to": names[self.dst],
            "constraint": f"{names[self.dst]} - {names[self.src]} <= {self.weight}",
            "weight": self.weight,
            "kind": self.kind,
            "record": self.record,
        }


@dataclass
class Record:
    """One append-only journal record (already schema-validated)."""

    seq: int
    rtype: str
    data: dict
    late: bool = False


@dataclass
class Journal:
    """Materialised integer constraint graph built from a journal.

    Nodes are assigned stable integer indices in the order they are first
    mentioned, so replaying a prefix of the journal reconstructs exactly the
    same graph (same indices, same edge ids, same report).
    """

    records: list[Record] = field(default_factory=list)
    names: list[str] = field(default_factory=lambda: [REF_NODE])
    index: dict[str, int] = field(default_factory=lambda: {REF_NODE: 0})
    edges: list[Edge] = field(default_factory=list)
    events: dict[str, dict] = field(default_factory=dict)
    devices: dict[str, dict] = field(default_factory=dict)
    segments: dict[str, int] = field(default_factory=dict)
    """Current 0-based offset segment of each device (rollback counter)."""
    booking_chain: list[int] = field(default_factory=list)  # bk node indices
    parent: list[int] = field(default_factory=lambda: [0])  # DSU over nodes

    # ------------------------------------------------------------------ #
    # construction helpers
    # ------------------------------------------------------------------ #
    def _node(self, name: str) -> int:
        idx = self.index.get(name)
        if idx is None:
            idx = len(self.names)
            self.index[name] = idx
            self.names.append(name)
            self.parent.append(idx)
        return idx

    def _find(self, a: int) -> int:
        parent = self.parent
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def _union(self, a: int, b: int) -> None:
        ra, rb = self._find(a), self._find(b)
        if ra != rb:
            # deterministic union: smaller index becomes root
            if ra > rb:
                ra, rb = rb, ra
            self.parent[rb] = ra

    def _add_edge(self, src: int, dst: int, weight: int, kind: str, seq: int) -> Edge:
        edge = Edge(len(self.edges) + 1, src, dst, int(weight), kind, seq)
        self.edges.append(edge)
        self._union(src, dst)
        return edge

    # ------------------------------------------------------------------ #
    # record ingestion
    # ------------------------------------------------------------------ #
    def ingest(self, record: dict, *, late: bool = False) -> None:
        """Validate and ingest one raw JSON-like record."""
        if not isinstance(record, dict) or "type" not in record:
            raise ValueError("record must be an object with a 'type' field")
        rtype = record["type"]
        seq = len(self.records) + 1
        handler = _RECORD_HANDLERS.get(rtype)
        if handler is None:
            raise ValueError(f"unknown record type: {rtype!r}")
        handler(self, seq, record)
        self.records.append(Record(seq, rtype, dict(record), late=late))

    # -- individual record types ---------------------------------------- #
    def _rec_device(self, seq: int, rec: dict) -> None:
        device = _require_str(rec, "device")
        anchored = rec.get("anchored", True)
        if not isinstance(anchored, bool):
            raise ValueError(f"device {device!r}: anchored must be boolean")
        lo = _optional_int(rec, "offset_min", 0)
        hi = _optional_int(rec, "offset_max", 0)
        if lo > hi:
            raise ValueError(f"device {device!r}: offset_min > offset_max")
        if device in self.devices:
            raise ValueError(f"duplicate device record: {device!r}")
        self.devices[device] = {
            "offset_min": lo,
            "offset_max": hi,
            "anchored": anchored,
        }
        self.segments[device] = 0
        off = self._node(self._offset_name(device, 0))
        ref = self.index[REF_NODE]
        if anchored:
            # off - ref <= hi  and  ref - off <= -lo   (lo <= off <= hi)
            self._add_edge(ref, off, hi, "offset_hi", seq)
            self._add_edge(off, ref, -lo, "offset_lo", seq)
        # An unanchored device keeps its offset variable but emits no edge to
        # the reference: its clock floats, forming a genuinely disconnected
        # component until other evidence links it in.

    @staticmethod
    def _offset_name(device: str, segment: int) -> str:
        return f"off:{device}" if segment == 0 else f"off:{device}#{segment}"

    def _current_offset(self, device: str) -> int:
        return self.index[self._offset_name(device, self.segments[device])]

    def _rec_clock_adjust(self, seq: int, rec: dict) -> None:
        device = _require_str(rec, "device")
        if device not in self.devices:
            raise ValueError(f"clock_adjust: unknown device {device!r}")
        delta_min = _optional_int(rec, "delta_min", -10**15)
        delta_max = _optional_int(rec, "delta_max", 10**15)
        if delta_min > delta_max:
            raise ValueError("clock_adjust: delta_min > delta_max")
        old_seg = self.segments[device]
        new_seg = old_seg + 1
        old = self._current_offset(device)
        new = self._node(self._offset_name(device, new_seg))
        # new - old <= delta_max ; old - new <= -delta_min
        self._add_edge(old, new, delta_max, "clock_adjust_hi", seq)
        self._add_edge(new, old, -delta_min, "clock_adjust_lo", seq)
        self.segments[device] = new_seg

    def _rec_event(self, seq: int, rec: dict) -> None:
        event = _require_str(rec, "event")
        device = _require_str(rec, "device")
        ts = _require_int(rec, "local_ts")
        if event in self.events:
            raise ValueError(f"duplicate event record: {event!r}")
        if device not in self.devices:
            raise ValueError(f"event {event!r}: unknown device {device!r}")
        segment = self.segments[device]
        self.events[event] = {
            "device": device,
            "local_ts": ts,
            "segment": segment,
        }
        off = self._current_offset(device)
        ev = self._node(f"ev:{event}")
        # effective time is pinned: ev = local_ts + off
        # ev - off <= ts ; off - ev <= -ts
        self._add_edge(off, ev, ts, "ev_pins_plus", seq)
        self._add_edge(ev, off, -ts, "ev_pins_minus", seq)
        bk = self._node(f"bk:{event}")
        if self.booking_chain:
            prev_bk = self.booking_chain[-1]
            # ledger order: previous entry was booked strictly first
            # bk_prev - bk_this <= -1  <=>  bk_this >= bk_prev + 1
            self._add_edge(bk, prev_bk, -1, "booking_order", seq)
        lag = rec.get("booking_lag")
        if lag is not None:
            lag = int(lag)
            if lag < 0:
                raise ValueError(f"event {event!r}: booking_lag must be >= 0")
            # bk - ev <= lag
            self._add_edge(ev, bk, lag, "booking_lag", seq)
        self.booking_chain.append(bk)

    def _rec_causal(self, seq: int, rec: dict) -> None:
        src_event = _require_str(rec, "src_event")
        dst_event = _require_str(rec, "dst_event")
        if src_event not in self.events or dst_event not in self.events:
            raise ValueError("causal edge references an unknown event")
        if src_event == dst_event:
            raise ValueError("causal edge must connect two distinct events")
        min_delay = _optional_int(rec, "min_delay", 0)
        max_delay = rec.get("max_delay")
        s = self.index[f"ev:{src_event}"]
        d = self.index[f"ev:{dst_event}"]
        # dst - src >= min_delay  <=>  src - dst <= -min_delay
        self._add_edge(d, s, -min_delay, "causal_min_delay", seq)
        if max_delay is not None:
            max_delay = int(max_delay)
            if max_delay < min_delay:
                raise ValueError("causal edge: max_delay < min_delay")
            # dst - src <= max_delay
            self._add_edge(s, d, max_delay, "causal_max_delay", seq)

    def _rec_manual(self, seq: int, rec: dict) -> None:
        # Manual backfill entry: a causal assertion plus a loose booking lag.
        # It is structurally identical to a causal edge (only local causality
        # between the two named events), which models "局部因果关系".
        self._rec_causal(seq, rec)
        lag = rec.get("booking_lag")
        if lag is not None:
            lag = int(lag)
            if lag < 0:
                raise ValueError("manual entry: booking_lag must be >= 0")
            dst_event = _require_str(rec, "dst_event")
            ev = self.index[f"ev:{dst_event}"]
            bk = self._node(f"bk:{dst_event}")
            if not any(
                e.kind == "manual_booking_lag" and e.src == ev and e.dst == bk
                for e in self.edges
            ):
                self._add_edge(ev, bk, lag, "manual_booking_lag", seq)

    # ------------------------------------------------------------------ #
    # read views
    # ------------------------------------------------------------------ #
    @property
    def n(self) -> int:
        return len(self.names)

    def connected(self, a: int, b: int) -> bool:
        """Whether any constraint path (ignoring direction) joins a and b."""
        return self._find(a) == self._find(b)

    def component_id(self, node: int) -> int:
        return self._find(node)

    def adjacency(self) -> tuple[list[list[tuple[int, int, int]]], list[list[int]]]:
        """Return (forward adjacency, reverse adjacency) over edge ids.

        Forward entry: (dst, weight, edge_id); reverse entry: edge_id.
        """
        fwd: list[list[tuple[int, int, int]]] = [[] for _ in range(self.n)]
        rev: list[list[int]] = [[] for _ in range(self.n)]
        for e in self.edges:
            fwd[e.src].append((e.dst, e.weight, e.eid))
            rev[e.dst].append(e.eid)
        return fwd, rev

    def edge_by_id(self, eid: int) -> Edge:
        return self.edges[eid - 1]


# ---------------------------------------------------------------------- #
# small validation utilities
# ---------------------------------------------------------------------- #
def _require_str(rec: dict, key: str) -> str:
    val = rec.get(key)
    if not isinstance(val, str) or not val:
        raise ValueError(f"field {key!r} must be a non-empty string")
    return val


def _require_int(rec: dict, key: str) -> int:
    val = rec.get(key)
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"field {key!r} must be an integer")
    return val


def _optional_int(rec: dict, key: str, default: int) -> int:
    if key not in rec or rec[key] is None:
        return default
    val = rec[key]
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"field {key!r} must be an integer")
    return val


_RECORD_HANDLERS = {
    "device": Journal._rec_device,
    "clock_adjust": Journal._rec_clock_adjust,
    "event": Journal._rec_event,
    "causal": Journal._rec_causal,
    "manual": Journal._rec_manual,
}


def load_records(path: str) -> list[dict]:
    """Load a UTF-8 JSON-lines journal (one record per line)."""
    import json

    out: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
    return out


def build_journal(records: list[dict], *, late_from_seq: int | None = None) -> Journal:
    """Build a model from raw records.

    ``late_from_seq`` (1-based ledger sequence) marks every record at or after
    that sequence as late evidence; it only changes bookkeeping flags, never
    the constraint graph itself.
    """
    journal = Journal()
    for i, rec in enumerate(records, 1):
        journal.ingest(rec, late=late_from_seq is not None and i >= late_from_seq)
    return journal
