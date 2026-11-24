"""Solvers for the integer difference-constraint model.

Uniform constraint form: edge u->v with weight w means ``x_v - x_u <= w``.
The tightest possible value of each variable difference is therefore a
shortest-path distance, a negative cycle means the constraints contradict
each other, and the edges on a shortest path form a reviewable witness.

Three engines are provided on the same graph representation:

* :func:`spfa_full`     - one whole-graph SPFA pass (the "full" computation)
* :class:`IncrementalSolver` - adds edges one at a time, propagating each
  relaxation locally and counting the visited nodes/edges ("局部更新")
* :func:`johnson_query` - reweighted Dijkstra for tight bounds + witnesses on
  a feasible graph (deterministic tie-breaking)

All paths are deterministic: queue processing is FIFO in a fixed node order
and Dijkstra breaks ties by node id, so full and incremental runs produce
identical distances and identical witnesses.
"""

from __future__ import annotations

import heapq
from collections import deque
from dataclasses import dataclass, field

from .model import INF, Edge, Journal

# ---------------------------------------------------------------------- #
# result containers
# ---------------------------------------------------------------------- #


@dataclass
class SolveResult:
    feasible: bool
    dist: list[int]
    """dist[v] = tightest bound x_v - x_ref (INF when unreachable)."""
    predecessor: list[int]
    """predecessor[v] = edge id of the chosen incoming shortest-path edge."""
    relaxations: int = 0
    node_visits: int = 0
    edge_scans: int = 0
    enqueues: int = 0
    conflict_node: int | None = None
    """A node lying on a detected negative cycle, if any."""


@dataclass
class IncrementalStats:
    edges_added: int = 0
    propagations: int = 0
    """Number of edges whose addition actually triggered a propagation."""
    relaxed_edges: int = 0
    node_visits: int = 0
    edge_scans: int = 0
    enqueues: int = 0
    per_edge: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------- #
# full-graph SPFA (FIFO, fully deterministic)
# ---------------------------------------------------------------------- #


def spfa_full(journal: Journal) -> SolveResult:
    """Solve the whole constraint graph with one SPFA pass.

    Every node starts at distance 0, equivalent to a virtual source with a
    0-weight edge to every node; a negative cycle is reported as soon as a
    shortest path would contain ``n`` edges (more edges than a simple path).
    """
    n = journal.n
    fwd, _ = journal.adjacency()
    dist = [0] * n
    pred = [-1] * n
    path_len = [0] * n
    in_queue = [True] * n
    queue = deque(range(n))
    stats = {"relax": 0, "visit": 0, "scan": 0, "enq": n}
    conflict_node: int | None = None

    while queue:
        u = queue.popleft()
        in_queue[u] = False
        stats["visit"] += 1
        du = dist[u]
        for v, w, eid in fwd[u]:
            stats["scan"] += 1
            nd = du + w
            if nd < dist[v]:
                dist[v] = nd
                pred[v] = eid
                path_len[v] = path_len[u] + 1
                stats["relax"] += 1
                if path_len[v] >= n:
                    conflict_node = v
                    return SolveResult(
                        False, dist, pred,
                        stats["relax"], stats["visit"], stats["scan"],
                        stats["enq"], conflict_node,
                    )
                if not in_queue[v]:
                    in_queue[v] = True
                    queue.append(v)
                    stats["enq"] += 1

    return SolveResult(
        True, dist, pred,
        stats["relax"], stats["visit"], stats["scan"], stats["enq"], None,
    )


# ---------------------------------------------------------------------- #
# incremental engine: edge-by-edge local propagation
# ---------------------------------------------------------------------- #


class IncrementalSolver:
    """Maintains shortest distances while edges are appended locally.

    Only nodes whose tight bound can actually change are enqueued, so late
    evidence touches just the connected component carrying that evidence.
    Distances, predecessors and tie-breaking match :func:`spfa_full` exactly.
    """

    def __init__(self, journal: Journal):
        self.journal = journal
        n = journal.n
        # Empty graph: every variable starts at 0, the same starting point as
        # the full SPFA's virtual zero-source. The adjacency is owned by this
        # engine and grows one edge at a time, so a propagation can only ever
        # traverse edges already inserted - prefix states and access counters
        # stay exact instead of "looking ahead" through future edges.
        self.dist = [0] * n
        self.pred = [-1] * n
        self.path_len = [0] * n
        self.fwd: list[list[tuple[int, int, int]]] = [[] for _ in range(n)]
        self.stats = IncrementalStats()
        self.feasible = True
        self.conflict_node: int | None = None
        self._in_queue = [False] * n
        # enqueue counter used only as a defensive negative-cycle tripwire
        self._enq_count = [0] * n
        self.n = n
        self._inserted = 0

    def add_edge(self, edge: Edge) -> dict:
        """Insert one edge and propagate the relaxation locally."""
        # Materialise this edge in the engine's own adjacency first.
        self.fwd[edge.src].append((edge.dst, edge.weight, edge.eid))
        self._inserted += 1
        self.stats.edges_added += 1
        local = {
            "edge": edge.eid,
            "kind": edge.kind,
            "record": edge.record,
            "changed": False,
            "node_visits": 0,
            "edge_scans": 0,
            "relaxed_edges": 0,
            "enqueues": 0,
            "touched_nodes": [],
        }
        touched: set[int] = set()
        queue: deque[int] = deque()
        if edge.weight < self.dist[edge.dst] - self.dist[edge.src]:
            self.dist[edge.dst] = self.dist[edge.src] + edge.weight
            self.pred[edge.dst] = edge.eid
            self.path_len[edge.dst] = self.path_len[edge.src] + 1
            local["changed"] = True
            local["relaxed_edges"] += 1
            self.stats.relaxed_edges += 1
            touched = {edge.dst}
            queue.append(edge.dst)
            self._in_queue[edge.dst] = True
            self._enq_count[edge.dst] += 1
            local["enqueues"] += 1
            self.stats.enqueues += 1
            if self.path_len[edge.dst] >= self.n:
                self.feasible = False
                self.conflict_node = edge.dst

        while queue and self.feasible:
            u = queue.popleft()
            self._in_queue[u] = False
            local["node_visits"] += 1
            self.stats.node_visits += 1
            du = self.dist[u]
            for v, w, eid in self.fwd[u]:
                local["edge_scans"] += 1
                self.stats.edge_scans += 1
                nd = du + w
                if nd < self.dist[v]:
                    self.dist[v] = nd
                    self.pred[v] = eid
                    self.path_len[v] = self.path_len[u] + 1
                    local["relaxed_edges"] += 1
                    self.stats.relaxed_edges += 1
                    touched.add(v)
                    if self.path_len[v] >= self.n:
                        self.feasible = False
                        self.conflict_node = v
                        break
                    if not self._in_queue[v]:
                        self._in_queue[v] = True
                        queue.append(v)
                        self._enq_count[v] += 1
                        local["enqueues"] += 1
                        self.stats.enqueues += 1
                        if self._enq_count[v] > self.n:
                            # Defensive tripwire; path_len normally fires first.
                            self.feasible = False
                            self.conflict_node = v
                            break

        local["touched_nodes"] = (
            sorted(self.journal.names[i] for i in touched) if local["changed"] else []
        )
        if local["changed"]:
            self.stats.propagations += 1
        self.stats.per_edge.append(local)
        return local

    def run_all(self) -> IncrementalStats:
        for edge in self.journal.edges:
            self.add_edge(edge)
            if not self.feasible:
                break
        return self.stats


# ---------------------------------------------------------------------- #
# Johnson reweighted Dijkstra: tight pair bounds + reviewable witnesses
# ---------------------------------------------------------------------- #


@dataclass
class QueryWitness:
    bound: int | None  # None means unbounded (no constraint path)
    edges: list[Edge]
    """Edges in path order; summing their weights reproduces ``bound``."""

    def to_dict(self, names: list[str]) -> dict:
        chain = [e.as_chain_step(names) for e in self.edges]
        check = sum(e.weight for e in self.edges) if self.edges else 0
        return {
            "bound": self.bound,
            "sum_check": check,
            "chain": chain,
        }


class JohnsonOracle:
    """Per-source shortest paths on a feasible graph.

    SPFA supplies feasible node potentials ``h``; reweighted weights
    ``w'(u,v) = w(u,v) + h[u] - h[v]`` are non-negative, so plain Dijkstra
    applies. Original distances are recovered as
    ``d(s,t) = d'(s,t) - h[s] + h[t]``.
    """

    def __init__(self, journal: Journal, potentials: list[int]):
        self.journal = journal
        self.n = journal.n
        self.fwd, _ = journal.adjacency()
        self.h = potentials
        self.reweighted: list[list[tuple[int, int, int]]] = [[] for _ in range(self.n)]
        for e in journal.edges:
            rw = e.weight + potentials[e.src] - potentials[e.dst]
            # On a feasible graph every reweighted weight is >= 0.
            assert rw >= 0, "negative reweighted edge: graph not feasible"
            self.reweighted[e.src].append((e.dst, rw, e.eid))
        self._cache: dict[int, tuple[list[int], list[int]]] = {}

    def dijkstra(self, src: int) -> tuple[list[int], list[int]]:
        cached = self._cache.get(src)
        if cached is not None:
            return cached
        dist = [INF] * self.n
        pred = [-1] * self.n
        dist[src] = 0
        heap: list[tuple[int, int]] = [(0, src)]
        while heap:
            d, u = heapq.heappop(heap)
            if d != dist[u]:
                continue
            # Adjacency lists are in ascending edge-id order; ties are only
            # ever broken by the heap's (distance, node-id) ordering, so the
            # resulting predecessor tree is deterministic and every chain is
            # contiguous. Predecessors are changed solely on strict
            # improvement, never retroactively on an equal distance.
            for v, rw, eid in self.reweighted[u]:
                nd = d + rw
                if nd < dist[v]:
                    dist[v] = nd
                    pred[v] = eid
                    heapq.heappush(heap, (nd, v))
        self._cache[src] = (dist, pred)
        return dist, pred

    def distance(self, src: int, dst: int) -> int | None:
        """Original-graph shortest distance d(src -> dst), None if unreachable."""
        dist, _ = self.dijkstra(src)
        if dist[dst] == INF:
            return None
        return dist[dst] - self.h[src] + self.h[dst]

    def witness(self, src: int, dst: int) -> QueryWitness:
        dist, pred = self.dijkstra(src)
        if dist[dst] == INF:
            return QueryWitness(None, [])
        # Reconstruct the edge chain backwards from dst to src.
        chain: list[Edge] = []
        cur = dst
        guard = 0
        while cur != src:
            eid = pred[cur]
            if eid < 0 or guard > self.n:
                # Should be unreachable; treat as no witness.
                return QueryWitness(None, [])
            edge = self.journal.edge_by_id(eid)
            chain.append(edge)
            cur = edge.src
            guard += 1
        chain.reverse()
        bound = dist[dst] - self.h[src] + self.h[dst]
        return QueryWitness(bound, chain)


# ---------------------------------------------------------------------- #
# pair verdicts: necessary vs merely possible ordering
# ---------------------------------------------------------------------- #


def pair_bounds(oracle: JohnsonOracle, a: int, b: int) -> tuple[int | None, int | None]:
    """Tightest integer bounds on ``x_b - x_a``: (lower, upper).

    lower = -d(b -> a), upper = d(a -> b); None marks an unbounded side
    because the constraint graph has no path in that direction.
    """
    upper = oracle.distance(a, b)
    rev = oracle.distance(b, a)
    lower = None if rev is None else -rev
    return lower, upper


def classify_pair(lower: int | None, upper: int | None) -> dict:
    """Turn tight integer bounds on ``delta = x_b - x_a`` into a verdict.

    For an integer feasible system the attainable values are exactly
    ``[lower, upper]`` (an open side means unbounded). Hence:

    A direction is *necessary* only when the opposite value is impossible.
    Note the sign convention: ``delta < 0`` means b happens before a (a is
    later), ``delta > 0`` means a happens before b (a is earlier).
    """
    if lower is None and upper is None:
        return {
            "verdict": "unconstrained",
            "label": "无约束（两侧均无路径）",
            "strictly_before_possible": True,
            "strictly_after_possible": True,
            "equal_possible": True,
        }
    neg_possible = lower is None or lower < 0
    pos_possible = upper is None or upper > 0
    equal_possible = (lower is None or lower <= 0) and (
        upper is None or upper >= 0
    )
    if neg_possible and pos_possible:
        verdict, label = "possible_both_orders", "仅可能先后（两个方向均可满足）"
    elif neg_possible and equal_possible:
        # delta <= 0: b is no later than a (a is no earlier than b).
        verdict, label = "necessary_a_after_or_equal", "必然不早：a 必然不早于 b（可能相等）"
    elif pos_possible and equal_possible:
        # delta >= 0: a is no later than b.
        verdict, label = "necessary_a_before_or_equal", "必然不晚：a 必然不晚于 b（可能相等）"
    elif neg_possible:
        verdict, label = "necessary_a_after", "必然先后：a 必然晚于 b"
    elif pos_possible:
        verdict, label = "necessary_a_before", "必然先后：a 必然早于 b"
    elif equal_possible:
        verdict, label = "necessary_equal", "必然相等（相等边界）"
    else:  # pragma: no cover - cannot occur in a feasible system
        verdict, label = "infeasible_pair", "无可行取值（系统应已判定矛盾）"
    return {
        "verdict": verdict,
        "label": label,
        "strictly_before_possible": bool(neg_possible),
        "strictly_after_possible": bool(pos_possible),
        "equal_possible": bool(equal_possible),
    }


# ---------------------------------------------------------------------- #
# strongly connected components (iterative Tarjan, no recursion depth limit)
# ---------------------------------------------------------------------- #


def tarjan_scc(journal: Journal) -> list[list[int]]:
    fwd, _ = journal.adjacency()
    n = journal.n
    index = [-1] * n
    low = [0] * n
    on_stack = [False] * n
    stack: list[int] = []
    components: list[list[int]] = []
    counter = 0

    for root in range(n):
        if index[root] != -1:
            continue
        # iterative DFS frames: (node, next-neighbour-position)
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack[root] = True
        frames = [(root, 0)]
        while frames:
            u, pos = frames[-1]
            neighbours = fwd[u]
            if pos < len(neighbours):
                v = neighbours[pos][0]
                frames[-1] = (u, pos + 1)
                if index[v] == -1:
                    index[v] = low[v] = counter
                    counter += 1
                    stack.append(v)
                    on_stack[v] = True
                    frames.append((v, 0))
                elif on_stack[v]:
                    low[u] = min(low[u], index[v])
            else:
                frames.pop()
                if frames:
                    parent = frames[-1][0]
                    low[parent] = min(low[parent], low[u])
                if low[u] == index[u]:
                    comp: list[int] = []
                    while True:
                        w = stack.pop()
                        on_stack[w] = False
                        comp.append(w)
                        if w == u:
                            break
                    components.append(sorted(comp))
    # Stable component order: smallest member id first.
    components.sort(key=lambda comp: comp[0])
    return components


# ---------------------------------------------------------------------- #
# shortest negative-cycle extraction (the reviewable conflict chains)
# ---------------------------------------------------------------------- #


@dataclass
class ConflictChain:
    edges: list[Edge]
    total_weight: int
    nodes: list[int]
    fallback: bool = False
    """True when enumeration budget was exhausted and an SPFA walk is used."""


def _scc_internal_edges(journal: Journal, comp: set[int]) -> list[Edge]:
    return [e for e in journal.edges if e.src in comp and e.dst in comp]


def _scc_has_negative_cycle(edges: list[Edge], nodes: list[int]) -> bool:
    """Bellman-Ford inside one SCC (all-zero start); True if infeasible."""
    adj: dict[int, list[tuple[int, int]]] = {u: [] for u in nodes}
    for e in edges:
        adj[e.src].append((e.dst, e.weight))
    dist = {u: 0 for u in nodes}
    for _ in range(len(nodes) - 1):
        changed = False
        for e in edges:
            nd = dist[e.src] + e.weight
            if nd < dist[e.dst]:
                dist[e.dst] = nd
                changed = True
        if not changed:
            return False
    for e in edges:
        if dist[e.src] + e.weight < dist[e.dst]:
            return True
    return False


def extract_conflict_chains(
    journal: Journal, *, cycle_budget: int = 200_000, max_chains: int = 16
) -> list[ConflictChain]:
    """Return the shortest negative cycles, one set per conflicting SCC.

    Enumeration is depth-bounded DFS over simple cycles (deterministic edge
    order). The first cycle length that yields any negative cycle is the
    shortest possible length; all negative cycles of that length are kept,
    canonicalised, de-duplicated and stably sorted. If the enumeration budget
    is exhausted on a large SCC, a predecessor-chain witness from SPFA is
    returned instead and explicitly marked as a fallback in the report.
    """
    fwd, _ = journal.adjacency()
    chains: list[ConflictChain] = []
    for comp_nodes in tarjan_scc(journal):
        if len(comp_nodes) < 2:
            continue
        comp = set(comp_nodes)
        internal = _scc_internal_edges(journal, comp)
        if not _scc_has_negative_cycle(internal, comp_nodes):
            continue
        found = _enumerate_shortest_negative_cycles(
            journal, comp, internal, budget=cycle_budget, max_chains=max_chains
        )
        if found is not None:
            chains.extend(found)
        else:
            chains.append(_fallback_chain(journal, comp_nodes))
    chains.sort(key=_chain_sort_key)
    return chains


def _enumerate_shortest_negative_cycles(
    journal: Journal,
    comp: set[int],
    internal: list[Edge],
    *,
    budget: int,
    max_chains: int,
) -> list[ConflictChain] | None:
    fwd, _ = journal.adjacency()
    seen: set[tuple[int, ...]] = set()
    work = budget
    # Try cycle lengths in increasing order; first hit = shortest length.
    for length in range(2, len(comp) + 1):
        hits: list[ConflictChain] = []
        for start in sorted(comp):
            # DFS stack: (node, depth, edge-path, visited-node set).
            # A cycle is accepted only when ``start`` is its smallest member,
            # which enumerates every simple cycle exactly once.
            stack: list[tuple[int, int, list[int], frozenset[int]]] = [
                (start, 0, [], frozenset({start}))
            ]
            while stack:
                work -= 1
                if work < 0:
                    return None
                u, depth, path_eids, visited = stack.pop()
                if depth == length:
                    if u == start:
                        total = 0
                        nodes = [start]
                        for eid in path_eids:
                            e = journal.edge_by_id(eid)
                            total += e.weight
                            nodes.append(e.dst)
                        if total < 0:
                            key = _canonical_cycle(journal, path_eids)
                            if key not in seen:
                                seen.add(key)
                                hits.append(
                                    ConflictChain(
                                        [journal.edge_by_id(i) for i in path_eids],
                                        total,
                                        nodes[:-1],
                                    )
                                )
                    continue
                for v, _w, eid in reversed(fwd[u]):
                    if v not in comp:
                        continue
                    if v == start and depth + 1 == length:
                        stack.append((v, depth + 1, path_eids + [eid], visited))
                    elif v != start and v not in visited and depth + 1 < length:
                        if v < start:
                            continue  # this cycle will be enumerated from v
                        stack.append(
                            (v, depth + 1, path_eids + [eid], visited | {v})
                        )
        if hits:
            hits.sort(key=_chain_sort_key)
            return hits[:max_chains]
    return None


def _canonical_cycle(journal: Journal, eids: list[int]) -> tuple[int, ...]:
    """Rotate an edge cycle so it starts at its smallest edge id."""
    if not eids:
        return tuple()
    min_pos = min(range(len(eids)), key=lambda i: eids[i])
    rotated = eids[min_pos:] + eids[:min_pos]
    return tuple(rotated)


def _chain_sort_key(chain: ConflictChain) -> tuple:
    edge_ids = tuple(e.eid for e in chain.edges)
    return (len(chain.edges), chain.total_weight, edge_ids)


def _fallback_chain(journal: Journal, comp_nodes: list[int]) -> ConflictChain:
    """SPFA predecessor walk inside a conflicting SCC (budget exhausted)."""
    comp = set(comp_nodes)
    internal = _scc_internal_edges(journal, comp)
    adj: dict[int, list[tuple[int, int, int]]] = {u: [] for u in comp_nodes}
    for e in internal:
        adj[e.src].append((e.dst, e.weight, e.eid))
    n = len(comp_nodes)
    dist = {u: 0 for u in comp_nodes}
    pred: dict[int, int] = {}
    path_len = {u: 0 for u in comp_nodes}
    queue = deque(sorted(comp_nodes))
    in_queue = {u: True for u in comp_nodes}
    hit: int | None = None
    while queue and hit is None:
        u = queue.popleft()
        in_queue[u] = False
        for v, w, eid in adj[u]:
            nd = dist[u] + w
            if nd < dist[v]:
                dist[v] = nd
                pred[v] = eid
                path_len[v] = path_len[u] + 1
                if path_len[v] >= n:
                    hit = v
                    break
                if not in_queue[v]:
                    in_queue[v] = True
                    queue.append(v)
    start = hit if hit is not None else comp_nodes[0]
    # Walk predecessors until the start repeats; the repeated segment is a
    # negative cycle.
    chain_eids: list[int] = []
    visited: dict[int, int] = {}
    cur = start
    while cur not in visited:
        visited[cur] = len(chain_eids)
        eid = pred.get(cur, -1)
        if eid < 0:
            break
        chain_eids.append(eid)
        cur = journal.edge_by_id(eid).src
    if cur in visited:
        chain_eids = chain_eids[visited[cur]:]
    chain_eids.reverse()
    edges = [journal.edge_by_id(i) for i in chain_eids]
    nodes = [edges[0].src] + [e.dst for e in edges]
    chain = ConflictChain(edges, sum(e.weight for e in edges), nodes[:-1])
    chain.fallback = True
    return chain
