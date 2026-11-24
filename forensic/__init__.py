"""Offline evidence verification for multi-device shutdown logs.

Pure Python 3.12 standard library. See :mod:`forensic.model` for the
integer difference-constraint formulation and :mod:`forensic.solver` for the
full/incremental shortest-path engines.
"""

from .model import INF, Edge, Journal, build_journal, load_records
from .solver import (
    ConflictChain,
    IncrementalSolver,
    JohnsonOracle,
    SolveResult,
    classify_pair,
    extract_conflict_chains,
    pair_bounds,
    spfa_full,
    tarjan_scc,
)

__all__ = [
    "INF",
    "Edge",
    "Journal",
    "build_journal",
    "load_records",
    "ConflictChain",
    "IncrementalSolver",
    "JohnsonOracle",
    "SolveResult",
    "classify_pair",
    "extract_conflict_chains",
    "pair_bounds",
    "spfa_full",
    "tarjan_scc",
]
