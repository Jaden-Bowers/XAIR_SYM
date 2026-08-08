# Phase 6 symbolic-readiness implementation

XAIR Symbolic 0.6 implements the `SYM-001` through `SYM-008` readiness model.

- `SYM-001`: the checked generated opcode capability table covers every public
  opcode, opaque effects carry explicit incompleteness, and wide values have a
  solver model API.
- `SYM-002`: sorted intervals, lazy mapped bytes, sparse pages, bounded symbolic
  address domains, separate taint overlays and page-level COW replace dense
  per-byte objects.
- `SYM-003`: each thread-confined symbolic context owns a persistent Z3 context,
  solver and AST cache. Timeout, resource, cancellation and query-duration
  accounting are explicit.
- `SYM-004`: attributed calls dispatch through the versioned environment model
  registry. Allocation/free, copy/move/fill, input, length and termination are
  modeled; unknown calls remain explicit incomplete operations.
- `SYM-005`: process startup distinguishes Win64 and SysV x64, preserves mapped
  permissions, constructs aligned entry stacks and optional minimal process
  environment pages, and represents memory separately from scalar expressions.
- `SYM-006`: detailed completion results account for states, forks, solver
  queries, limits and terminal states. Parallel scheduling uses disjoint
  first-symbol partitions, shared state/step/fork budgets, a dynamically
  reserved process-wide memory budget with peak reporting, global coverage,
  and structural terminal identity rather than independent full-budget
  portfolio searches.
- `SYM-007`: provenance carries categories, address/call site, byte ranges,
  confidence and explicit/implicit origin. Control taint is scoped with CFG
  immediate postdominators, sanitizer validation is explicit, and sink nodes
  preserve address-level paths.
- `SYM-008`: schema 3 snapshots are sparse, bounded, checksummed, atomically
  replaced and fingerprinted. Backing bytes and page overrides are sparse and
  duplicate records are rejected. The checked loader validates caller-selected
  binary, ABI, model and option expectations; isolated clones omit unsafe raw
  callback pointers while recreating the built-in environment from owned
  configuration. Expression and taint DAGs are serialized and remapped, so a
  snapshot can be loaded into a fresh context.

`FLAGS_SHL` carries the prior flags as an explicit third IR operand. Execution
selects that exact dependency when the masked count is zero; unrelated live
flags cannot influence the result. Logic/shift AF and other architecturally
undefined flag components are stable, operation-origin `Unknown` values.

Custom call models can inspect a structured public call view (ABI, identity,
distinct call-site/target provenance, input and output confidence, effects,
symbolic arguments and taint), set typed and
tainted results, update memory through transactional memory APIs, add
constraints, mark incompleteness/havoc, and request no-return termination.
Built-in input, fill, copy, calloc, free and realloc models validate whole
ranges and preserve memory atomically on failure.

CTest covers the capability table, 100 MiB sparse mappings, page COW,
containment overlap rejection, taint/sink metadata, checksum corruption and
sparse snapshot size. Optional libFuzzer targets are
`xair_fuzz_snapshot_loader`, `xair_fuzz_expression_builder`, and
`xair_fuzz_sym_fuzzer`; the performance smoke executable is
`xair_sym_benchmark`.
