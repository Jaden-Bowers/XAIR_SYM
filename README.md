# XAIR Symbolic Engine

XAIR Symbolic is governed by XA IR semantic contract 1.1.0 in
[`../xair/docs/semantics.md`](../xair/docs/semantics.md). Solver `unknown`, timeout,
cancellation, resource limits, Unknown values, faults, and Opaque operations must
follow that contract; any baseline gap listed there makes dependent results
explicitly incomplete.

The component now uses the sibling-aware
[`xair` unified build](../xair/docs/building.md), including source-built static
Z3. Symbolic contexts are thread-confined, parallel workers are isolated, and
cancellation tokens are shared atomics as defined by
[`thread-safety.md`](../xair/docs/thread-safety.md).

XAIR Symbolic is a C library for symbolic execution and object-based symbolic
memory over frozen XAIR modules and XAIR CFGs. It is a separate project from the
IR generator and CFG recovery engine and consumes their public C APIs.

Current version: 0.6.0. The Phase 6 symbolic-readiness architecture is enabled.

Implemented:

- Immutable structurally interned expression DAGs with stable 32-bit IDs.
- Fixed-width bit-vector expressions from 1 through 128 bits.
- A solver-neutral public C boundary and native Z3 C backend.
- SAT, UNSAT, and concrete model extraction.
- Persistent path constraints through cloned execution states.
- Symbolic interpretation of scalar XAIR operations.
- Feasibility-checked conditional path forking over frozen XAIR modules.
- Sorted interval memory with lazy file-backed objects, sparse 4 KiB symbolic
  pages, separate taint overlays, and page-level copy-on-write.
- Concrete-address loads and stores through XAIR memory operations.
- Bounded symbolic byte-address loads and stores over known memory objects,
  encoded as guarded value summaries with explicit in-bounds constraints.
- Deterministic counters for expressions, solver activity, states, forks, and
  memory copies.
- Interned source, union, and named sanitizer provenance nodes.
- Value and object-byte taint shadows that follow copy-on-write state memory.
- Explicit and targeted implicit-flow propagation modes.
- Read-only provenance inspection for source-to-sink explanations.
- Breadth-first, depth-first, and coverage-new frontier policies.
- Per-run state, block-step, and block-visit resource budgets.
- Exact duplicate-state subsumption at the scheduler boundary.
- Conservative dependency slicing before solver submission.
- Collision-safe SAT, UNSAT, and model caches keyed by persistent constraint
  identities and exact query objectives.
- Concrete branch-trace ingestion and targeted branch inversion.
- Feasible model extraction as byte-oriented fuzzer inputs.
- Versioned binary testcase exchange with bounded C readers and writers.
- Hybrid execution controls that cap online forks and record concretization.
- PE32, PE32+, ELF32, and ELF64 process-memory initialization through the
  upstream binary and CFG contracts.
- Architecture-specific stack initialization and symbolic initial registers.
- Deterministic heap objects, symbolic input buffers, taint sources, and
  provenance-preserving memory copies.
- Versioned Linux, Windows, and Windows-driver model classification for common
  allocation, input, copy, termination, probing, and completion APIs.
- Structured custom-model inspection and updates for ABI, arguments, taint,
  distinct call-site/target provenance, model confidence, results, memory,
  constraints, completeness, and termination.
- Versioned module-fingerprinted state snapshots with deterministic in-memory
  restoration and bounded file loading.
- Snapshot preservation of values, constraints, taint, control taint, memory
  objects, permissions, symbolic bytes, and provenance IDs.
- Deterministic disjoint first-symbol partitions with shared global state,
  step, fork, coverage, and dynamically reserved memory budgets plus
  structural terminal deduplication.
- Synchronized C callbacks and atomic cancellation tokens for parallel runs.
- Predecoded immutable block plans that remove repeated public IR inspection
  and operation decoding from the execution loop.
- Public runtime version inspection.

The production implementation and public API are C. There is no Python runtime
or Python orchestration layer. Z3 is an external solver dependency used through
its C API.

Concrete addresses resolve through the interval index. Symbolic byte addresses
use bounded finite-domain guarded summaries and return an explicit resource
limit before scanning a large address space. Wide accesses compose page-backed
bytes without allocating expressions for untouched mapped data.

The process model maps the binary segments supplied by `xair_binary_view`, then
adds a deterministic stack and initializes entry parameters by their frozen IR
names. Relocation application, dynamic linking, command-line construction,
filesystem state, and full kernel object graphs remain explicit later
environment work. Unknown external calls are reported as unknown models rather
than being assigned unconstrained behavior silently.

Snapshot files use sparse, checksummed schema `XAIRSN03`. They validate IR and
binary fingerprints, symbolic and memory-model versions, ABI, model-library
version, options and completeness. Saves use a temporary file and atomic
replacement, so an interrupted save cannot truncate the prior snapshot.

Parallel execution splits the first symbolic input domain into disjoint modulo
partitions. Each partition has an isolated context, and the requested global
state, step, and fork limits use shared counters; memory is reserved against a
shared process-wide limit and reports its peak across workers. Terminal
identity is compared structurally (including values, taint, and memory), not by
a collision-prone hash. Isolated clones reconstruct the owned built-in model
environment. Dynamic callback registries are explicitly unsupported for
parallel isolation because raw process-local callback pointers are not copied.

The compiled block path is a predecoded C dispatch plan, not a native-code JIT.
It removes repeated IR accessor calls while retaining one symbolic-semantics
implementation. Native code generation, additional solver backends, and
executable-memory code epochs remain later performance work and must be
benchmarked before becoming defaults.

## Build

```sh
cmake -S . -B build-wsl-strict -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DXAIR_SYM_STRICT_WARNINGS=ON \
  -DXAIR_CFG_STRICT_WARNINGS=ON \
  -DXAIR_STRICT_WARNINGS=ON
cmake --build build-wsl-strict
ctest --test-dir build-wsl-strict --output-on-failure
```

Set `XAIR_SYM_Z3_ROOT` to a Z3 installation containing `include/z3.h` and
`lib/libz3.so` when it is not available at the default local WSL path.
