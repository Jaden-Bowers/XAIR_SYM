# XAIR Symbolic Engine

XAIR Symbolic is a C library for symbolic execution and object-based symbolic
memory over frozen XAIR modules and XAIR CFGs. It is a separate project from the
IR generator and CFG recovery engine and consumes their public C APIs.

Current version: 0.1.0, Block B bootstrap.

Implemented:

- Immutable structurally interned expression DAGs with stable 32-bit IDs.
- Fixed-width bit-vector expressions from 1 through 128 bits.
- A solver-neutral public C boundary and native Z3 C backend.
- SAT, UNSAT, and concrete model extraction.
- Persistent path constraints through cloned execution states.
- Symbolic interpretation of scalar XAIR operations.
- Feasibility-checked conditional path forking over frozen XAIR modules.
- Object-based memory with bounds, permissions, sparse symbolic bytes, and
  copy-on-write state cloning.
- Concrete-address loads and stores through XAIR memory operations.
- Bounded symbolic byte-address loads and stores over known memory objects,
  encoded as guarded value summaries with explicit in-bounds constraints.
- Deterministic counters for expressions, solver activity, states, forks, and
  memory copies.

The production implementation and public API are C. There is no Python runtime
or Python orchestration layer. Z3 is an external solver dependency used through
its C API.

The current memory bootstrap resolves concrete addresses directly and bounded
symbolic byte addresses through guarded object-byte summaries. Wide symbolic
accesses and scalable index representations belong to later optimization work.
Unsupported semantic forms return an explicit status.

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
