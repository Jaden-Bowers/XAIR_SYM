# XAIR Symbolic

XAIR Symbolic is a C library for symbolic execution, taint tracking, and
constraint solving over frozen XAIR modules and XAIR control-flow graphs. It
uses Z3 through its C API.

## Build

Place this repository beside `xair` and `xair_cfg`, then build with CMake:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Set `XAIR_Z3_SOURCE_ROOT` when the Z3 source tree is not available in an
automatically detected sibling location.

## How it works

The engine translates XAIR values into interned fixed-width symbolic
expressions. Execution states carry path constraints, registers, memory
objects, symbolic bytes, taint, and provenance. Conditional transfers fork
states after bounded solver checks, while API models describe common external
calls. Schedulers explore the resulting states under explicit resource limits
and return concrete witnesses or source-to-sink flow explanations.
