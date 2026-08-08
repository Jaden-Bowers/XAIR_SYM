#!/usr/bin/env python3
"""Cross-check each advertised opcode capability against its owning engine.

This intentionally extracts individual function bodies.  A case label in an
unrelated switch must not make an opcode look implemented everywhere.
"""
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parents[1]
xair_root = root.parent / "xair"


def function_body(text: str, name: str) -> str:
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;]*?\)\s*\{", text, re.S)
    if match is None:
        raise SystemExit(f"engine function {name} was not found")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise SystemExit(f"engine function {name} has no closing brace")


def cases(text: str, *functions: str) -> set[str]:
    return set().union(*(
        set(re.findall(r"\bcase\s+(XAIR_OP_[A-Z0-9_]+)\s*:", function_body(text, name)))
        for name in functions
    ))


header = (xair_root / "include" / "xair" / "xair.h").read_text(encoding="utf-8")
enum_body = re.search(r"typedef enum\s*\{(.*?)\}\s*xair_opcode\s*;", header, re.S)
if enum_body is None:
    raise SystemExit("xair_opcode was not found")
expected = re.findall(r"\b(XAIR_OP_[A-Z0-9_]+)\b", enum_body.group(1))

table_text = (root / "src" / "xair_sym_opcode_capabilities.inc").read_text(encoding="utf-8")
table_rows = re.findall(r"XAIR_SYM_OPCODE\((XAIR_OP_[A-Z0-9_]+),\s*([A-Z_]+)\)", table_text)
actual = [opcode for opcode, _ in table_rows]
if expected != actual:
    raise SystemExit(f"opcode capability table is stale\nexpected: {expected}\nactual: {actual}")

xair = (xair_root / "src" / "xair.c").read_text(encoding="utf-8")
core = (root / "src" / "xair_sym_core.c").read_text(encoding="utf-8")
solver = (root / "src" / "xair_sym_solver_z3.c").read_text(encoding="utf-8")
execution = (root / "src" / "xair_sym_exec.c").read_text(encoding="utf-8")
snapshot = (root / "src" / "xair_sym_snapshot.c").read_text(encoding="utf-8")
taint = (root / "src" / "xair_sym_taint.c").read_text(encoding="utf-8")

constants = {"XAIR_OP_CONST_U64", "XAIR_OP_CONST_WIDE"}
symbolic_origins = {"XAIR_OP_UNKNOWN", "XAIR_OP_UNDEF", "XAIR_OP_OPAQUE_PURE",
                    "XAIR_OP_OPAQUE_EFFECT", "XAIR_OP_CALL", "XAIR_OP_INTRINSIC"}
memory_ops = {"XAIR_OP_LOAD", "XAIR_OP_STORE", "XAIR_OP_MEMORY_BARRIER"}
flag_packs = {"XAIR_OP_FLAGS_ADD", "XAIR_OP_FLAGS_SUB", "XAIR_OP_FLAGS_LOGIC", "XAIR_OP_FLAGS_SHL"}

engines: dict[str, set[str]] = {}
engines["VERIFY"] = cases(xair, "verify_binary_op", "verify_unary_op", "verify_memory_op",
                           "verify_select_op", "verify_op") | constants
engines["FORMAT"] = cases(xair, "xair_opcode_name")
engines["CONCRETE"] = cases(xair, "exec_binary_op", "exec_unary_op", "exec_memory_op",
                             "exec_op") | constants | symbolic_origins | memory_ops | {"XAIR_OP_SELECT"}
engines["EXPRESSION"] = (cases(core, "unary_shape_valid", "binary_shape_valid") |
                         constants | {"XAIR_OP_SELECT"} | symbolic_origins | memory_ops)
engines["Z3"] = (cases(solver, "translate_xair", "translate", "translate_flag_pack") | constants |
                 {"XAIR_OP_SELECT"} | symbolic_origins | flag_packs)
engines["FOLD"] = cases(xair, "fold_constant_op") | constants | flag_packs

# Taint propagation is deliberately generic: it walks the operation's public
# input/result vectors instead of duplicating an opcode switch.  Snapshot
# serialization similarly records all state values and validates every XAIR
# expression shape independently.  Verify those generic engines themselves
# before assigning their support set.
taint_body = function_body(taint, "xair_sym_taint_operands")
if "op->src_count" not in taint_body or "xair_sym_taint_union" not in taint_body:
    raise SystemExit("generic taint engine no longer walks and combines operands")
serialized_shapes = cases(snapshot, "snapshot_expression_shape_valid")
if not constants.issubset(set(expected)) or not flag_packs.issubset(serialized_shapes):
    raise SystemExit("snapshot expression validator is missing constant/flag shape support")
engines["TAINT"] = set(expected)
engines["SERIALIZE"] = (serialized_shapes | constants | {"XAIR_OP_SELECT"} |
                        symbolic_origins | memory_ops)
engines["EXPLICIT_INCOMPLETE"] = {
    "XAIR_OP_OPAQUE_PURE", "XAIR_OP_OPAQUE_EFFECT", "XAIR_OP_CALL", "XAIR_OP_INTRINSIC"
}

macro_caps = {
    "CAP_SCALAR": {"VERIFY", "FORMAT", "CONCRETE", "EXPRESSION", "Z3", "FOLD", "TAINT", "SERIALIZE"},
    "CAP_MEMORY": {"VERIFY", "FORMAT", "CONCRETE", "EXPRESSION", "TAINT", "SERIALIZE"},
    "CAP_INCOMPLETE": {"VERIFY", "FORMAT", "CONCRETE", "EXPRESSION", "TAINT", "SERIALIZE", "EXPLICIT_INCOMPLETE"},
    "CAP_SYMBOLIC": {"VERIFY", "FORMAT", "CONCRETE", "EXPRESSION", "Z3", "TAINT", "SERIALIZE"},
    "CAP_OPAQUE_PURE": {"VERIFY", "FORMAT", "CONCRETE", "EXPRESSION", "Z3", "TAINT", "SERIALIZE", "EXPLICIT_INCOMPLETE"},
}

def missing_claims(engine_sets: dict[str, set[str]]) -> list[str]:
    failures: list[str] = []
    for opcode, macro in table_rows:
        if macro not in macro_caps:
            failures.append(f"{opcode}: unknown capability macro {macro}")
            continue
        for capability in macro_caps[macro]:
            if opcode not in engine_sets[capability]:
                failures.append(f"{opcode}: advertised {capability.lower()} engine is absent")
    return failures


missing = missing_claims(engines)
if missing:
    print("capability claims without an independent engine implementation:", file=sys.stderr)
    for item in missing:
        print("  " + item, file=sys.stderr)
    raise SystemExit(1)

# Mutation guard: the checker itself must fail closed when an independently
# implemented scalar disappears from any advertised engine.  MUL is an
# ordinary non-special opcode, so no generic representation may mask it.
for capability in ("VERIFY", "FORMAT", "CONCRETE", "EXPRESSION", "Z3", "FOLD", "SERIALIZE"):
    mutated = {name: set(opcodes) for name, opcodes in engines.items()}
    mutated[capability].discard("XAIR_OP_MUL")
    expected_failure = f"XAIR_OP_MUL: advertised {capability.lower()} engine is absent"
    if expected_failure not in missing_claims(mutated):
        raise SystemExit(f"capability checker mutation guard failed for {capability.lower()}")

# Contract-sensitive flags receive an extra parity audit.  AF for logic/shift
# must be an origin-stable Unknown, and FLAGS_SHL must carry explicit prior
# flags rather than searching unrelated live state.
semantics = (xair_root / "docs" / "semantics.md").read_text(encoding="utf-8")
if "Unknown AF with an origin tied to this operation" not in semantics or \
   "Count zero preserves prior flags and therefore requires them as input" not in semantics:
    raise SystemExit("normative flag contract text changed; capability audit needs review")
solver_extract = function_body(solver, "translate_flag_pack")
if "unknown_flag" not in solver_extract:
    raise SystemExit("symbolic flag extraction has no stable Unknown origin path")
xair_shift_builder = function_body(xair, "xair_build_shift_flags")
if "input_count = 3u" not in xair_shift_builder:
    raise SystemExit("FLAGS_SHL does not encode explicit prior flags")
sym_execute = function_body(execution, "execute_op_view")
if "op.src_count == 3" not in sym_execute or "args[2]" not in sym_execute:
    raise SystemExit("symbolic FLAGS_SHL does not consume its explicit prior-flags operand")

print(f"validated {len(table_rows)} opcodes across {len(engines)} independent engines")
