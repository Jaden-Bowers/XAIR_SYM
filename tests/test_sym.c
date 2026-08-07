#include "xair_sym/xair_sym.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void require_sym(xair_sym_status status) {
    if (status != XAIR_SYM_OK) fprintf(stderr, "unexpected symbolic status: %s\n", xair_sym_status_name(status));
    assert(status == XAIR_SYM_OK);
}

static void require_xair(xair_status status) { assert(status == XAIR_OK); }

static void test_expression_interning_and_z3_model(void) {
    xair_sym_context *context = NULL; xair_module *module = NULL; xair_sym_state *state = NULL;
    xair_exec_state *concrete_state = NULL; xair_exec_result concrete_result;
    xair_block_id block; xair_value_id value, one_value, sum_value; xair_sym_expr_id x, one, sum0, sum1, answer, condition;
    xair_sym_sat sat; uint64_t model; xair_sym_stats stats;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value));
    require_xair(xair_build_const_u64(module, block, xair_type_i(8), 1, "one", &one_value));
    require_xair(xair_build_binary(module, block, XAIR_OP_ADD, xair_type_i(8), value, one_value, "sum", &sum_value));
    require_xair(xair_set_return(module, block, &sum_value, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "x", &x)); require_sym(xair_sym_const(context, 8, 1, &one));
    require_sym(xair_sym_binary(context, XAIR_OP_ADD, 8, x, one, &sum0));
    require_sym(xair_sym_binary(context, XAIR_OP_ADD, 8, x, one, &sum1)); assert(sum0 == sum1);
    require_sym(xair_sym_const(context, 8, 42, &answer)); require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, sum0, answer, &condition));
    require_sym(xair_sym_state_assume(state, condition)); require_sym(xair_sym_check(state, XAIR_SYM_INVALID_ID, &sat)); assert(sat == XAIR_SYM_SAT);
    require_sym(xair_sym_model_u64(state, x, &model)); assert(model == 41);
    require_sym(xair_sym_model_u64(state, x, &model)); assert(model == 41);
    require_xair(xair_exec_state_create(module, &concrete_state));
    require_xair(xair_exec_set_param(concrete_state, value, xair_exec_i(8, model)));
    require_xair(xair_exec_run(module, block, concrete_state, 4, &concrete_result));
    assert(concrete_result.kind == XAIR_EXEC_HALTED_RETURN);
    assert(concrete_result.return_count == 1 && concrete_result.returns[0].lo == 42);
    xair_sym_context_stats(context, &stats); assert(stats.expressions_reused >= 1); assert(stats.solver_queries == 2);
    assert(stats.model_cache_hits == 1);
    xair_exec_state_destroy(concrete_state); xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { size_t count; unsigned seen_true; unsigned seen_false; } terminal_counts;
static xair_sym_status count_terminal(xair_sym_state *state, void *user) {
    terminal_counts *counts = (terminal_counts *)user; counts->count++;
    if (xair_sym_state_block(state) == 1) counts->seen_true = 1;
    if (xair_sym_state_block(state) == 2) counts->seen_false = 1;
    return XAIR_SYM_OK;
}

typedef struct { xair_value_id loaded; xair_sym_expr_id address; size_t count; } memory_terminal;
static xair_sym_status check_memory_terminal(xair_sym_state *state, void *user) {
    memory_terminal *terminal = (memory_terminal *)user;
    xair_sym_expr_id loaded;
    uint64_t address;
    terminal->count++;
    if (xair_sym_state_get_value(state, terminal->loaded, &loaded) != XAIR_SYM_OK) return XAIR_SYM_ERR_BAD_ARG;
    if (xair_sym_model_u64(state, terminal->address, &address) != XAIR_SYM_OK) return XAIR_SYM_ERR_SOLVER;
    return address == 0x2000 || address == 0x2001 ? XAIR_SYM_OK : XAIR_SYM_ERR_SOLVER;
}

static void test_symbolic_address_resolves_inside_object(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id memory, address_value, loaded; xair_sym_expr_id memory_token, address, a, b;
    xair_sym_object_id object; memory_terminal terminal;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_mem(0, 64), "memory", &memory));
    require_xair(xair_block_add_param(module, block, xair_type_addr(64), "address", &address_value));
    require_xair(xair_build_load(module, block, xair_type_i(8), memory, address_value, XAIR_ENDIAN_LE, "loaded", &loaded));
    require_xair(xair_set_return(module, block, &loaded, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_const(context, 1, 0, &memory_token)); require_sym(xair_sym_symbol(context, 64, "address", &address));
    require_sym(xair_sym_const(context, 8, 0x11, &a)); require_sym(xair_sym_const(context, 8, 0x22, &b));
    require_sym(xair_sym_state_set_value(state, memory, memory_token)); require_sym(xair_sym_state_set_value(state, address_value, address));
    require_sym(xair_sym_object_add(state, 0x2000, 2, 3, &object));
    require_sym(xair_sym_memory_store8(state, 0x2000, a)); require_sym(xair_sym_memory_store8(state, 0x2001, b));
    terminal.loaded = loaded; terminal.address = address; terminal.count = 0;
    require_sym(xair_sym_explore(state, 4, 4, check_memory_terminal, &terminal)); assert(terminal.count == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_symbolic_xair_branch_explores_both_paths(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id entry, low, high; xair_value_id x, ten, condition; xair_sym_expr_id symbol; terminal_counts counts;
    xair_sym_explore_options options; xair_sym_stats stats;
    memset(&counts, 0, sizeof(counts)); require_xair(xair_module_create(&module));
    require_xair(xair_block_create(module, "entry", &entry)); require_xair(xair_block_create(module, "low", &low)); require_xair(xair_block_create(module, "high", &high));
    require_xair(xair_block_add_param(module, entry, xair_type_i(8), "x", &x));
    require_xair(xair_build_const_u64(module, entry, xair_type_i(8), 10, "ten", &ten));
    require_xair(xair_build_binary(module, entry, XAIR_OP_ULT, xair_type_i(1), x, ten, "condition", &condition));
    require_xair(xair_set_cbranch(module, entry, condition, low, NULL, 0, high, NULL, 0));
    require_xair(xair_set_return(module, low, NULL, 0)); require_xair(xair_set_return(module, high, NULL, 0));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, entry, &state));
    require_sym(xair_sym_symbol(context, 8, "input", &symbol)); require_sym(xair_sym_state_set_value(state, x, symbol));
    require_sym(xair_sym_explore(state, 16, 16, count_terminal, &counts));
    assert(counts.count == 2); assert(counts.seen_true && counts.seen_false);
    memset(&counts, 0, sizeof(counts)); xair_sym_explore_options_init(&options);
    options.execution_mode = XAIR_SYM_EXEC_HYBRID_CONCRETIZE; options.max_symbolic_forks = 0;
    options.max_states = 8; options.max_block_steps = 8;
    require_sym(xair_sym_explore_with_options(state, &options, count_terminal, &counts)); assert(counts.count == 1);
    xair_sym_context_stats(context, &stats); assert(stats.concretizations == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_lazy_zero_flag_forks_symbolically(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id entry, zero_block, nonzero_block; xair_value_id x, flags, zf; xair_sym_expr_id symbol; terminal_counts counts;
    memset(&counts, 0, sizeof(counts)); require_xair(xair_module_create(&module));
    require_xair(xair_block_create(module, "entry", &entry));
    require_xair(xair_block_create(module, "zero", &zero_block));
    require_xair(xair_block_create(module, "nonzero", &nonzero_block));
    require_xair(xair_block_add_param(module, entry, xair_type_i(8), "x", &x));
    require_xair(xair_build_unary(module, entry, XAIR_OP_FLAGS_LOGIC, xair_type_flags(6), x, "flags", &flags));
    require_xair(xair_build_unary(module, entry, XAIR_OP_FLAG_ZF, xair_type_i(1), flags, "zf", &zf));
    require_xair(xair_set_cbranch(module, entry, zf, zero_block, NULL, 0, nonzero_block, NULL, 0));
    require_xair(xair_set_return(module, zero_block, NULL, 0)); require_xair(xair_set_return(module, nonzero_block, NULL, 0));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, entry, &state));
    require_sym(xair_sym_symbol(context, 8, "flag_input", &symbol)); require_sym(xair_sym_state_set_value(state, x, symbol));
    require_sym(xair_sym_explore(state, 8, 8, count_terminal, &counts));
    assert(counts.count == 2); assert(counts.seen_true && counts.seen_false);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_object_memory_is_copy_on_write(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL; xair_sym_state *clone = NULL;
    xair_block_id block; xair_value_id value; xair_sym_expr_id a, b, loaded; xair_sym_object_id object; xair_sym_stats stats;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value)); require_xair(xair_set_return(module, block, &value, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_const(context, 8, 0xaa, &a)); require_sym(xair_sym_const(context, 8, 0xbb, &b));
    require_sym(xair_sym_object_add(state, 0x1000, 16, 3, &object)); assert(object == 0);
    require_sym(xair_sym_memory_store8(state, 0x1004, a)); require_sym(xair_sym_state_clone(state, &clone));
    require_sym(xair_sym_memory_store8(clone, 0x1004, b)); require_sym(xair_sym_memory_load8(state, 0x1004, &loaded)); assert(loaded == a);
    require_sym(xair_sym_memory_load8(clone, 0x1004, &loaded)); assert(loaded == b);
    xair_sym_context_stats(context, &stats); assert(stats.memory_cow_copies == 1);
    xair_sym_state_destroy(clone); xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { xair_value_id value; xair_sym_taint_id expected; size_t count; } taint_terminal;
static xair_sym_status check_taint_terminal(xair_sym_state *state, void *user) {
    taint_terminal *terminal = (taint_terminal *)user;
    xair_sym_taint_id taint;
    terminal->count++;
    if (xair_sym_state_get_taint(state, terminal->value, &taint) != XAIR_SYM_OK) return XAIR_SYM_ERR_BAD_ARG;
    return taint == terminal->expected ? XAIR_SYM_OK : XAIR_SYM_ERR_RANGE;
}

static void test_taint_propagates_and_interns_provenance(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id lhs, rhs, sum; xair_sym_expr_id a, b;
    xair_sym_taint_id source_a, source_b, combined0, combined1, sanitized0, sanitized1;
    taint_terminal terminal; xair_sym_stats stats; xair_sym_taint_view provenance;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "lhs", &lhs));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "rhs", &rhs));
    require_xair(xair_build_binary(module, block, XAIR_OP_ADD, xair_type_i(8), lhs, rhs, "sum", &sum));
    require_xair(xair_set_return(module, block, &sum, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "a", &a)); require_sym(xair_sym_symbol(context, 8, "b", &b));
    require_sym(xair_sym_taint_source(context, "network", &source_a)); require_sym(xair_sym_taint_source(context, "file", &source_b));
    require_sym(xair_sym_taint_union(context, source_a, source_b, &combined0));
    require_sym(xair_sym_taint_union(context, source_b, source_a, &combined1)); assert(combined0 == combined1);
    require_sym(xair_sym_taint_sanitize(context, combined0, "bounds_checked", &sanitized0));
    require_sym(xair_sym_taint_sanitize(context, combined0, "bounds_checked", &sanitized1)); assert(sanitized0 == sanitized1);
    require_sym(xair_sym_taint_get(context, sanitized0, &provenance));
    assert(provenance.kind == XAIR_SYM_TAINT_NODE_SANITIZER && provenance.lhs == combined0);
    assert(strcmp(provenance.name, "bounds_checked") == 0);
    require_sym(xair_sym_state_set_value(state, lhs, a)); require_sym(xair_sym_state_set_value(state, rhs, b));
    require_sym(xair_sym_state_set_taint(state, lhs, source_a)); require_sym(xair_sym_state_set_taint(state, rhs, source_b));
    terminal.value = sum; terminal.expected = combined0; terminal.count = 0;
    require_sym(xair_sym_explore(state, 4, 4, check_taint_terminal, &terminal)); assert(terminal.count == 1);
    xair_sym_context_stats(context, &stats); assert(stats.taint_nodes == 4); assert(stats.taint_nodes_reused >= 2);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_memory_taint_is_copy_on_write(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL; xair_sym_state *clone = NULL;
    xair_block_id block; xair_value_id value; xair_sym_object_id object; xair_sym_taint_id source, loaded;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value)); require_xair(xair_set_return(module, block, &value, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_taint_source(context, "stdin", &source)); require_sym(xair_sym_object_add(state, 0x3000, 4, 3, &object));
    require_sym(xair_sym_state_clone(state, &clone)); require_sym(xair_sym_memory_store_taint8(clone, 0x3001, source));
    require_sym(xair_sym_memory_load_taint8(state, 0x3001, &loaded)); assert(loaded == XAIR_SYM_TAINT_NONE);
    require_sym(xair_sym_memory_load_taint8(clone, 0x3001, &loaded)); assert(loaded == source);
    xair_sym_state_destroy(clone); xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_targeted_implicit_select_taint(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id condition_value, true_value, false_value, selected;
    xair_sym_expr_id condition, a, b; xair_sym_taint_id control_source; taint_terminal terminal;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(1), "condition", &condition_value));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "true_value", &true_value));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "false_value", &false_value));
    require_xair(xair_build_select(module, block, condition_value, true_value, false_value, "selected", &selected));
    require_xair(xair_set_return(module, block, &selected, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 1, "tainted_condition", &condition));
    require_sym(xair_sym_const(context, 8, 1, &a)); require_sym(xair_sym_const(context, 8, 2, &b));
    require_sym(xair_sym_taint_source(context, "control", &control_source));
    require_sym(xair_sym_state_set_value(state, condition_value, condition));
    require_sym(xair_sym_state_set_value(state, true_value, a)); require_sym(xair_sym_state_set_value(state, false_value, b));
    require_sym(xair_sym_state_set_taint(state, condition_value, control_source));
    terminal.value = selected; terminal.expected = XAIR_SYM_TAINT_NONE; terminal.count = 0;
    require_sym(xair_sym_explore(state, 4, 4, check_taint_terminal, &terminal)); assert(terminal.count == 1);
    xair_sym_context_set_taint_mode(context, XAIR_SYM_TAINT_TARGETED_IMPLICIT);
    terminal.expected = control_source; terminal.count = 0;
    require_sym(xair_sym_explore(state, 4, 4, check_taint_terminal, &terminal)); assert(terminal.count == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { xair_value_id true_value; xair_value_id false_value; xair_sym_taint_id expected; size_t count; } strict_terminal;
static xair_sym_status check_strict_terminal(xair_sym_state *state, void *user) {
    strict_terminal *terminal = (strict_terminal *)user;
    xair_value_id value = xair_sym_state_block(state) == 1 ? terminal->true_value : terminal->false_value;
    xair_sym_taint_id taint;
    terminal->count++;
    if (xair_sym_state_get_taint(state, value, &taint) != XAIR_SYM_OK) return XAIR_SYM_ERR_BAD_ARG;
    return taint == terminal->expected ? XAIR_SYM_OK : XAIR_SYM_ERR_RANGE;
}

static void test_strict_implicit_branch_taint(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id entry, true_block, false_block; xair_value_id condition_value, true_result, false_result;
    xair_sym_expr_id condition; xair_sym_taint_id source; strict_terminal terminal;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &entry));
    require_xair(xair_block_create(module, "true", &true_block)); require_xair(xair_block_create(module, "false", &false_block));
    require_xair(xair_block_add_param(module, entry, xair_type_i(1), "condition", &condition_value));
    require_xair(xair_set_cbranch(module, entry, condition_value, true_block, NULL, 0, false_block, NULL, 0));
    require_xair(xair_build_const_u64(module, true_block, xair_type_i(8), 1, "true_result", &true_result));
    require_xair(xair_set_return(module, true_block, &true_result, 1));
    require_xair(xair_build_const_u64(module, false_block, xair_type_i(8), 2, "false_result", &false_result));
    require_xair(xair_set_return(module, false_block, &false_result, 1));
    require_sym(xair_sym_context_create(&context)); xair_sym_context_set_taint_mode(context, XAIR_SYM_TAINT_STRICT_IMPLICIT);
    require_sym(xair_sym_state_create(context, module, entry, &state)); require_sym(xair_sym_symbol(context, 1, "strict_condition", &condition));
    require_sym(xair_sym_taint_source(context, "secret", &source)); require_sym(xair_sym_state_set_value(state, condition_value, condition));
    require_sym(xair_sym_state_set_taint(state, condition_value, source));
    terminal.true_value = true_result; terminal.false_value = false_result; terminal.expected = source; terminal.count = 0;
    require_sym(xair_sym_explore(state, 8, 8, check_strict_terminal, &terminal)); assert(terminal.count == 2);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_constraint_slicing_and_exact_query_cache(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id value; xair_sym_expr_id x, y, one, two, x_eq, y_eq; xair_sym_sat sat; xair_sym_stats stats;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value)); require_xair(xair_set_return(module, block, &value, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "slice_x", &x)); require_sym(xair_sym_symbol(context, 8, "slice_y", &y));
    require_sym(xair_sym_const(context, 8, 1, &one)); require_sym(xair_sym_const(context, 8, 2, &two));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, x, one, &x_eq)); require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, y, two, &y_eq));
    require_sym(xair_sym_state_assume(state, x_eq)); require_sym(xair_sym_state_assume(state, y_eq));
    require_sym(xair_sym_check(state, x_eq, &sat)); assert(sat == XAIR_SYM_SAT);
    require_sym(xair_sym_check(state, x_eq, &sat)); assert(sat == XAIR_SYM_SAT);
    xair_sym_context_stats(context, &stats); assert(stats.solver_queries == 1); assert(stats.solver_cache_hits == 1);
    assert(stats.constraints_submitted == 1); assert(stats.constraints_sliced == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { xair_block_id first; size_t count; } order_terminal;
static xair_sym_status record_order(xair_sym_state *state, void *user) {
    order_terminal *order = (order_terminal *)user;
    if (order->count == 0) order->first = xair_sym_state_block(state);
    order->count++;
    return XAIR_SYM_OK;
}

static void test_dfs_policy_and_loop_budget(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id entry, true_block, false_block;
    xair_value_id condition_value, loop_value, one_value, next_value;
    xair_sym_expr_id condition, zero;
    xair_sym_explore_options options; order_terminal order; xair_sym_stats stats;
    xair_analysis_result result; xair_diagnostic diagnostic;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &entry));
    require_xair(xair_block_create(module, "true", &true_block)); require_xair(xair_block_create(module, "false", &false_block));
    require_xair(xair_block_add_param(module, entry, xair_type_i(1), "condition", &condition_value));
    require_xair(xair_set_cbranch(module, entry, condition_value, true_block, NULL, 0, false_block, NULL, 0));
    require_xair(xair_set_return(module, true_block, NULL, 0)); require_xair(xair_set_return(module, false_block, NULL, 0));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, entry, &state));
    require_sym(xair_sym_symbol(context, 1, "schedule_condition", &condition)); require_sym(xair_sym_state_set_value(state, condition_value, condition));
    xair_sym_explore_options_init(&options); options.search = XAIR_SYM_SEARCH_DFS; options.max_states = 8; options.max_block_steps = 8;
    order.first = XAIR_INVALID_ID; order.count = 0; require_sym(xair_sym_explore_with_options(state, &options, record_order, &order));
    assert(order.count == 2 && order.first == false_block);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);

    module = NULL; context = NULL; state = NULL;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "loop", &entry));
    require_xair(xair_block_add_param(module, entry, xair_type_i(8), "loop_value", &loop_value));
    require_xair(xair_build_const_u64(module, entry, xair_type_i(8), 1, "one", &one_value));
    require_xair(xair_build_binary(module, entry, XAIR_OP_ADD, xair_type_i(8),
        loop_value, one_value, "next", &next_value));
    require_xair(xair_set_jump(module, entry, entry, &next_value, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, entry, &state));
    require_sym(xair_sym_const(context, 8, 0, &zero));
    require_sym(xair_sym_state_set_value(state, loop_value, zero));
    xair_sym_explore_options_init(&options); options.max_states = 16; options.max_block_steps = 16; options.max_visits_per_block = 2;
    assert(xair_sym_explore_with_options_ex(state, &options, NULL, NULL, &result, &diagnostic) ==
        XAIR_SYM_ERR_RESOURCE_LIMIT);
    assert(result.state == XAIR_ANALYSIS_LIMITED);
    assert(diagnostic.status == XAIR_ERR_RESOURCE_LIMIT);
    assert(diagnostic.stage == XAIR_STAGE_SYMBOLIC);
    xair_sym_context_stats(context, &stats);
    assert(stats.scheduler_pruned == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_concolic_inversion_and_testcase_exchange(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *base = NULL; xair_sym_state *inverted = NULL;
    xair_sym_trace *trace = NULL; xair_block_id block; xair_value_id value; xair_sym_expr_id x, answer, condition;
    uint64_t model; uint8_t generated[1], loaded[1]; size_t loaded_size; const char *path = "xair_sym_testcase.bin";
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value)); require_xair(xair_set_return(module, block, &value, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &base));
    require_sym(xair_sym_symbol(context, 8, "concolic_x", &x)); require_sym(xair_sym_const(context, 8, 42, &answer));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, x, answer, &condition)); require_sym(xair_sym_trace_create(&trace));
    require_sym(xair_sym_trace_add_branch(trace, block, condition, 0)); assert(xair_sym_trace_count(trace) == 1);
    require_sym(xair_sym_concolic_invert(base, trace, 0, &inverted)); require_sym(xair_sym_model_u64(inverted, x, &model)); assert(model == 42);
    require_sym(xair_sym_model_bytes(inverted, &x, 1, generated)); assert(generated[0] == 42);
    remove(path); require_sym(xair_sym_testcase_write(path, generated, sizeof(generated)));
    require_sym(xair_sym_testcase_read(path, loaded, sizeof(loaded), &loaded_size)); remove(path);
    assert(loaded_size == 1 && loaded[0] == 42);
    xair_sym_state_destroy(inverted); xair_sym_trace_destroy(trace); xair_sym_state_destroy(base);
    xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_process_environment_and_models(void) {
    static uint8_t code[] = {
        0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc3
    };
    xair_binary_segment segment; xair_binary_view binary; xair_cfg_options cfg_options; xair_cfg_builder *builder = NULL;
    xair_cfg *cfg = NULL; xair_cfg_stats cfg_stats; xair_error error; xair_sym_context *context = NULL;
    xair_sym_environment *environment = NULL; xair_sym_state *state = NULL; xair_sym_process_options process_options;
    xair_sym_expr_id code_byte, symbols[4], copied; xair_sym_taint_id source_taint, copied_taint;
    xair_sym_model_kind kind; xair_sym_model_info model_info; uint64_t input_buffer, copy_buffer;
    memset(&segment, 0, sizeof(segment)); segment.va = 0x1000; segment.mem_size = sizeof(code);
    segment.file_size = sizeof(code); segment.perms = XAIR_BINARY_PERM_READ | XAIR_BINARY_PERM_EXEC; segment.bytes = code;
    memset(&binary, 0, sizeof(binary)); binary.format = XAIR_BINARY_FORMAT_ELF; binary.arch = XAIR_ARCH_X86_64;
    binary.entry = 0x1000; binary.image_base = 0x1000; binary.segments = &segment; binary.segment_count = 1;
    xair_cfg_options_init(&cfg_options, XAIR_CFG_PROFILE_BALANCED); cfg_options.entry = binary.entry;
    require_xair(xair_cfg_builder_create(&binary, &cfg_options, &builder)); require_xair(xair_cfg_add_root(builder, binary.entry));
    require_xair(xair_cfg_build(builder, &cfg, &cfg_stats, &error)); xair_cfg_builder_destroy(builder);
    require_sym(xair_sym_context_create(&context)); xair_sym_process_options_init(&process_options, binary.arch);
    process_options.stack_size = 4096; process_options.max_segment_size = 4096;
    require_sym(xair_sym_process_create(context, cfg, &binary, &process_options, &environment, &state));
    require_sym(xair_sym_memory_load8(state, 0x1000, &code_byte));
    require_sym(xair_sym_environment_model(environment, "read", &kind)); assert(kind == XAIR_SYM_MODEL_INPUT);
    require_sym(xair_sym_environment_model(environment, "ExAllocatePoolWithTag", &kind)); assert(kind == XAIR_SYM_MODEL_ALLOC);
    require_sym(xair_sym_environment_model_info(environment, "ProbeForRead", &model_info));
    assert(model_info.kind == XAIR_SYM_MODEL_DRIVER_INPUT && model_info.version_major == 1);
    require_sym(xair_sym_environment_allocate(environment, state, 16, &input_buffer));
    require_sym(xair_sym_environment_allocate(environment, state, 16, &copy_buffer));
    require_sym(xair_sym_environment_input(environment, state, input_buffer, 4, "network", symbols));
    require_sym(xair_sym_environment_copy(environment, state, copy_buffer, input_buffer, 4));
    require_sym(xair_sym_memory_load8(state, copy_buffer + 2, &copied)); assert(copied == symbols[2]);
    require_sym(xair_sym_memory_load_taint8(state, input_buffer, &source_taint));
    require_sym(xair_sym_memory_load_taint8(state, copy_buffer + 2, &copied_taint)); assert(copied_taint == source_taint);
    xair_sym_state_destroy(state); xair_sym_environment_destroy(environment); xair_sym_context_destroy(context); xair_cfg_destroy(cfg);
}

static void test_snapshot_roundtrip_preserves_state(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_sym_state *restored = NULL; xair_sym_snapshot *snapshot = NULL; xair_sym_snapshot *loaded_snapshot = NULL;
    xair_block_id block; xair_value_id value; xair_sym_expr_id symbol, byte, loaded_byte; xair_sym_taint_id taint, loaded_taint;
    xair_sym_object_id object; uint64_t model; const char *path = "xair_sym_snapshot.bin";
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value)); require_xair(xair_set_return(module, block, &value, 1));
    require_xair(xair_module_freeze(module)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state)); require_sym(xair_sym_symbol(context, 8, "snapshot_value", &symbol));
    require_sym(xair_sym_const(context, 8, 0x5a, &byte)); require_sym(xair_sym_taint_source(context, "snapshot_source", &taint));
    require_sym(xair_sym_state_set_value(state, value, symbol)); require_sym(xair_sym_state_set_taint(state, value, taint));
    require_sym(xair_sym_object_add(state, 0x4000, 4, 3, &object)); require_sym(xair_sym_memory_store8(state, 0x4001, byte));
    require_sym(xair_sym_memory_store_taint8(state, 0x4001, taint)); require_sym(xair_sym_snapshot_take(state, &snapshot));
    require_sym(xair_sym_snapshot_restore(snapshot, &restored)); require_sym(xair_sym_memory_load8(restored, 0x4001, &loaded_byte));
    require_sym(xair_sym_memory_load_taint8(restored, 0x4001, &loaded_taint)); assert(loaded_byte == byte && loaded_taint == taint);
    xair_sym_state_destroy(restored); restored = NULL;
    remove(path); require_sym(xair_sym_snapshot_save(snapshot, path));
    require_sym(xair_sym_snapshot_load(context, module, path, &loaded_snapshot)); remove(path);
    require_sym(xair_sym_snapshot_restore(loaded_snapshot, &restored)); require_sym(xair_sym_model_u64(restored, symbol, &model));
    assert(model <= 255); require_sym(xair_sym_state_get_taint(restored, value, &loaded_taint)); assert(loaded_taint == taint);
    xair_sym_state_destroy(restored); xair_sym_snapshot_destroy(loaded_snapshot); xair_sym_snapshot_destroy(snapshot);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_compiled_dispatch_and_cancellation(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL; xair_sym_program *program = NULL;
    xair_block_id block; xair_value_id value, one, sum; xair_sym_expr_id symbol; terminal_counts counts; xair_sym_stats stats;
    xair_sym_cancel_token *token = NULL; xair_sym_explore_options options;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value));
    require_xair(xair_build_const_u64(module, block, xair_type_i(8), 1, "one", &one));
    require_xair(xair_build_binary(module, block, XAIR_OP_ADD, xair_type_i(8), value, one, "sum", &sum));
    require_xair(xair_set_return(module, block, &sum, 1)); require_xair(xair_module_freeze(module));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "compiled_input", &symbol)); require_sym(xair_sym_state_set_value(state, value, symbol));
    require_sym(xair_sym_program_compile(module, &program)); require_sym(xair_sym_state_attach_program(state, program));
    memset(&counts, 0, sizeof(counts)); require_sym(xair_sym_explore(state, 4, 4, count_terminal, &counts)); assert(counts.count == 1);
    xair_sym_context_stats(context, &stats); assert(stats.compiled_dispatches == 1);
    require_sym(xair_sym_cancel_token_create(&token)); xair_sym_cancel_token_request(token);
    xair_sym_explore_options_init(&options); options.cancel_token = token; counts.count = 0;
    {
        xair_analysis_result result;
        xair_diagnostic diagnostic;
        assert(xair_sym_explore_with_options_ex(state, &options, count_terminal, &counts,
            &result, &diagnostic) == XAIR_SYM_ERR_CANCELED);
        assert(result.state == XAIR_ANALYSIS_CANCELED);
        assert(diagnostic.status == XAIR_ERR_CANCELED);
        assert(diagnostic.stage == XAIR_STAGE_SYMBOLIC);
    }
    assert(counts.count == 0);
    assert(xair_sym_cancel_token_requested(token)); xair_sym_cancel_token_reset(token); assert(!xair_sym_cancel_token_requested(token));
    xair_sym_cancel_token_destroy(token); xair_sym_program_destroy(program); xair_sym_state_destroy(state);
    xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_parallel_isolated_workers(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL; xair_sym_snapshot *snapshot = NULL;
    xair_block_id entry, left, right; xair_value_id condition_value; xair_sym_expr_id condition;
    xair_sym_parallel_options options; terminal_counts counts;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &entry));
    require_xair(xair_block_create(module, "left", &left)); require_xair(xair_block_create(module, "right", &right));
    require_xair(xair_block_add_param(module, entry, xair_type_i(1), "condition", &condition_value));
    require_xair(xair_set_cbranch(module, entry, condition_value, left, NULL, 0, right, NULL, 0));
    require_xair(xair_set_return(module, left, NULL, 0)); require_xair(xair_set_return(module, right, NULL, 0));
    require_xair(xair_module_freeze(module)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, entry, &state)); require_sym(xair_sym_symbol(context, 1, "parallel_condition", &condition));
    require_sym(xair_sym_state_set_value(state, condition_value, condition)); require_sym(xair_sym_snapshot_take(state, &snapshot));
    xair_sym_parallel_options_init(&options); options.workers = 2; options.explore.max_states = 8; options.explore.max_block_steps = 8;
    memset(&counts, 0, sizeof(counts)); require_sym(xair_sym_parallel_explore(snapshot, &options, count_terminal, &counts));
    assert(counts.count == 4);
    xair_sym_snapshot_destroy(snapshot); xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_symbolic_and_taint_names_are_not_truncated(void) {
    static const char symbol_name[] =
        "symbolic_variable_name_that_is_longer_than_the_previous_forty_eight_character_limit_and_must_survive";
    static const char taint_name[] =
        "taint_source_name_that_is_longer_than_the_previous_forty_eight_character_limit_and_must_survive";
    xair_sym_context *context = NULL;
    xair_sym_expr_id expression;
    xair_sym_expr_view expression_view;
    xair_sym_taint_id taint;
    xair_sym_taint_view taint_view;
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_symbol(context, 64, symbol_name, &expression));
    require_sym(xair_sym_expr_get(context, expression, &expression_view));
    assert(strcmp(expression_view.symbol, symbol_name) == 0);
    require_sym(xair_sym_taint_source(context, taint_name, &taint));
    require_sym(xair_sym_taint_get(context, taint, &taint_view));
    assert(strcmp(taint_view.name, taint_name) == 0);
    xair_sym_context_destroy(context);
}

static void test_solver_cancellation_reports_diagnostic(void) {
    xair_module *module = NULL;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_cancel_token *token = NULL;
    xair_analysis_options options;
    xair_diagnostic diagnostic;
    xair_sym_sat sat = XAIR_SYM_UNKNOWN;
    xair_block_id block;

    require_xair(xair_module_create(&module));
    require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_set_return(module, block, NULL, 0));
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_xair(xair_cancel_token_create(&token));
    xair_cancel_token_request(token);
    xair_analysis_options_init(&options);
    options.cancel_token = token;
    xair_sym_context_set_analysis_options(context, &options);
    assert(xair_sym_check_ex(state, XAIR_SYM_INVALID_ID, &sat, &diagnostic) == XAIR_SYM_ERR_CANCELED);
    assert(diagnostic.status == XAIR_ERR_CANCELED);
    assert(diagnostic.stage == XAIR_STAGE_SOLVER);
    assert(diagnostic.block == block);
    xair_cancel_token_destroy(token);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
}

int main(void) {
    test_solver_cancellation_reports_diagnostic();
    test_symbolic_and_taint_names_are_not_truncated();
    test_expression_interning_and_z3_model();
    test_symbolic_xair_branch_explores_both_paths();
    test_lazy_zero_flag_forks_symbolically();
    test_object_memory_is_copy_on_write();
    test_symbolic_address_resolves_inside_object();
    test_taint_propagates_and_interns_provenance();
    test_memory_taint_is_copy_on_write();
    test_targeted_implicit_select_taint();
    test_strict_implicit_branch_taint();
    test_constraint_slicing_and_exact_query_cache();
    test_dfs_policy_and_loop_budget();
    test_concolic_inversion_and_testcase_exchange();
    test_process_environment_and_models();
    test_snapshot_roundtrip_preserves_state();
    test_compiled_dispatch_and_cancellation();
    test_parallel_isolated_workers();
    return 0;
}
