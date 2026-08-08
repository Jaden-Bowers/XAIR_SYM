#include "xair_sym/xair_sym.h"
#include "../src/xair_sym_internal.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require_sym_at(xair_sym_status status, int line) {
    if (status != XAIR_SYM_OK) fprintf(stderr, "unexpected symbolic status at line %d: %s\n", line, xair_sym_status_name(status));
    assert(status == XAIR_SYM_OK);
}
#define require_sym(status) require_sym_at((status), __LINE__)

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
    xair_block_id block; xair_value_id memory, address_value, loaded; xair_sym_expr_id address, a, b;
    xair_sym_object_id object; memory_terminal terminal;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_mem(0, 64), "memory", &memory));
    require_xair(xair_block_add_param(module, block, xair_type_addr(64), "address", &address_value));
    require_xair(xair_build_load(module, block, xair_type_i(8), memory, address_value, XAIR_ENDIAN_LE, "loaded", &loaded));
    require_xair(xair_set_return(module, block, &loaded, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 64, "address", &address));
    require_sym(xair_sym_const(context, 8, 0x11, &a)); require_sym(xair_sym_const(context, 8, 0x22, &b));
    require_sym(xair_sym_state_set_value(state, address_value, address));
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

static void test_phase6_shift_flags_without_prior_flags_are_explicitly_incomplete(void) {
    xair_module *module = NULL;
    xair_block_id block; xair_value_id value, count, flags;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "shift_flags", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "count", &count));
    assert(xair_build_binary(module, block, XAIR_OP_FLAGS_SHL, xair_type_flags(6),
        value, count, "flags", &flags) == XAIR_ERR_BAD_ARG);
    xair_module_destroy(module);
}

typedef struct { xair_value_id af; size_t calls; } preserved_flag_terminal;
static xair_sym_status check_preserved_shift_flag(xair_sym_state *state, void *user) {
    preserved_flag_terminal *terminal = (preserved_flag_terminal *)user;
    xair_sym_expr_id expression; uint64_t value;
    terminal->calls++;
    if (xair_sym_state_get_value(state, terminal->af, &expression) != XAIR_SYM_OK ||
        xair_sym_model_u64(state, expression, &value) != XAIR_SYM_OK || value != 1u)
        return XAIR_SYM_ERR_INTERNAL;
    return XAIR_SYM_OK;
}

static void test_phase6_zero_count_shift_preserves_prior_flags(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id prior, unrelated, value, count, shifted, af;
    xair_sym_expr_id lhs, rhs, prior_expr, unrelated_expr, value_expr, count_expr;
    xair_sym_explore_options options; xair_sym_explore_result result; xair_diagnostic diagnostic;
    preserved_flag_terminal terminal;
    memset(&terminal, 0, sizeof(terminal));
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "preserve_shift_flags", &block));
    require_xair(xair_block_add_param(module, block, xair_type_flags(6), "prior_flags", &prior));
    require_xair(xair_block_add_param(module, block, xair_type_flags(6), "unrelated_flags", &unrelated));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "count", &count));
    require_xair(xair_build_shift_flags(module, block, value, count, prior, "flags", &shifted));
    require_xair(xair_build_unary(module, block, XAIR_OP_FLAG_AF, xair_type_i(1), shifted, "af", &af));
    require_xair(xair_set_return(module, block, &af, 1)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_const(context, 8, 0x0f, &lhs)); require_sym(xair_sym_const(context, 8, 1, &rhs));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_ADD, 6, lhs, rhs, &prior_expr));
    require_sym(xair_sym_const(context, 8, 0, &lhs)); require_sym(xair_sym_const(context, 8, 0, &rhs));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_ADD, 6, lhs, rhs, &unrelated_expr));
    require_sym(xair_sym_const(context, 8, 0x81, &value_expr)); require_sym(xair_sym_const(context, 8, 0, &count_expr));
    require_sym(xair_sym_state_set_value(state, prior, prior_expr));
    require_sym(xair_sym_state_set_value(state, unrelated, unrelated_expr));
    require_sym(xair_sym_state_set_value(state, value, value_expr));
    require_sym(xair_sym_state_set_value(state, count, count_expr)); terminal.af = af;
    xair_sym_explore_options_init(&options); options.max_states = 4; options.max_block_steps = 4;
    require_sym(xair_sym_explore_detailed(state, &options, check_preserved_shift_flag,
        &terminal, &result, &diagnostic));
    assert(terminal.calls == 1 && result.completion_reason == XAIR_SYM_COMPLETED && result.unresolved_operations == 0);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct {
    xair_sym_context *context;
    xair_value_id count;
    xair_value_id zf;
    size_t calls;
} symbolic_shift_terminal;

static xair_sym_status check_symbolic_shift_prior_select(xair_sym_state *state, void *user) {
    symbolic_shift_terminal *terminal = (symbolic_shift_terminal *)user;
    xair_sym_expr_id count, zf, zero8, one8, zero1, one1;
    xair_sym_expr_id count_zero, count_one, zf_zero, zf_one, query;
    xair_sym_sat sat;
    terminal->calls++;
    if (xair_sym_state_get_value(state, terminal->count, &count) != XAIR_SYM_OK ||
        xair_sym_state_get_value(state, terminal->zf, &zf) != XAIR_SYM_OK ||
        xair_sym_const(terminal->context, 8, 0, &zero8) != XAIR_SYM_OK ||
        xair_sym_const(terminal->context, 8, 1, &one8) != XAIR_SYM_OK ||
        xair_sym_const(terminal->context, 1, 0, &zero1) != XAIR_SYM_OK ||
        xair_sym_const(terminal->context, 1, 1, &one1) != XAIR_SYM_OK) return XAIR_SYM_ERR_INTERNAL;
    if (xair_sym_binary(terminal->context, XAIR_OP_EQ, 1, count, zero8, &count_zero) != XAIR_SYM_OK ||
        xair_sym_binary(terminal->context, XAIR_OP_EQ, 1, count, one8, &count_one) != XAIR_SYM_OK ||
        xair_sym_binary(terminal->context, XAIR_OP_EQ, 1, zf, zero1, &zf_zero) != XAIR_SYM_OK ||
        xair_sym_binary(terminal->context, XAIR_OP_EQ, 1, zf, one1, &zf_one) != XAIR_SYM_OK)
        return XAIR_SYM_ERR_INTERNAL;
    if (xair_sym_binary(terminal->context, XAIR_OP_AND, 1, count_zero, zf_zero, &query) != XAIR_SYM_OK ||
        xair_sym_check(state, query, &sat) != XAIR_SYM_OK || sat != XAIR_SYM_SAT)
        return XAIR_SYM_ERR_SOLVER;
    if (xair_sym_binary(terminal->context, XAIR_OP_AND, 1, count_zero, zf_one, &query) != XAIR_SYM_OK ||
        xair_sym_check(state, query, &sat) != XAIR_SYM_OK || sat != XAIR_SYM_UNSAT)
        return XAIR_SYM_ERR_SOLVER;
    if (xair_sym_binary(terminal->context, XAIR_OP_AND, 1, count_one, zf_one, &query) != XAIR_SYM_OK ||
        xair_sym_check(state, query, &sat) != XAIR_SYM_OK || sat != XAIR_SYM_SAT)
        return XAIR_SYM_ERR_SOLVER;
    return XAIR_SYM_OK;
}

static void test_phase6_symbolic_shift_count_selects_explicit_prior_flags(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id prior, value, count, shifted, zf;
    xair_sym_expr_id lhs, rhs, prior_expr, value_expr, count_expr;
    symbolic_shift_terminal terminal;
    memset(&terminal, 0, sizeof(terminal));
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "symbolic_shift", &block));
    require_xair(xair_block_add_param(module, block, xair_type_flags(6), "prior", &prior));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "count", &count));
    require_xair(xair_build_shift_flags(module, block, value, count, prior, "flags", &shifted));
    require_xair(xair_build_unary(module, block, XAIR_OP_FLAG_ZF, xair_type_i(1), shifted, "zf", &zf));
    require_xair(xair_set_return(module, block, &zf, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_const(context, 8, 0x0f, &lhs)); require_sym(xair_sym_const(context, 8, 1, &rhs));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_ADD, 6, lhs, rhs, &prior_expr));
    require_sym(xair_sym_const(context, 8, 0x80, &value_expr));
    require_sym(xair_sym_symbol(context, 8, "symbolic_shift_count", &count_expr));
    require_sym(xair_sym_state_set_value(state, prior, prior_expr));
    require_sym(xair_sym_state_set_value(state, value, value_expr));
    require_sym(xair_sym_state_set_value(state, count, count_expr));
    terminal.context = context; terminal.count = count; terminal.zf = zf;
    require_sym(xair_sym_explore(state, 4, 4, check_symbolic_shift_prior_select, &terminal));
    assert(terminal.calls == 1);
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

typedef struct { xair_sym_context *context; xair_value_id value; xair_sym_taint_id expected; const char *transform; size_t count; } taint_terminal;
static xair_sym_status check_taint_terminal(xair_sym_state *state, void *user) {
    taint_terminal *terminal = (taint_terminal *)user;
    xair_sym_taint_id taint;
    xair_sym_taint_view view;
    terminal->count++;
    if (xair_sym_state_get_taint(state, terminal->value, &taint) != XAIR_SYM_OK) return XAIR_SYM_ERR_BAD_ARG;
    if (terminal->transform == NULL) return taint == terminal->expected ? XAIR_SYM_OK : XAIR_SYM_ERR_RANGE;
    if (xair_sym_taint_get(terminal->context, taint, &view) != XAIR_SYM_OK) return XAIR_SYM_ERR_BAD_ARG;
    return view.kind == XAIR_SYM_TAINT_NODE_TRANSFORM && view.lhs == terminal->expected &&
        strcmp(view.name, terminal->transform) == 0 ? XAIR_SYM_OK : XAIR_SYM_ERR_RANGE;
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
    terminal.context = context; terminal.value = sum; terminal.expected = combined0; terminal.transform = "add"; terminal.count = 0;
    require_sym(xair_sym_explore(state, 4, 4, check_taint_terminal, &terminal)); assert(terminal.count == 1);
    xair_sym_context_stats(context, &stats); assert(stats.taint_nodes == 5); assert(stats.taint_nodes_reused >= 2);
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
    terminal.context = context; terminal.value = selected; terminal.expected = XAIR_SYM_TAINT_NONE; terminal.transform = NULL; terminal.count = 0;
    require_sym(xair_sym_explore(state, 4, 4, check_taint_terminal, &terminal)); assert(terminal.count == 1);
    xair_sym_context_set_taint_mode(context, XAIR_SYM_TAINT_TARGETED_IMPLICIT);
    terminal.expected = control_source; terminal.transform = "select"; terminal.count = 0;
    require_sym(xair_sym_explore(state, 4, 4, check_taint_terminal, &terminal)); assert(terminal.count == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { xair_sym_context *context; xair_value_id true_value; xair_value_id false_value; xair_sym_taint_id expected; size_t count; } strict_terminal;
static xair_sym_status check_strict_terminal(xair_sym_state *state, void *user) {
    strict_terminal *terminal = (strict_terminal *)user;
    xair_value_id value = xair_sym_state_block(state) == 1 ? terminal->true_value : terminal->false_value;
    xair_sym_taint_id taint; xair_sym_taint_view view; xair_sym_taint_details details;
    terminal->count++;
    if (xair_sym_state_get_taint(state, value, &taint) != XAIR_SYM_OK) return XAIR_SYM_ERR_BAD_ARG;
    if (xair_sym_taint_get(terminal->context, taint, &view) != XAIR_SYM_OK ||
        xair_sym_taint_get_details(terminal->context, taint, &details) != XAIR_SYM_OK)
        return XAIR_SYM_ERR_BAD_ARG;
    return view.kind == XAIR_SYM_TAINT_NODE_TRANSFORM && view.lhs == terminal->expected &&
        strcmp(view.name, "control_dependency") == 0 && details.implicit ? XAIR_SYM_OK : XAIR_SYM_ERR_RANGE;
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
    terminal.context = context; terminal.true_value = true_result; terminal.false_value = false_result; terminal.expected = source; terminal.count = 0;
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

static xair_sym_status registry_noop_model(xair_sym_state *state, xair_op_id call_op, void *user) {
    (void)state; (void)call_op; (void)user; return XAIR_SYM_OK;
}

typedef struct { xair_value_id result; size_t calls; } restored_calloc_terminal;
static xair_sym_status check_restored_calloc_model(xair_sym_state *state, void *user) {
    restored_calloc_terminal *terminal = (restored_calloc_terminal *)user;
    xair_sym_expr_id result, byte; uint64_t address, value;
    terminal->calls++;
    if (xair_sym_state_get_value(state, terminal->result, &result) != XAIR_SYM_OK ||
        xair_sym_model_u64(state, result, &address) != XAIR_SYM_OK || address == 0 ||
        xair_sym_memory_load8(state, address, &byte) != XAIR_SYM_OK ||
        xair_sym_model_u64(state, byte, &value) != XAIR_SYM_OK || value != 0)
        return XAIR_SYM_ERR_INTERNAL;
    return XAIR_SYM_OK;
}

static void test_process_environment_and_models(void) {
    static const uint8_t code_template[] = {
        0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc3
    };
    uint8_t *code = (uint8_t *)malloc(sizeof(code_template));
    xair_binary_segment segment; xair_binary_view binary; xair_cfg_options cfg_options; xair_cfg_builder *builder = NULL;
    xair_cfg *cfg = NULL; xair_cfg_stats cfg_stats; xair_error error; xair_sym_context *context = NULL;
    xair_sym_environment *environment = NULL; xair_sym_state *state = NULL; xair_sym_process_options process_options;
    xair_sym_expr_id code_byte, symbols[4], symbols_second[4], copied; xair_sym_taint_id source_taint, copied_taint;
    xair_sym_model_kind kind; xair_sym_model_info model_info; uint64_t input_buffer, copy_buffer;
    xair_sym_model_identity identity; uint64_t version_before, version_after;
    xair_module *call_module = NULL; xair_block_id call_block; xair_value_id count_value, size_value, calloc_result;
    xair_sym_state *call_state = NULL, *loaded_state = NULL; xair_sym_snapshot *call_snapshot = NULL, *loaded_snapshot = NULL;
    xair_sym_context *fresh_context = NULL; xair_sym_expr_id count_expr, size_expr;
    xair_op_attributes call_attributes; xair_type call_type = xair_type_addr(64); const char *call_result_name = "calloc_result";
    xair_sym_explore_options explore_options; xair_sym_explore_result explore_result; xair_diagnostic diagnostic;
    restored_calloc_terminal calloc_terminal; const char *snapshot_path = "xair_sym_builtin_environment.bin";
    assert(code != NULL); memcpy(code, code_template, sizeof(code_template));
    memset(&segment, 0, sizeof(segment)); segment.va = 0x1000; segment.mem_size = sizeof(code_template);
    segment.file_size = sizeof(code_template); segment.perms = XAIR_BINARY_PERM_READ | XAIR_BINARY_PERM_EXEC; segment.bytes = code;
    memset(&binary, 0, sizeof(binary)); binary.format = XAIR_BINARY_FORMAT_ELF; binary.arch = XAIR_ARCH_X86_64;
    binary.entry = 0x1000; binary.image_base = 0x1000; binary.segments = &segment; binary.segment_count = 1;
    xair_cfg_options_init(&cfg_options, XAIR_CFG_PROFILE_BALANCED); cfg_options.entry = binary.entry;
    require_xair(xair_cfg_builder_create(&binary, &cfg_options, &builder)); require_xair(xair_cfg_add_root(builder, binary.entry));
    require_xair(xair_cfg_build(builder, &cfg, &cfg_stats, &error)); xair_cfg_builder_destroy(builder);
    require_sym(xair_sym_context_create(&context)); xair_sym_process_options_init(&process_options, binary.arch);
    process_options.stack_size = 4096; process_options.max_segment_size = 4096;
    require_sym(xair_sym_process_create(context, cfg, &binary, &process_options, &environment, &state));
    free(code); code = NULL; segment.bytes = NULL;
    require_sym(xair_sym_memory_load8(state, 0x1000, &code_byte));
    { uint64_t owned_byte; require_sym(xair_sym_model_u64(state, code_byte, &owned_byte)); assert(owned_byte == 0x48u); }
    require_sym(xair_sym_environment_model(environment, "read", &kind)); assert(kind == XAIR_SYM_MODEL_INPUT);
    require_sym(xair_sym_environment_model(environment, "ExAllocatePoolWithTag", &kind)); assert(kind == XAIR_SYM_MODEL_ALLOC);
    require_sym(xair_sym_environment_model_info(environment, "ProbeForRead", &model_info));
    assert(model_info.kind == XAIR_SYM_MODEL_DRIVER_INPUT && model_info.version_major == 1);
    memset(&call_attributes, 0, sizeof(call_attributes)); memset(&calloc_terminal, 0, sizeof(calloc_terminal));
    call_attributes.kind = XAIR_ATTR_CALL; call_attributes.call_kind = XAIR_CALL_DIRECT_EXTERNAL;
    call_attributes.calling_convention = XAIR_CC_SYSV_X64; call_attributes.import_name = "calloc";
    require_xair(xair_module_create(&call_module)); require_xair(xair_block_create(call_module, "calloc_call", &call_block));
    require_xair(xair_block_add_param(call_module, call_block, xair_type_i(64), "count", &count_value));
    require_xair(xair_block_add_param(call_module, call_block, xair_type_i(64), "size", &size_value));
    { xair_value_id inputs[2] = {count_value, size_value};
      require_xair(xair_build_call(call_module, call_block, inputs, 2, &call_type, &call_result_name,
          1, &call_attributes, &calloc_result)); }
    require_xair(xair_set_return(call_module, call_block, &calloc_result, 1)); require_xair(xair_module_freeze(call_module));
    require_sym(xair_sym_state_create(context, call_module, call_block, &call_state));
    require_sym(xair_sym_const(context, 64, 2, &count_expr)); require_sym(xair_sym_const(context, 64, 4, &size_expr));
    require_sym(xair_sym_state_set_value(call_state, count_value, count_expr));
    require_sym(xair_sym_state_set_value(call_state, size_value, size_expr));
    require_sym(xair_sym_state_attach_environment(call_state, environment));
    require_sym(xair_sym_snapshot_take(call_state, &call_snapshot)); remove(snapshot_path);
    require_sym(xair_sym_snapshot_save(call_snapshot, snapshot_path));
    xair_sym_snapshot_destroy(call_snapshot); call_snapshot = NULL; xair_sym_state_destroy(call_state); call_state = NULL;
    version_before = xair_sym_environment_model_version(environment);
    memset(&identity, 0, sizeof(identity)); identity.module = "custom.dll"; identity.name = "custom_read"; identity.ordinal = 17;
    model_info.kind = XAIR_SYM_MODEL_INPUT; model_info.version_major = 3; model_info.version_minor = 2;
    require_sym(xair_sym_environment_register_model(environment, &identity, &model_info, registry_noop_model, NULL));
    version_after = xair_sym_environment_model_version(environment); assert(version_after != version_before);
    { xair_sym_snapshot *unsupported_snapshot = (xair_sym_snapshot *)(uintptr_t)1u;
      assert(xair_sym_snapshot_take(state, &unsupported_snapshot) == XAIR_SYM_ERR_UNSUPPORTED && unsupported_snapshot == NULL); }
    { xair_sym_model_info queried; require_sym(xair_sym_environment_model_identity(environment, &identity, &queried));
      assert(queried.kind == model_info.kind && queried.version_major == 3 && queried.version_minor == 2); }
    require_sym(xair_sym_environment_allocate(environment, state, 16, &input_buffer));
    require_sym(xair_sym_environment_allocate(environment, state, 16, &copy_buffer));
    { xair_sym_expr_id before, after, rejected[2] = {XAIR_SYM_INVALID_ID, XAIR_SYM_INVALID_ID};
      require_sym(xair_sym_const(context, 8, 0x5a, &before)); require_sym(xair_sym_memory_store8(state, input_buffer + 15u, before));
      assert(xair_sym_environment_input(environment, state, input_buffer + 15u, 2, "network", rejected) == XAIR_SYM_ERR_RANGE);
      require_sym(xair_sym_memory_load8(state, input_buffer + 15u, &after)); assert(after == before);
      assert(rejected[0] == XAIR_SYM_INVALID_ID && rejected[1] == XAIR_SYM_INVALID_ID); }
    require_sym(xair_sym_environment_input(environment, state, input_buffer, 4, "network", symbols));
    require_sym(xair_sym_environment_input(environment, state, input_buffer, 4, "network", symbols_second));
    assert(symbols[0] != symbols_second[0]);
    require_sym(xair_sym_environment_copy(environment, state, copy_buffer, input_buffer, 4));
    require_sym(xair_sym_memory_load8(state, copy_buffer + 2, &copied)); assert(copied == symbols_second[2]);
    require_sym(xair_sym_memory_load_taint8(state, input_buffer, &source_taint));
    require_sym(xair_sym_memory_load_taint8(state, copy_buffer + 2, &copied_taint)); assert(copied_taint == source_taint);
    xair_sym_state_destroy(state); xair_sym_environment_destroy(environment); xair_sym_context_destroy(context); xair_cfg_destroy(cfg);
    require_sym(xair_sym_context_create(&fresh_context));
    require_sym(xair_sym_snapshot_load(fresh_context, call_module, snapshot_path, &loaded_snapshot)); remove(snapshot_path);
    require_sym(xair_sym_snapshot_restore(loaded_snapshot, &loaded_state)); calloc_terminal.result = calloc_result;
    xair_sym_explore_options_init(&explore_options); explore_options.max_states = 4; explore_options.max_block_steps = 4;
    require_sym(xair_sym_explore_detailed(loaded_state, &explore_options, check_restored_calloc_model,
        &calloc_terminal, &explore_result, &diagnostic));
    assert(calloc_terminal.calls == 1 && explore_result.completion_reason == XAIR_SYM_COMPLETED);
    xair_sym_state_destroy(loaded_state); xair_sym_snapshot_destroy(loaded_snapshot);
    xair_sym_context_destroy(fresh_context); xair_module_destroy(call_module);
}

static void test_phase6_failed_realloc_restores_memory_accounting(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_sym_environment *environment = NULL; xair_block_id block;
    xair_value_id pointer, size_value, result, inputs[2]; xair_type result_type = xair_type_addr(64);
    const char *result_name = "reallocated"; xair_op_attributes attributes;
    xair_sym_expr_id pointer_expr, size_expr; xair_sym_object_id old_object, probe_object;
    xair_sym_explore_options options; xair_sym_explore_result explore_result; xair_diagnostic diagnostic;
    xair_analysis_options analysis; xair_sym_stats before_stats, after_stats;
    uint64_t fingerprint; size_t object_bytes, reserved; size_t i;
    memset(&attributes, 0, sizeof(attributes));
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "realloc_failure", &block));
    require_xair(xair_block_add_param(module, block, xair_type_addr(64), "pointer", &pointer));
    require_xair(xair_block_add_param(module, block, xair_type_i(64), "size", &size_value));
    attributes.kind = XAIR_ATTR_CALL; attributes.call_kind = XAIR_CALL_DIRECT_EXTERNAL;
    attributes.calling_convention = XAIR_CC_SYSV_X64; attributes.import_name = "realloc";
    inputs[0] = pointer; inputs[1] = size_value;
    require_xair(xair_build_call(module, block, inputs, 2, &result_type, &result_name,
        1, &attributes, &result));
    require_xair(xair_set_return(module, block, &result, 1));
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64,
        XAIR_CC_SYSV_X64, UINT64_C(0x00010000), UINT64_C(0x7fff00000000),
        4096u, UINT64_C(0x600000000000), &environment));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_state_attach_environment(state, environment));
    require_sym(xair_sym_object_add(state, UINT64_C(0x500000000000), 16u, 2u, &old_object));
    require_sym(xair_sym_const(context, 64, UINT64_C(0x500000000000), &pointer_expr));
    require_sym(xair_sym_const(context, 64, 1024u * 1024u, &size_expr));
    require_sym(xair_sym_state_set_value(state, pointer, pointer_expr));
    require_sym(xair_sym_state_set_value(state, size_value, size_expr));
    xair_analysis_options_init(&analysis); analysis.max_memory = 4u * 1024u * 1024u;
    xair_sym_context_set_analysis_options(context, &analysis);
    object_bytes = context->object_bytes; reserved = context->parallel_memory_reserved;
    xair_sym_context_stats(context, &before_stats);
    fingerprint = xair_sym_memory_fingerprint(state->memory);
    xair_sym_explore_options_init(&options); options.max_states = 2; options.max_block_steps = 2;
    options.analysis = analysis;
    for (i = 0; i < 32u; ++i) {
        assert(xair_sym_explore_detailed(state, &options, NULL, NULL,
            &explore_result, &diagnostic) == XAIR_SYM_ERR_RANGE);
        assert(state->memory->count == 1u && state->memory->objects[0].base == UINT64_C(0x500000000000));
        assert(xair_sym_memory_fingerprint(state->memory) == fingerprint);
        assert(context->object_bytes == object_bytes && context->parallel_memory_reserved == reserved);
        xair_sym_context_stats(context, &after_stats);
        assert(after_stats.memory_objects == before_stats.memory_objects &&
            after_stats.memory_pages == before_stats.memory_pages &&
            after_stats.memory_cow_copies == before_stats.memory_cow_copies &&
            after_stats.memory_page_copies == before_stats.memory_page_copies);
    }
    require_sym(xair_sym_object_add(state, UINT64_C(0x500000001000), 16u, 3u, &probe_object));
    assert(probe_object == 1u && old_object == 0u);
    xair_sym_state_destroy(state); xair_sym_environment_destroy(environment);
    xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { const xair_module *module; xair_value_id rbx; xair_sym_expr_id initial_rbx; size_t calls; int saw_rax_42; } win64_terminal;
static xair_sym_status check_win64_abi_terminal(xair_sym_state *state, void *user) {
    win64_terminal *terminal = (win64_terminal *)user;
    size_t i;
    xair_sym_expr_id preserved;
    terminal->calls++;
    if (xair_sym_state_get_value(state, terminal->rbx, &preserved) != XAIR_SYM_OK ||
        preserved != terminal->initial_rbx) return XAIR_SYM_ERR_INTERNAL;
    for (i = 0; i < xair_module_value_count(terminal->module); ++i) {
        xair_sym_expr_id expression;
        uint64_t value;
        if (xair_value_type(terminal->module, (xair_value_id)i).bits != 64u) continue;
        if (xair_sym_state_get_value(state, (xair_value_id)i, &expression) == XAIR_SYM_OK &&
            xair_sym_model_u64(state, expression, &value) == XAIR_SYM_OK && value == 42u)
            terminal->saw_rax_42 = 1;
    }
    return XAIR_SYM_OK;
}

static xair_value_id find_defined_named_value(const xair_module *module, xair_sym_state *state, const char *name) {
    size_t i;
    for (i = 0; i < xair_module_value_count(module); ++i) {
        xair_sym_expr_id ignored;
        const char *candidate = xair_value_name(module, (xair_value_id)i);
        if (candidate != NULL && strcmp(candidate, name) == 0 &&
            xair_sym_state_get_value(state, (xair_value_id)i, &ignored) == XAIR_SYM_OK)
            return (xair_value_id)i;
    }
    return XAIR_INVALID_ID;
}

static void test_phase6_win64_process_abi_contract(void) {
    static uint8_t code[] = {
        0x49,0x89,0xe3,
        0x49,0x89,0xdb, 0x49,0x01,0xcb, 0x49,0x01,0xd3,
        0x4d,0x01,0xc3, 0x4d,0x01,0xcb, 0x4d,0x01,0xd3,
        0x48,0xb8,0x2a,0,0,0,0,0,0,0, 0xc3
    };
    static const char *arguments[] = {"rcx", "rdx", "r8", "r9"};
    xair_binary_segment segment; xair_binary_view binary; xair_cfg_options cfg_options;
    xair_cfg_builder *builder = NULL; xair_cfg *cfg = NULL; xair_cfg_stats cfg_stats; xair_error error;
    xair_sym_context *context = NULL; xair_sym_environment *environment = NULL; xair_sym_state *state = NULL;
    xair_sym_process_options options; const xair_module *module; xair_sym_expr_id expression;
    xair_sym_expr_view view; uint64_t expected_rsp, value; size_t i; win64_terminal terminal;
    memset(&segment, 0, sizeof(segment)); segment.va = 0x180001000; segment.mem_size = sizeof(code);
    segment.file_size = sizeof(code); segment.perms = XAIR_BINARY_PERM_READ | XAIR_BINARY_PERM_EXEC; segment.bytes = code;
    memset(&binary, 0, sizeof(binary)); binary.format = XAIR_BINARY_FORMAT_PE; binary.arch = XAIR_ARCH_X86_64;
    binary.entry = segment.va; binary.image_base = 0x180000000; binary.segments = &segment; binary.segment_count = 1;
    xair_cfg_options_init(&cfg_options, XAIR_CFG_PROFILE_BALANCED); cfg_options.entry = binary.entry;
    require_xair(xair_cfg_builder_create(&binary, &cfg_options, &builder)); require_xair(xair_cfg_add_root(builder, binary.entry));
    require_xair(xair_cfg_build(builder, &cfg, &cfg_stats, &error)); xair_cfg_builder_destroy(builder);
    require_sym(xair_sym_context_create(&context)); xair_sym_process_options_init(&options, binary.arch);
    options.abi = XAIR_CC_WIN64; options.stack_base = UINT64_C(0x0000000060000000); options.stack_size = 4096;
    options.max_segment_size = 4096;
    require_sym(xair_sym_process_create(context, cfg, &binary, &options, &environment, &state));
    module = xair_cfg_module(cfg); expected_rsp = (options.stack_base + options.stack_size) & ~UINT64_C(15); expected_rsp -= 40u;
    assert((expected_rsp & 15u) == 8u);
    require_sym(xair_sym_state_get_value(state, find_defined_named_value(module, state, "rsp"), &expression));
    require_sym(xair_sym_model_u64(state, expression, &value)); assert(value == expected_rsp);
    for (i = 0; i < 40u; ++i) {
        require_sym(xair_sym_memory_load8(state, expected_rsp + i, &expression));
        require_sym(xair_sym_model_u64(state, expression, &value)); assert(value == 0u);
    }
    for (i = 0; i < sizeof(arguments) / sizeof(arguments[0]); ++i) {
        require_sym(xair_sym_state_get_value(state, find_defined_named_value(module, state, arguments[i]), &expression));
        require_sym(xair_sym_expr_get(context, expression, &view));
        assert(view.kind == XAIR_SYM_EXPR_SYMBOL && strstr(view.symbol, "win64_argument_") == view.symbol);
    }
    terminal.rbx = find_defined_named_value(module, state, "rbx");
    require_sym(xair_sym_state_get_value(state, terminal.rbx, &expression));
    require_sym(xair_sym_expr_get(context, expression, &view)); assert(strstr(view.symbol, "win64_callee_saved_") == view.symbol);
    terminal.initial_rbx = expression;
    require_sym(xair_sym_state_get_value(state, find_defined_named_value(module, state, "r10"), &expression));
    require_sym(xair_sym_expr_get(context, expression, &view)); assert(strstr(view.symbol, "win64_caller_saved_") == view.symbol);
    terminal.module = module; terminal.calls = 0; terminal.saw_rax_42 = 0;
    require_sym(xair_sym_explore(state, 32, 128, check_win64_abi_terminal, &terminal));
    assert(terminal.calls == 1 && terminal.saw_rax_42);
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

typedef struct { terminal_counts counts; xair_block_id allocating_block; } parallel_memory_terminal;
static xair_sym_status count_parallel_memory_terminal(xair_sym_state *state, void *user) {
    parallel_memory_terminal *terminal = (parallel_memory_terminal *)user;
    xair_sym_status status = XAIR_SYM_OK;
    terminal->counts.count++;
    if (xair_sym_state_block(state) == 1) terminal->counts.seen_true = 1;
    if (xair_sym_state_block(state) == 2) terminal->counts.seen_false = 1;
    if (xair_sym_state_block(state) == terminal->allocating_block)
        status = xair_sym_memory_store_taint8(state, 0x6000, XAIR_SYM_TAINT_NONE);
    return status;
}

static void test_parallel_isolated_workers(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL; xair_sym_snapshot *snapshot = NULL;
    xair_block_id entry, left, right; xair_value_id condition_value; xair_sym_expr_id condition;
    xair_sym_parallel_options options; xair_sym_explore_result result; xair_diagnostic diagnostic;
    terminal_counts counts; parallel_memory_terminal memory_terminal; xair_sym_object_id object;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &entry));
    require_xair(xair_block_create(module, "left", &left)); require_xair(xair_block_create(module, "right", &right));
    require_xair(xair_block_add_param(module, entry, xair_type_i(1), "condition", &condition_value));
    require_xair(xair_set_cbranch(module, entry, condition_value, left, NULL, 0, right, NULL, 0));
    require_xair(xair_set_return(module, left, NULL, 0)); require_xair(xair_set_return(module, right, NULL, 0));
    require_xair(xair_module_freeze(module)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, entry, &state)); require_sym(xair_sym_symbol(context, 1, "parallel_condition", &condition));
    require_sym(xair_sym_state_set_value(state, condition_value, condition));
    require_sym(xair_sym_object_add(state, 0x6000, 4096, 3, &object));
    require_sym(xair_sym_snapshot_take(state, &snapshot));
    xair_sym_parallel_options_init(&options); options.workers = 2; options.explore.max_states = 8; options.explore.max_block_steps = 8;
    memset(&counts, 0, sizeof(counts)); require_sym(xair_sym_parallel_explore_detailed(
        snapshot, &options, count_terminal, &counts, &result, &diagnostic));
    assert(counts.count == 2 && result.terminal_states == 2);
    assert(result.workers_started == 2 && result.partitions == 2);
    assert(result.coverage_blocks == 3);
    options.explore.analysis.max_memory = 128u * 1024u * 1024u;
    memset(&memory_terminal, 0, sizeof(memory_terminal)); memory_terminal.allocating_block = left;
    require_sym(xair_sym_parallel_explore_detailed(snapshot, &options,
        count_parallel_memory_terminal, &memory_terminal, &result, &diagnostic));
    assert(memory_terminal.counts.count == 2 && result.peak_memory_bytes != 0 &&
        result.peak_memory_bytes <= options.explore.analysis.max_memory);
    assert(memory_terminal.counts.seen_true && memory_terminal.counts.seen_false);
    options.explore.analysis.max_memory = 0;
    options.explore.max_states = 3; options.explore.max_block_steps = 8;
    memset(&counts, 0, sizeof(counts));
    assert(xair_sym_parallel_explore_detailed(snapshot, &options, count_terminal, &counts,
        &result, &diagnostic) == XAIR_SYM_ERR_RESOURCE_LIMIT);
    assert(result.states_processed <= 3 && result.completion_reason == XAIR_SYM_LIMIT_REACHED);
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

static void test_v03_unknown_branch_forks_both_paths(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id entry, yes, no; xair_value_id condition; terminal_counts counts;
    memset(&counts, 0, sizeof(counts));
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &entry));
    require_xair(xair_block_create(module, "yes", &yes)); require_xair(xair_block_create(module, "no", &no));
    require_xair(xair_build_unknown(module, entry, xair_type_i(1), "undefined_zf", "condition", &condition));
    require_xair(xair_set_cbranch(module, entry, condition, yes, NULL, 0, no, NULL, 0));
    require_xair(xair_set_return(module, yes, NULL, 0)); require_xair(xair_set_return(module, no, NULL, 0));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, entry, &state));
    require_sym(xair_sym_explore(state, 8, 8, count_terminal, &counts));
    assert(counts.count == 2 && counts.seen_true && counts.seen_false);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct {
    xair_value_id result; xair_sym_expr_id modeled, expected_argument;
    xair_sym_taint_id expected_taint; xair_sym_context *context;
    xair_op_id call_op; size_t calls; size_t terminal_calls;
} call_model_test;
static xair_sym_status test_call_model(xair_sym_state *state, xair_op_id call_op, void *user) {
    call_model_test *model = (call_model_test *)user;
    xair_sym_model_call_view call; xair_sym_expr_id argument, byte, tautology; xair_sym_taint_id taint;
    assert(call_op == 0); model->calls++;
    require_sym(xair_sym_model_call_get(state, call_op, &call));
    assert(call.struct_size == sizeof(call) && call.context == model->context &&
        call.abi == XAIR_CC_WIN64 && call.argument_count == 1 && call.result_count == 1 &&
        call.confidence == XAIR_CONFIDENCE_HIGH && call.output_confidence == XAIR_CONFIDENCE_UNKNOWN &&
        call.call_site == UINT64_C(0x401000) && call.direct_target == UINT64_C(0x77770000) &&
        strcmp(call.import_module, "KERNEL32.dll") == 0 && strcmp(call.import_name, "GetTickCount64") == 0);
    require_sym(xair_sym_model_call_argument_get(state, call_op, 0, &argument, &taint));
    assert(argument == model->expected_argument && taint == model->expected_taint);
    require_sym(xair_sym_model_call_confidence_set(state, call_op, XAIR_CONFIDENCE_EXACT));
    require_sym(xair_sym_const(model->context, 8, 0x5a, &byte));
    require_sym(xair_sym_memory_store8(state, 0x7000, byte));
    require_sym(xair_sym_binary(model->context, XAIR_OP_EQ, 1, argument, argument, &tautology));
    require_sym(xair_sym_state_assume(state, tautology));
    xair_sym_model_call_mark_incomplete(state, 0);
    xair_sym_model_call_terminate(state);
    return xair_sym_model_call_result_set(state, call_op, 0, model->modeled, taint);
}

static xair_sym_status check_custom_model_outputs(xair_sym_state *state, void *user) {
    call_model_test *model = (call_model_test *)user;
    xair_sym_model_call_view call; xair_sym_expr_id byte; uint64_t value;
    model->terminal_calls++;
    if (xair_sym_model_call_get(state, model->call_op, &call) != XAIR_SYM_OK ||
        call.output_confidence != XAIR_CONFIDENCE_EXACT ||
        xair_sym_memory_load8(state, 0x7000, &byte) != XAIR_SYM_OK ||
        xair_sym_model_u64(state, byte, &value) != XAIR_SYM_OK || value != 0x5a)
        return XAIR_SYM_ERR_INTERNAL;
    return XAIR_SYM_OK;
}

static void test_v03_symbolic_call_model_intercepts_call(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_sym_program *program = NULL;
    xair_block_id entry; xair_value_id argument_value, result; xair_value_id inputs[1]; xair_type type = xair_type_i(64);
    xair_sym_expr_id argument_expr; xair_sym_taint_id argument_taint;
    const char *name = "rax"; xair_op_attributes attributes; call_model_test model;
    xair_source_record source; xair_source_id source_id; xair_sym_object_id object;
    xair_sym_explore_options options; xair_sym_explore_result explore_result; xair_diagnostic diagnostic;
    memset(&attributes, 0, sizeof(attributes)); memset(&model, 0, sizeof(model)); memset(&source, 0, sizeof(source));
    attributes.kind = XAIR_ATTR_CALL; attributes.effects = XAIR_EFFECT_READ_MEMORY;
    attributes.call_kind = XAIR_CALL_DIRECT_EXTERNAL; attributes.calling_convention = XAIR_CC_WIN64;
    attributes.confidence = XAIR_CONFIDENCE_HIGH;
    attributes.direct_target = UINT64_C(0x77770000);
    attributes.import_module = "KERNEL32.dll"; attributes.import_name = "GetTickCount64";
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &entry));
    source.location.instruction_va = UINT64_C(0x401000); source.kind = XAIR_SOURCE_MACHINE;
    source.confidence = XAIR_CONFIDENCE_EXACT; source.semantic_id = "custom-model-call";
    require_xair(xair_module_add_source(module, &source, &source_id));
    require_xair(xair_module_set_current_source(module, source_id));
    require_xair(xair_block_add_param(module, entry, xair_type_i(64), "argument", &argument_value)); inputs[0] = argument_value;
    require_xair(xair_build_call(module, entry, inputs, 1, &type, &name, 1, &attributes, &result));
    require_xair(xair_set_return(module, entry, &result, 1));
    require_xair(xair_module_freeze(module)); require_sym(xair_sym_program_compile(module, &program));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_const(context, 64, 1234, &model.modeled));
    require_sym(xair_sym_symbol(context, 64, "model_argument", &argument_expr));
    require_sym(xair_sym_taint_source(context, "model_argument_taint", &argument_taint));
    require_sym(xair_sym_state_create(context, module, entry, &state)); model.result = result; model.context = context;
    model.call_op = 0;
    model.expected_argument = argument_expr; model.expected_taint = argument_taint;
    require_sym(xair_sym_state_set_value(state, argument_value, argument_expr));
    require_sym(xair_sym_state_set_taint(state, argument_value, argument_taint));
    require_sym(xair_sym_object_add(state, 0x7000, 1, 3u, &object));
    require_sym(xair_sym_state_attach_program(state, program));
    xair_sym_state_set_call_model(state, test_call_model, &model);
    xair_sym_explore_options_init(&options); options.max_states = 4; options.max_block_steps = 4;
    require_sym(xair_sym_explore_detailed(state, &options, check_custom_model_outputs,
        &model, &explore_result, &diagnostic));
    assert(model.calls == 1 && model.terminal_calls == 1 &&
        explore_result.completion_reason == XAIR_SYM_INCOMPLETE &&
        explore_result.unresolved_operations == 1);
    xair_sym_state_destroy(state); xair_sym_program_destroy(program); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct {
    xair_sym_context *context;
    xair_value_id rbx;
    xair_sym_expr_id initial_rbx;
    xair_value_id results[10];
    size_t result_count;
    size_t calls;
} unknown_abi_terminal;
static xair_sym_status check_unknown_abi_fallback(xair_sym_state *state, void *user) {
    unknown_abi_terminal *terminal = (unknown_abi_terminal *)user;
    xair_sym_expr_id expression; xair_sym_expr_view view; size_t i;
    terminal->calls++;
    if (xair_sym_state_get_value(state, terminal->rbx, &expression) != XAIR_SYM_OK ||
        expression != terminal->initial_rbx) return XAIR_SYM_ERR_INTERNAL;
    for (i = 0; i < terminal->result_count; ++i) {
        if (xair_sym_state_get_value(state, terminal->results[i], &expression) != XAIR_SYM_OK ||
            xair_sym_expr_get(terminal->context, expression, &view) != XAIR_SYM_OK ||
            view.kind != XAIR_SYM_EXPR_SYMBOL) return XAIR_SYM_ERR_INTERNAL;
    }
    return XAIR_SYM_OK;
}

static void run_unknown_abi_fallback(xair_calling_convention abi) {
    static const char *win_names[] = {"rax","rcx","rdx","r8","r9","r10","r11","memory"};
    static const char *sysv_names[] = {"rax","rcx","rdx","rsi","rdi","r8","r9","r10","r11","memory"};
    const char **names = abi == XAIR_CC_WIN64 ? win_names : sysv_names;
    size_t result_count = abi == XAIR_CC_WIN64 ? 8u : 10u, i;
    xair_type types[10]; xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id memory, rbx, call_results[10], inputs[1]; xair_op_attributes attributes;
    xair_sym_expr_id rbx_expr; xair_sym_explore_options options; xair_sym_explore_result result;
    xair_diagnostic diagnostic; unknown_abi_terminal terminal;
    memset(&attributes, 0, sizeof(attributes)); memset(&terminal, 0, sizeof(terminal));
    attributes.kind = XAIR_ATTR_CALL; attributes.call_kind = XAIR_CALL_DIRECT_EXTERNAL;
    attributes.calling_convention = abi; attributes.effects = XAIR_EFFECT_READ_MEMORY | XAIR_EFFECT_WRITE_MEMORY;
    attributes.import_name = "unknown_external";
    for (i = 0; i + 1u < result_count; ++i) types[i] = xair_type_i(64);
    types[result_count - 1u] = xair_type_mem(0, 64);
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "unknown_abi", &block));
    require_xair(xair_block_add_param(module, block, xair_type_mem(0, 64), "memory", &memory));
    require_xair(xair_block_add_param(module, block, xair_type_i(64), "rbx", &rbx)); inputs[0] = memory;
    require_xair(xair_build_call(module, block, inputs, 1, types, names, result_count, &attributes, call_results));
    require_xair(xair_set_return(module, block, &rbx, 1)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state)); require_sym(xair_sym_symbol(context, 64, "callee_saved_rbx", &rbx_expr));
    require_sym(xair_sym_state_set_value(state, rbx, rbx_expr)); terminal.context = context; terminal.rbx = rbx;
    terminal.initial_rbx = rbx_expr; terminal.result_count = result_count - 1u;
    memcpy(terminal.results, call_results, terminal.result_count * sizeof(*call_results));
    xair_sym_explore_options_init(&options); options.max_states = 4; options.max_block_steps = 4;
    require_sym(xair_sym_explore_detailed(state, &options, check_unknown_abi_fallback, &terminal, &result, &diagnostic));
    assert(terminal.calls == 1 && result.completion_reason == XAIR_SYM_INCOMPLETE && result.unresolved_operations == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_phase6_unknown_win64_and_sysv_call_fallback(void) {
    run_unknown_abi_fallback(XAIR_CC_WIN64);
    run_unknown_abi_fallback(XAIR_CC_SYSV_X64);
}

static void test_v03_z3_wide_constants_agree_with_concrete_bits(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id entry; xair_sym_expr_id lhs, rhs, value, expected, equality; xair_sym_sat sat;
    uint64_t seed = UINT64_C(0x9e3779b97f4a7c15); size_t i;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &entry));
    require_xair(xair_set_return(module, entry, NULL, 0));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, entry, &state));
    require_sym(xair_sym_const_wide(context, 128, UINT64_C(0x1122334455667788), UINT64_C(0x99aabbccddeeff00), &lhs));
    require_sym(xair_sym_const_wide(context, 128, UINT64_C(0x00ff00ff00ff00ff), UINT64_C(0x00ff00ff00ff00ff), &rhs));
    require_sym(xair_sym_binary(context, XAIR_OP_XOR, 128, lhs, rhs, &value));
    require_sym(xair_sym_const_wide(context, 128, UINT64_C(0x11dd33bb55997777), UINT64_C(0x9955bb33dd11ffff), &expected));
    assert(lhs != rhs && value != expected);
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, value, expected, &equality));
    require_sym(xair_sym_state_assume(state, equality));
    for (i = 0; i < 32; ++i) {
        uint64_t alo, ahi, blo, bhi;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; alo = seed;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; ahi = seed;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; blo = seed;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; bhi = seed;
        require_sym(xair_sym_const_wide(context, 128, alo, ahi, &lhs));
        require_sym(xair_sym_const_wide(context, 128, blo, bhi, &rhs));
        require_sym(xair_sym_binary(context, XAIR_OP_XOR, 128, lhs, rhs, &value));
        require_sym(xair_sym_const_wide(context, 128, alo ^ blo, ahi ^ bhi, &expected));
        require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, value, expected, &equality));
        require_sym(xair_sym_state_assume(state, equality));
    }
    require_sym(xair_sym_check(state, XAIR_SYM_INVALID_ID, &sat));
    assert(sat == XAIR_SYM_SAT);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { xair_sym_context *context; xair_value_id flags[6]; size_t calls; } flag_solver_terminal;
static xair_sym_status check_all_flag_extracts_with_solver(xair_sym_state *state, void *user) {
    static const uint64_t expected[6] = {0, 0, 1, 0, 1, 1};
    flag_solver_terminal *terminal = (flag_solver_terminal *)user;
    size_t i;
    terminal->calls++;
    for (i = 0; i < 6; ++i) {
        xair_sym_expr_id actual, constant, equality;
        xair_sym_sat sat;
        if (xair_sym_state_get_value(state, terminal->flags[i], &actual) != XAIR_SYM_OK) return XAIR_SYM_ERR_BAD_ARG;
        if (xair_sym_const(terminal->context, 1, expected[i], &constant) != XAIR_SYM_OK) return XAIR_SYM_ERR_OOM;
        if (xair_sym_binary(terminal->context, XAIR_OP_EQ, 1, actual, constant, &equality) != XAIR_SYM_OK)
            return XAIR_SYM_ERR_BAD_ARG;
        if (xair_sym_check(state, equality, &sat) != XAIR_SYM_OK || sat != XAIR_SYM_SAT) return XAIR_SYM_ERR_SOLVER;
    }
    return XAIR_SYM_OK;
}

static void test_phase3_all_emitted_flag_extracts_translate_to_z3(void) {
    static const xair_opcode extracts[6] = { XAIR_OP_FLAG_CF, XAIR_OP_FLAG_PF, XAIR_OP_FLAG_AF,
        XAIR_OP_FLAG_ZF, XAIR_OP_FLAG_SF, XAIR_OP_FLAG_OF };
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id lhs, rhs, flags; xair_sym_expr_id lhs_value, rhs_value;
    flag_solver_terminal terminal; size_t i;
    memset(&terminal, 0, sizeof(terminal));
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "flags", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "lhs", &lhs));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "rhs", &rhs));
    require_xair(xair_build_binary(module, block, XAIR_OP_FLAGS_ADD, xair_type_flags(6), lhs, rhs, "flags", &flags));
    for (i = 0; i < 6; ++i)
        require_xair(xair_build_unary(module, block, extracts[i], xair_type_i(1), flags, "flag", &terminal.flags[i]));
    require_xair(xair_set_return(module, block, terminal.flags, 6));
    require_sym(xair_sym_context_create(&context)); terminal.context = context;
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_const(context, 8, 0x7f, &lhs_value)); require_sym(xair_sym_const(context, 8, 1, &rhs_value));
    require_sym(xair_sym_state_set_value(state, lhs, lhs_value)); require_sym(xair_sym_state_set_value(state, rhs, rhs_value));
    require_sym(xair_sym_explore(state, 4, 4, check_all_flag_extracts_with_solver, &terminal));
    assert(terminal.calls == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_phase6_logic_and_shift_af_are_stable_unknowns(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_sym_expr_id value, one, zero, logic_flags, shift_flags;
    xair_sym_expr_id logic_af, logic_af_again, shift_af, equality; xair_sym_sat sat;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "af_parity", &block));
    require_xair(xair_set_return(module, block, NULL, 0)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_const(context, 8, 0x81, &value)); require_sym(xair_sym_const(context, 8, 1, &one));
    require_sym(xair_sym_const(context, 1, 0, &zero));
    require_sym(xair_sym_unary(context, XAIR_OP_FLAGS_LOGIC, 6, value, 0, &logic_flags));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_SHL, 6, value, one, &shift_flags));
    require_sym(xair_sym_unary(context, XAIR_OP_FLAG_AF, 1, logic_flags, 0, &logic_af));
    require_sym(xair_sym_unary(context, XAIR_OP_FLAG_AF, 1, logic_flags, 0, &logic_af_again));
    require_sym(xair_sym_unary(context, XAIR_OP_FLAG_AF, 1, shift_flags, 0, &shift_af));
    assert(logic_af == logic_af_again);
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, logic_af, zero, &equality));
    require_sym(xair_sym_check(state, equality, &sat)); assert(sat == XAIR_SYM_SAT);
    require_sym(xair_sym_binary(context, XAIR_OP_NE, 1, logic_af, zero, &equality));
    require_sym(xair_sym_check(state, equality, &sat)); assert(sat == XAIR_SYM_SAT);
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, shift_af, zero, &equality));
    require_sym(xair_sym_check(state, equality, &sat)); assert(sat == XAIR_SYM_SAT);
    require_sym(xair_sym_binary(context, XAIR_OP_NE, 1, shift_af, zero, &equality));
    require_sym(xair_sym_check(state, equality, &sat)); assert(sat == XAIR_SYM_SAT);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { xair_sym_context *context; xair_value_id quotient; size_t calls; } divide_terminal;
static xair_sym_status check_symbolic_divide_terminal(xair_sym_state *state, void *user) {
    divide_terminal *terminal = (divide_terminal *)user;
    xair_sym_expr_id actual, expected, equality; xair_sym_sat sat;
    terminal->calls++;
    if (xair_sym_state_get_value(state, terminal->quotient, &actual) != XAIR_SYM_OK ||
        xair_sym_const(terminal->context, 64, 5, &expected) != XAIR_SYM_OK ||
        xair_sym_binary(terminal->context, XAIR_OP_EQ, 1, actual, expected, &equality) != XAIR_SYM_OK ||
        xair_sym_check(state, equality, &sat) != XAIR_SYM_OK || sat != XAIR_SYM_SAT) return XAIR_SYM_ERR_SOLVER;
    return XAIR_SYM_OK;
}

static void test_phase3_x86_div_intrinsic_has_symbolic_value_model(void) {
    static const uint8_t bytes[] = {0x48,0xf7,0xf3,0xc3};
    xair_module *module = NULL; xair_image image; xair_lift_options options; xair_lift_result lift;
    xair_sym_context *context = NULL; xair_sym_state *state = NULL; divide_terminal terminal;
    size_t i;
    memset(&options, 0, sizeof(options)); memset(&terminal, 0, sizeof(terminal));
    require_xair(xair_module_create(&module)); require_xair(xair_image_init(&image, bytes, sizeof(bytes), 0x9000));
    options.arch = XAIR_ARCH_X86_64; options.address = image.base;
    require_xair(xair_lift_basic_block(module, &image, &options, &lift));
    terminal.quotient = XAIR_INVALID_ID;
    for (i = 0; i < lift.output_reg_count; ++i)
        if (lift.output_regs[i].reg == XAIR_X86_RAX) terminal.quotient = lift.output_regs[i].value;
    assert(terminal.quotient != XAIR_INVALID_ID);
    require_sym(xair_sym_context_create(&context)); terminal.context = context;
    require_sym(xair_sym_state_create(context, module, lift.block, &state));
    for (i = 0; i < lift.input_reg_count; ++i) {
        uint64_t concrete = lift.input_regs[i].reg == XAIR_X86_RAX ? 10u :
            lift.input_regs[i].reg == XAIR_X86_RBX ? 2u : 0u;
        xair_sym_expr_id value; require_sym(xair_sym_const(context, 64, concrete, &value));
        require_sym(xair_sym_state_set_value(state, lift.input_regs[i].value, value));
    }
    require_sym(xair_sym_explore(state, 4, 4, check_symbolic_divide_terminal, &terminal));
    assert(terminal.calls == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_phase6_opcode_capability_table_is_complete(void) {
    size_t i;
    assert(xair_sym_opcode_capability_count() == 52);
    require_sym(xair_sym_opcode_capabilities_validate());
    for (i = 0; i < xair_sym_opcode_capability_count(); ++i) {
        xair_sym_opcode_capability capability;
        require_sym(xair_sym_opcode_capability_get(i, &capability));
        assert(capability.capabilities != 0 && xair_opcode_name(capability.opcode) != NULL);
    }
}

static void test_phase6_public_expression_shape_validation(void) {
    xair_sym_context *context = NULL; xair_sym_expr_id a8, b16, arbitrary6, packed, condition, output = 123u;
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_symbol(context, 8, "a8", &a8));
    require_sym(xair_sym_symbol(context, 16, "b16", &b16));
    require_sym(xair_sym_symbol(context, 1, "condition", &condition));
    require_sym(xair_sym_symbol(context, 6, "not_a_flag_pack", &arbitrary6));
    assert(xair_sym_binary(context, XAIR_OP_ADD, 8, a8, b16, &output) == XAIR_SYM_ERR_BAD_ARG);
    assert(output == 123u);
    assert(xair_sym_binary(context, XAIR_OP_EQ, 8, a8, a8, &output) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_unary(context, XAIR_OP_EXTRACT, 8, a8, 1, &output) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_unary(context, XAIR_OP_ZEXT, 8, a8, 0, &output) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_select(context, a8, a8, a8, &output) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_select(context, condition, a8, b16, &output) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_unary(context, XAIR_OP_FLAG_ZF, 1, arbitrary6, 0, &output) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_const_wide(context, 65, 0, 2, &output) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_const_wide(context, 8, 0x100, 0, &output) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_unary(context, XAIR_OP_FLAGS_LOGIC, 6, a8, 0, &packed));
    require_sym(xair_sym_unary(context, XAIR_OP_FLAG_ZF, 1, packed, 0, &output));
    xair_sym_context_destroy(context);
}

static void test_phase6_sparse_paged_memory_and_overlap(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL;
    xair_sym_state *state = NULL; xair_sym_state *clone = NULL;
    xair_block_id block; xair_sym_object_id large, small; xair_sym_expr_id a, b, loaded;
    xair_sym_stats stats;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "memory", &block));
    require_xair(xair_set_return(module, block, NULL, 0)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_object_add(state, UINT64_C(0x100000000), 100u * 1024u * 1024u, 3u, &large));
    assert(large == 0); xair_sym_context_stats(context, &stats); assert(stats.memory_pages == 0);
    require_sym(xair_sym_const(context, 8, 0x41, &a)); require_sym(xair_sym_const(context, 8, 0x42, &b));
    require_sym(xair_sym_memory_store8(state, UINT64_C(0x100001234), a));
    require_sym(xair_sym_state_clone(state, &clone)); require_sym(xair_sym_memory_store8(clone, UINT64_C(0x100001234), b));
    require_sym(xair_sym_memory_load8(state, UINT64_C(0x100001234), &loaded)); assert(loaded == a);
    require_sym(xair_sym_memory_load8(clone, UINT64_C(0x100001234), &loaded)); assert(loaded == b);
    xair_sym_context_stats(context, &stats); assert(stats.memory_page_copies == 1);
    require_sym(xair_sym_object_add(state, 0x4000, 16, 3, &small));
    assert(xair_sym_object_add(state, 0x3000, 0x2000, 3, &small) == XAIR_SYM_ERR_BAD_ARG);
    xair_sym_state_destroy(clone); xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_phase6_atomic_multi_byte_store_boundaries(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_sym_object_id object; xair_sym_expr_id initial0, initial1, values[2], loaded;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "atomic_store", &block));
    require_xair(xair_set_return(module, block, NULL, 0)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_const(context, 8, 0xaa, &initial0)); require_sym(xair_sym_const(context, 8, 0xbb, &initial1));
    require_sym(xair_sym_const(context, 8, 0x11, &values[0])); require_sym(xair_sym_const(context, 8, 0x22, &values[1]));
    require_sym(xair_sym_object_add(state, 0x1000, 2, 3, &object));
    require_sym(xair_sym_object_add(state, 0x1002, 2, 3, &object));
    require_sym(xair_sym_memory_store8(state, 0x1000, initial0)); require_sym(xair_sym_memory_store8(state, 0x1001, initial1));
    assert(xair_sym_memory_store_bytes(state, 0x1001, values, NULL, 2) == XAIR_SYM_ERR_RANGE);
    require_sym(xair_sym_memory_load8(state, 0x1000, &loaded)); assert(loaded == initial0);
    require_sym(xair_sym_memory_load8(state, 0x1001, &loaded)); assert(loaded == initial1);
    require_sym(xair_sym_object_add(state, 0x2000, 2, 1, &object));
    assert(xair_sym_memory_store_bytes(state, 0x2000, values, NULL, 2) == XAIR_SYM_ERR_RANGE);
    require_sym(xair_sym_object_add(state, UINT64_MAX, 1, 3, &object));
    assert(xair_sym_memory_store_bytes(state, UINT64_MAX, values, NULL, 2) == XAIR_SYM_ERR_RANGE);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { xair_value_id loaded; size_t calls; } endian_terminal;
static xair_sym_status check_big_endian_terminal(xair_sym_state *state, void *user) {
    endian_terminal *terminal = (endian_terminal *)user;
    xair_sym_expr_id loaded, byte0, byte1; uint64_t value;
    terminal->calls++;
    if (xair_sym_state_get_value(state, terminal->loaded, &loaded) != XAIR_SYM_OK ||
        xair_sym_model_u64(state, loaded, &value) != XAIR_SYM_OK || value != 0x1234u ||
        xair_sym_memory_load8(state, 0x9000, &byte0) != XAIR_SYM_OK ||
        xair_sym_memory_load8(state, 0x9001, &byte1) != XAIR_SYM_OK) return XAIR_SYM_ERR_INTERNAL;
    return xair_sym_model_u64(state, byte0, &value) == XAIR_SYM_OK && value == 0x12u &&
        xair_sym_model_u64(state, byte1, &value) == XAIR_SYM_OK && value == 0x34u ? XAIR_SYM_OK : XAIR_SYM_ERR_INTERNAL;
}

static void test_phase6_big_endian_memory_execution(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id memory, address, input, stored, loaded;
    xair_sym_expr_id address_expr, input_expr; xair_sym_object_id object; endian_terminal terminal;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "big_endian", &block));
    require_xair(xair_block_add_param(module, block, xair_type_mem(0, 64), "memory", &memory));
    require_xair(xair_block_add_param(module, block, xair_type_addr(64), "address", &address));
    require_xair(xair_block_add_param(module, block, xair_type_i(16), "input", &input));
    require_xair(xair_build_store(module, block, memory, address, input, XAIR_ENDIAN_BE, "stored", &stored));
    require_xair(xair_build_load(module, block, xair_type_i(16), stored, address, XAIR_ENDIAN_BE, "loaded", &loaded));
    require_xair(xair_set_return(module, block, &loaded, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_const(context, 64, 0x9000, &address_expr)); require_sym(xair_sym_const(context, 16, 0x1234, &input_expr));
    require_sym(xair_sym_state_set_value(state, address, address_expr)); require_sym(xair_sym_state_set_value(state, input, input_expr));
    require_sym(xair_sym_object_add(state, 0x9000, 2, 3, &object));
    terminal.loaded = loaded; terminal.calls = 0;
    require_sym(xair_sym_explore(state, 8, 8, check_big_endian_terminal, &terminal)); assert(terminal.calls == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_phase6_taint_details_and_sink(void) {
    xair_sym_context *context = NULL; xair_sym_taint_details details, loaded;
    xair_sym_taint_id source, sanitizer, validated, transformed, sink, queried; xair_sym_taint_view view;
    xair_sym_expr_id guard;
    memset(&details, 0, sizeof(details)); details.category = XAIR_SYM_TAINT_CATEGORY_NETWORK;
    details.source_address = 0x401000; details.call_site = 0x402000; details.byte_offset = 4;
    details.byte_length = 12; details.confidence = 4;
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_taint_source_ex(context, "recv", &details, &source));
    require_sym(xair_sym_taint_sanitize(context, source, "length_check", &sanitizer));
    require_sym(xair_sym_taint_get_details(context, sanitizer, &loaded)); assert(!loaded.sanitizer_validated);
    require_sym(xair_sym_taint_sanitize_ex(context, source, "bounds_check", 1, &validated));
    require_sym(xair_sym_taint_get_details(context, validated, &loaded)); assert(loaded.sanitizer_validated);
    require_sym(xair_sym_symbol(context, 1, "taint_guard", &guard));
    require_sym(xair_sym_taint_transform(context, validated, "guarded_copy", guard, 0, &transformed));
    require_sym(xair_sym_taint_get_details(context, transformed, &loaded)); assert(loaded.guard == guard);
    require_sym(xair_sym_taint_sink(context, transformed, "executable_memory", 0x500000, &sink));
    require_sym(xair_sym_taint_get(context, sink, &view)); assert(view.kind == XAIR_SYM_TAINT_NODE_SINK);
    require_sym(xair_sym_taint_get_details(context, sink, &loaded));
    assert(strcmp(loaded.sink, "executable_memory") == 0);
    assert(loaded.source_address == 0x401000 && loaded.sink_address == 0x500000);
    assert(xair_sym_taint_sink_count(context) == 1);
    require_sym(xair_sym_taint_sink_get(context, 0, &queried)); assert(queried == sink);
    assert(xair_sym_taint_sink_get(context, 1, &queried) == XAIR_SYM_ERR_RANGE && queried == XAIR_SYM_TAINT_NONE);
    xair_sym_context_destroy(context);
}

typedef struct { xair_sym_context *context; int expect_union; size_t calls; } symbolic_taint_terminal;
static xair_sym_status check_symbolic_overwrite_taint(xair_sym_state *state, void *user) {
    symbolic_taint_terminal *terminal = (symbolic_taint_terminal *)user;
    xair_sym_taint_id taint; xair_sym_taint_view view; xair_sym_taint_details details;
    terminal->calls++;
    if (xair_sym_memory_load_taint8(state, 0xa000, &taint) != XAIR_SYM_OK ||
        xair_sym_taint_get(terminal->context, taint, &view) != XAIR_SYM_OK) return XAIR_SYM_ERR_INTERNAL;
    if (terminal->expect_union) return view.kind == XAIR_SYM_TAINT_NODE_UNION ? XAIR_SYM_OK : XAIR_SYM_ERR_INTERNAL;
    if (xair_sym_taint_get_details(terminal->context, taint, &details) != XAIR_SYM_OK)
        return XAIR_SYM_ERR_INTERNAL;
    return view.kind == XAIR_SYM_TAINT_NODE_TRANSFORM &&
        strcmp(view.name, "symbolic_store_preserve_guard") == 0 &&
        details.guard != XAIR_SYM_INVALID_ID ? XAIR_SYM_OK : XAIR_SYM_ERR_INTERNAL;
}

static void test_phase6_symbolic_clean_and_guarded_taint_overwrite(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_block_id block; xair_value_id memory, address, data, stored; xair_sym_expr_id address_expr, data_expr;
    xair_sym_object_id object; xair_sym_taint_id old_taint, new_taint; symbolic_taint_terminal terminal;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "symbolic_taint_store", &block));
    require_xair(xair_block_add_param(module, block, xair_type_mem(0, 64), "memory", &memory));
    require_xair(xair_block_add_param(module, block, xair_type_addr(64), "address", &address));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "data", &data));
    require_xair(xair_build_store(module, block, memory, address, data, XAIR_ENDIAN_LE, "stored", &stored));
    require_xair(xair_set_return(module, block, NULL, 0)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 64, "symbolic_taint_address", &address_expr));
    require_sym(xair_sym_const(context, 8, 0, &data_expr));
    require_sym(xair_sym_state_set_value(state, address, address_expr)); require_sym(xair_sym_state_set_value(state, data, data_expr));
    require_sym(xair_sym_object_add(state, 0xa000, 2, 3, &object));
    require_sym(xair_sym_memory_store8(state, 0xa000, data_expr));
    require_sym(xair_sym_memory_store8(state, 0xa001, data_expr));
    require_sym(xair_sym_taint_source(context, "old_memory", &old_taint)); require_sym(xair_sym_taint_source(context, "new_data", &new_taint));
    require_sym(xair_sym_memory_store_taint8(state, 0xa000, old_taint)); require_sym(xair_sym_memory_store_taint8(state, 0xa001, old_taint));
    terminal.context = context; terminal.expect_union = 0; terminal.calls = 0;
    require_sym(xair_sym_explore(state, 8, 8, check_symbolic_overwrite_taint, &terminal)); assert(terminal.calls == 1);
    require_sym(xair_sym_state_set_taint(state, data, new_taint)); terminal.expect_union = 1; terminal.calls = 0;
    require_sym(xair_sym_explore(state, 8, 8, check_symbolic_overwrite_taint, &terminal)); assert(terminal.calls == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

static void test_phase6_sparse_checksummed_snapshot(void) {
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_sym_state *state = NULL;
    xair_sym_snapshot *snapshot = NULL, *loaded = NULL; xair_block_id block; xair_sym_object_id object;
    xair_sym_expr_id byte; xair_sym_snapshot_metadata metadata, expected; uint64_t before, after;
    const char *path = "xair_sym_sparse_snapshot.bin"; FILE *file; long size; int value; uint8_t *bytes;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "snapshot", &block));
    require_xair(xair_set_return(module, block, NULL, 0)); require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_object_add(state, UINT64_C(0x80000000), 16u * 1024u * 1024u, 3, &object));
    require_sym(xair_sym_const(context, 8, 0x5a, &byte)); require_sym(xair_sym_memory_store8(state, UINT64_C(0x80001234), byte));
    require_sym(xair_sym_snapshot_take(state, &snapshot)); require_sym(xair_sym_snapshot_metadata_get(snapshot, &metadata));
    assert(metadata.schema_version == 3 && metadata.memory_model_version == 2);
    require_sym(xair_sym_snapshot_fingerprint(snapshot, &before)); remove(path); require_sym(xair_sym_snapshot_save(snapshot, path));
    file = fopen(path, "rb+"); assert(file != NULL); assert(fseek(file, 0, SEEK_END) == 0); size = ftell(file);
    assert(size > 0 && size < 65536); bytes = (uint8_t *)malloc((size_t)size); assert(bytes != NULL);
    assert(fseek(file, 0, SEEK_SET) == 0 && fread(bytes, 1, (size_t)size, file) == (size_t)size);
    expected = metadata; expected.binary_hash ^= 1u; loaded = (xair_sym_snapshot *)(uintptr_t)1u;
    assert(xair_sym_snapshot_load_bytes_checked(context, module, bytes, (size_t)size, &expected,
        XAIR_SYM_SNAPSHOT_EXPECT_BINARY, &loaded) == XAIR_SYM_ERR_BAD_ARG && loaded == NULL);
    free(bytes);
    assert(fseek(file, 12, SEEK_SET) == 0); value = fgetc(file); assert(value != EOF);
    assert(fseek(file, 12, SEEK_SET) == 0); assert(fputc(value ^ 0x80, file) != EOF); assert(fclose(file) == 0);
    assert(xair_sym_snapshot_load(context, module, path, &loaded) == XAIR_SYM_ERR_BAD_ARG); remove(path);
    require_sym(xair_sym_snapshot_fingerprint(snapshot, &after)); assert(before == after);
    xair_sym_snapshot_destroy(snapshot); xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
}

typedef struct { xair_sym_context *context; xair_value_id values[4]; uint64_t expected[4]; size_t calls; } equivalence_terminal;
static xair_sym_status check_random_equivalence(xair_sym_state *state, void *user) {
    equivalence_terminal *terminal = (equivalence_terminal *)user;
    size_t i;
    terminal->calls++;
    for (i = 0; i < 4; ++i) {
        xair_sym_expr_id expression; xair_sym_expr_view view;
        if (xair_sym_state_get_value(state, terminal->values[i], &expression) != XAIR_SYM_OK ||
            xair_sym_expr_get(terminal->context, expression, &view) != XAIR_SYM_OK ||
            view.kind != XAIR_SYM_EXPR_CONST || view.immediate != terminal->expected[i]) return XAIR_SYM_ERR_INTERNAL;
    }
    return XAIR_SYM_OK;
}

static void test_phase6_random_concrete_symbolic_equivalence(void) {
    static const xair_opcode opcodes[4] = { XAIR_OP_ADD, XAIR_OP_SUB, XAIR_OP_XOR, XAIR_OP_ULT };
    xair_module *module = NULL; xair_sym_context *context = NULL; xair_block_id block;
    xair_value_id lhs, rhs, outputs[4]; uint64_t seed = UINT64_C(0x9e3779b97f4a7c15); size_t case_i, op_i;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "equivalence", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(64), "lhs", &lhs));
    require_xair(xair_block_add_param(module, block, xair_type_i(64), "rhs", &rhs));
    for (op_i = 0; op_i < 4; ++op_i)
        require_xair(xair_build_binary(module, block, opcodes[op_i], op_i == 3 ? xair_type_i(1) : xair_type_i(64),
            lhs, rhs, "result", &outputs[op_i]));
    require_xair(xair_set_return(module, block, outputs, 4)); require_sym(xair_sym_context_create(&context));
    for (case_i = 0; case_i < 256; ++case_i) {
        xair_exec_state *concrete = NULL; xair_exec_result concrete_result;
        xair_sym_state *symbolic = NULL; xair_sym_expr_id lhs_expr, rhs_expr; equivalence_terminal terminal;
        uint64_t left, right;
        seed = seed * UINT64_C(6364136223846793005) + 1; left = seed;
        seed = seed * UINT64_C(6364136223846793005) + 1; right = seed;
        require_xair(xair_exec_state_create(module, &concrete));
        require_xair(xair_exec_set_param(concrete, lhs, xair_exec_i(64, left)));
        require_xair(xair_exec_set_param(concrete, rhs, xair_exec_i(64, right)));
        require_xair(xair_exec_run(module, block, concrete, 8, &concrete_result)); assert(concrete_result.return_count == 4);
        memset(&terminal, 0, sizeof(terminal)); terminal.context = context;
        for (op_i = 0; op_i < 4; ++op_i) { terminal.values[op_i] = outputs[op_i]; terminal.expected[op_i] = concrete_result.returns[op_i].lo; }
        require_sym(xair_sym_state_create(context, module, block, &symbolic));
        require_sym(xair_sym_const(context, 64, left, &lhs_expr)); require_sym(xair_sym_const(context, 64, right, &rhs_expr));
        require_sym(xair_sym_state_set_value(symbolic, lhs, lhs_expr)); require_sym(xair_sym_state_set_value(symbolic, rhs, rhs_expr));
        require_sym(xair_sym_explore(symbolic, 2, 2, check_random_equivalence, &terminal)); assert(terminal.calls == 1);
        xair_sym_state_destroy(symbolic); xair_exec_state_destroy(concrete);
    }
    xair_sym_context_destroy(context); xair_module_destroy(module);
}

int main(void) {
    test_phase6_opcode_capability_table_is_complete();
    test_phase6_public_expression_shape_validation();
    test_phase6_sparse_paged_memory_and_overlap();
    test_phase6_atomic_multi_byte_store_boundaries();
    test_phase6_big_endian_memory_execution();
    test_phase6_taint_details_and_sink();
    test_phase6_symbolic_clean_and_guarded_taint_overwrite();
    test_phase6_sparse_checksummed_snapshot();
    test_phase6_random_concrete_symbolic_equivalence();
    test_solver_cancellation_reports_diagnostic();
    test_symbolic_and_taint_names_are_not_truncated();
    test_expression_interning_and_z3_model();
    test_symbolic_xair_branch_explores_both_paths();
    test_lazy_zero_flag_forks_symbolically();
    test_phase6_shift_flags_without_prior_flags_are_explicitly_incomplete();
    test_phase6_zero_count_shift_preserves_prior_flags();
    test_phase6_symbolic_shift_count_selects_explicit_prior_flags();
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
    test_phase6_failed_realloc_restores_memory_accounting();
    test_phase6_win64_process_abi_contract();
    test_snapshot_roundtrip_preserves_state();
    test_compiled_dispatch_and_cancellation();
    test_v03_unknown_branch_forks_both_paths();
    test_v03_symbolic_call_model_intercepts_call();
    test_phase6_unknown_win64_and_sysv_call_fallback();
    test_v03_z3_wide_constants_agree_with_concrete_bits();
    test_phase3_all_emitted_flag_extracts_translate_to_z3();
    test_phase6_logic_and_shift_af_are_stable_unknowns();
    test_phase3_x86_div_intrinsic_has_symbolic_value_model();
    test_parallel_isolated_workers();
    return 0;
}
