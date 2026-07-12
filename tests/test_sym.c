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
    xair_block_id block; xair_value_id value; xair_sym_expr_id x, one, sum0, sum1, answer, condition;
    xair_sym_sat sat; uint64_t model; xair_sym_stats stats;
    require_xair(xair_module_create(&module)); require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value)); require_xair(xair_set_return(module, block, &value, 1));
    require_sym(xair_sym_context_create(&context)); require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "x", &x)); require_sym(xair_sym_const(context, 8, 1, &one));
    require_sym(xair_sym_binary(context, XAIR_OP_ADD, 8, x, one, &sum0));
    require_sym(xair_sym_binary(context, XAIR_OP_ADD, 8, x, one, &sum1)); assert(sum0 == sum1);
    require_sym(xair_sym_const(context, 8, 42, &answer)); require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, sum0, answer, &condition));
    require_sym(xair_sym_state_assume(state, condition)); require_sym(xair_sym_check(state, XAIR_SYM_INVALID_ID, &sat)); assert(sat == XAIR_SYM_SAT);
    require_sym(xair_sym_model_u64(state, x, &model)); assert(model == 41);
    xair_sym_context_stats(context, &stats); assert(stats.expressions_reused >= 1); assert(stats.solver_queries == 2);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context); xair_module_destroy(module);
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

int main(void) {
    test_expression_interning_and_z3_model();
    test_symbolic_xair_branch_explores_both_paths();
    test_lazy_zero_flag_forks_symbolically();
    test_object_memory_is_copy_on_write();
    test_symbolic_address_resolves_inside_object();
    return 0;
}
