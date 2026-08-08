#include "xair_sym/xair_sym.h"
#include "../src/xair_sym_internal.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void require_sym(xair_sym_status status) {
    if (status != XAIR_SYM_OK) fprintf(stderr, "unexpected symbolic status: %s\n", xair_sym_status_name(status));
    assert(status == XAIR_SYM_OK);
}

static xair_sym_state *make_state(xair_sym_context **out_context, xair_module **out_module) {
    xair_sym_state *state = NULL;
    xair_block_id block;
    assert(xair_module_create(out_module) == XAIR_OK);
    assert(xair_block_create(*out_module, "entry", &block) == XAIR_OK);
    assert(xair_set_return(*out_module, block, NULL, 0) == XAIR_OK);
    require_sym(xair_sym_context_create(out_context));
    require_sym(xair_sym_state_create(*out_context, *out_module, block, &state));
    return state;
}

static void test_byte_vector_uses_one_model(void) {
    xair_sym_context *context = NULL;
    xair_module *module = NULL;
    xair_sym_state *state = make_state(&context, &module);
    xair_sym_expr_id symbols[2], sum, expected, condition;
    xair_sym_stats stats;
    uint8_t bytes[2] = {0, 0};
    require_sym(xair_sym_symbol(context, 8, "model_byte_x", &symbols[0]));
    require_sym(xair_sym_symbol(context, 8, "model_byte_y", &symbols[1]));
    require_sym(xair_sym_binary(context, XAIR_OP_ADD, 8, symbols[0], symbols[1], &sum));
    require_sym(xair_sym_const(context, 8, 0xa5, &expected));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, sum, expected, &condition));
    require_sym(xair_sym_state_assume(state, condition));
    require_sym(xair_sym_model_bytes(state, symbols, 2, bytes));
    assert((uint8_t)(bytes[0] + bytes[1]) == UINT8_C(0xa5));
    xair_sym_context_stats(context, &stats);
    assert(stats.solver_queries == 1);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
}

static void test_wide_value_uses_one_model(void) {
    xair_sym_context *context = NULL;
    xair_module *module = NULL;
    xair_sym_state *state = make_state(&context, &module);
    xair_sym_expr_id wide, low, high, relation;
    xair_sym_stats stats;
    uint64_t modeled_low = 0, modeled_high = 0;
    require_sym(xair_sym_symbol(context, 128, "model_wide", &wide));
    require_sym(xair_sym_unary(context, XAIR_OP_EXTRACT, 64, wide, 0, &low));
    require_sym(xair_sym_unary(context, XAIR_OP_EXTRACT, 64, wide, 64, &high));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, low, high, &relation));
    require_sym(xair_sym_state_assume(state, relation));
    require_sym(xair_sym_model_wide(state, wide, &modeled_low, &modeled_high));
    assert(modeled_low == modeled_high);
    xair_sym_context_stats(context, &stats);
    assert(stats.solver_queries == 1);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
}

static void test_solver_memory_limit_is_explicit(void) {
    xair_sym_context *context = NULL;
    xair_module *module = NULL;
    xair_sym_state *state = make_state(&context, &module);
    xair_sym_expr_id symbol;
    xair_analysis_options options;
    xair_diagnostic diagnostic;
    xair_sym_sat sat = XAIR_SYM_SAT;
    xair_sym_stats stats;
    require_sym(xair_sym_symbol(context, 8, "limited", &symbol));
    xair_analysis_options_init(&options);
    options.max_memory = 1;
    xair_sym_context_set_analysis_options(context, &options);
    assert(xair_sym_check_ex(state, XAIR_SYM_INVALID_ID, &sat, &diagnostic) == XAIR_SYM_ERR_RESOURCE_LIMIT);
    assert(sat == XAIR_SYM_UNKNOWN);
    assert(diagnostic.status == XAIR_ERR_RESOURCE_LIMIT && diagnostic.stage == XAIR_STAGE_SOLVER);
    xair_sym_context_stats(context, &stats);
    assert(stats.solver_unknown == 1);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
}

static void test_parallel_workers_share_solver_budget_without_cross_charging(void) {
    xair_module *module = NULL;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_snapshot *snapshot = NULL;
    xair_block_id entry, left, right;
    xair_value_id condition_value;
    xair_sym_expr_id condition;
    xair_sym_parallel_options options;
    xair_sym_explore_result result;
    xair_diagnostic diagnostic;
    assert(xair_module_create(&module) == XAIR_OK);
    assert(xair_block_create(module, "entry", &entry) == XAIR_OK);
    assert(xair_block_create(module, "left", &left) == XAIR_OK);
    assert(xair_block_create(module, "right", &right) == XAIR_OK);
    assert(xair_block_add_param(module, entry, xair_type_i(1), "condition", &condition_value) == XAIR_OK);
    assert(xair_set_cbranch(module, entry, condition_value, left, NULL, 0, right, NULL, 0) == XAIR_OK);
    assert(xair_set_return(module, left, NULL, 0) == XAIR_OK);
    assert(xair_set_return(module, right, NULL, 0) == XAIR_OK);
    assert(xair_module_freeze(module) == XAIR_OK);
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, entry, &state));
    require_sym(xair_sym_symbol(context, 1, "parallel_solver_condition", &condition));
    require_sym(xair_sym_state_set_value(state, condition_value, condition));
    require_sym(xair_sym_snapshot_take(state, &snapshot));
    xair_sym_parallel_options_init(&options);
    options.workers = 2;
    options.explore.max_states = 8;
    options.explore.max_block_steps = 8;
    options.explore.analysis.max_memory = 128u * 1024u * 1024u;
    require_sym(xair_sym_parallel_explore_detailed(snapshot, &options, NULL, NULL,
        &result, &diagnostic));
    assert(result.workers_started == 2);
    assert(result.terminal_states == 2);
    assert(result.peak_memory_bytes <= options.explore.analysis.max_memory);
    xair_sym_snapshot_destroy(snapshot);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
}

static void test_limited_queries_reuse_translation_runtime(void) {
    xair_sym_context *context = NULL;
    xair_module *module = NULL;
    xair_sym_state *state = make_state(&context, &module);
    xair_sym_expr_id symbols[2], sum, expected, condition;
    xair_analysis_options options;
    xair_sym_stats before, after;
    uint8_t bytes[2];
    require_sym(xair_sym_symbol(context, 8, "limited_reuse_x", &symbols[0]));
    require_sym(xair_sym_symbol(context, 8, "limited_reuse_y", &symbols[1]));
    require_sym(xair_sym_binary(context, XAIR_OP_ADD, 8, symbols[0], symbols[1], &sum));
    require_sym(xair_sym_const(context, 8, 0x5a, &expected));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, sum, expected, &condition));
    require_sym(xair_sym_state_assume(state, condition));
    xair_analysis_options_init(&options);
    options.max_memory = 128u * 1024u * 1024u;
    xair_sym_context_set_analysis_options(context, &options);
    require_sym(xair_sym_model_bytes(state, symbols, 2, bytes));
    xair_sym_context_stats(context, &before);
    require_sym(xair_sym_model_bytes(state, symbols, 2, bytes));
    xair_sym_context_stats(context, &after);
    assert(after.solver_queries == before.solver_queries + 1);
    assert(after.solver_translation_hits > before.solver_translation_hits);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
}

static void initialize_test_budget(xair_sym_parallel_budget *budget, size_t maximum) {
    memset(budget, 0, sizeof(*budget));
    assert(xair_mutex_init(&budget->lock));
    budget->max_memory = maximum;
    budget->remaining_memory = maximum;
}

static void test_solver_caches_charge_shared_budget(void) {
    enum { symbol_count = 48 };
    xair_module *module = NULL;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_expr_id symbols[symbol_count];
    xair_sym_parallel_budget budget;
    xair_block_id block;
    size_t i, used, expected_cache_bytes;
    uint64_t modeled;
    assert(xair_module_create(&module) == XAIR_OK);
    assert(xair_block_create(module, "cache_budget", &block) == XAIR_OK);
    assert(xair_set_return(module, block, NULL, 0) == XAIR_OK);
    assert(xair_module_freeze(module) == XAIR_OK);
    require_sym(xair_sym_context_create(&context));
    initialize_test_budget(&budget, 128u * 1024u * 1024u);
    context->parallel_budget = &budget;
    require_sym(xair_sym_state_create(context, module, block, &state));
    for (i = 0; i < symbol_count; ++i) {
        char name[32];
        (void)snprintf(name, sizeof(name), "budget_symbol_%u", (unsigned)i);
        require_sym(xair_sym_symbol(context, 1, name, &symbols[i]));
    }
    for (i = 0; i < 45; ++i) {
        xair_sym_sat sat;
        require_sym(xair_sym_check(state, symbols[i], &sat));
        assert(sat == XAIR_SYM_SAT);
    }
    for (i = 0; i < 17; ++i) require_sym(xair_sym_model_u64(state, symbols[i], &modeled));
    assert(context->query_cache_capacity == 128);
    assert(context->model_cache_capacity == 32);
    expected_cache_bytes = context->query_cache_capacity * sizeof(*context->query_cache) +
        context->model_cache_capacity * sizeof(*context->model_cache);
    used = budget.max_memory - budget.remaining_memory;
    assert(used == context->parallel_memory_reserved);
    assert(used >= expected_cache_bytes);
    assert(budget.peak_memory >= used);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    assert(budget.remaining_memory == budget.max_memory);
    xair_mutex_destroy(&budget.lock);
    xair_module_destroy(module);
}

static void test_query_cache_growth_hits_shared_cap(void) {
    enum { symbol_count = 45 };
    xair_module *module = NULL;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_expr_id symbols[symbol_count];
    xair_sym_parallel_budget budget;
    xair_block_id block;
    size_t i;
    const size_t next_cache_allocation = 128u * sizeof(xair_sym_query_cache_entry);
    assert(xair_module_create(&module) == XAIR_OK);
    assert(xair_block_create(module, "cache_cap", &block) == XAIR_OK);
    assert(xair_set_return(module, block, NULL, 0) == XAIR_OK);
    assert(xair_module_freeze(module) == XAIR_OK);
    require_sym(xair_sym_context_create(&context));
    initialize_test_budget(&budget, 128u * 1024u * 1024u);
    context->parallel_budget = &budget;
    require_sym(xair_sym_state_create(context, module, block, &state));
    for (i = 0; i < symbol_count; ++i) {
        char name[32];
        (void)snprintf(name, sizeof(name), "cap_symbol_%u", (unsigned)i);
        require_sym(xair_sym_symbol(context, 1, name, &symbols[i]));
    }
    for (i = 0; i < 44; ++i) {
        xair_sym_sat sat;
        require_sym(xair_sym_check(state, symbols[i], &sat));
    }
    xair_mutex_lock(&budget.lock);
    budget.remaining_memory = 1024u * 1024u + next_cache_allocation - 1u;
    xair_mutex_unlock(&budget.lock);
    {
        xair_sym_sat sat;
        assert(xair_sym_check(state, symbols[44], &sat) == XAIR_SYM_ERR_RESOURCE_LIMIT);
    }
    xair_mutex_lock(&budget.lock);
    budget.remaining_memory = budget.max_memory - context->parallel_memory_reserved;
    xair_mutex_unlock(&budget.lock);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_mutex_destroy(&budget.lock);
    xair_module_destroy(module);
}

static void test_symbolic_zero_shift_select_preserves_prior_flags(void) {
    xair_sym_context *context = NULL;
    xair_module *module = NULL;
    xair_sym_state *state = make_state(&context, &module);
    xair_sym_expr_id count, value_ff, value_one, count_zero, prior_flags, prior_flags_clear, shifted_flags;
    xair_sym_expr_id count_is_zero, selected_flags, selected_flags_clear, carry, carry_clear;
    xair_sym_expr_id bit_one, bit_zero, carry_one, carry_zero, clear_is_zero;
    xair_sym_sat sat;
    require_sym(xair_sym_symbol(context, 8, "symbolic_shift_count", &count));
    require_sym(xair_sym_const(context, 8, 0xff, &value_ff));
    require_sym(xair_sym_const(context, 8, 1, &value_one));
    require_sym(xair_sym_const(context, 8, 0, &count_zero));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_ADD, 6,
        value_ff, value_one, &prior_flags));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_ADD, 6,
        value_one, value_one, &prior_flags_clear));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_SHL, 6,
        value_one, count, &shifted_flags));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1,
        count, count_zero, &count_is_zero));
    require_sym(xair_sym_select(context, count_is_zero,
        prior_flags, shifted_flags, &selected_flags));
    require_sym(xair_sym_select(context, count_is_zero,
        prior_flags_clear, shifted_flags, &selected_flags_clear));
    require_sym(xair_sym_unary(context, XAIR_OP_FLAG_CF, 1,
        selected_flags, 0, &carry));
    require_sym(xair_sym_unary(context, XAIR_OP_FLAG_CF, 1,
        selected_flags_clear, 0, &carry_clear));
    require_sym(xair_sym_const(context, 1, 1, &bit_one));
    require_sym(xair_sym_const(context, 1, 0, &bit_zero));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, carry, bit_one, &carry_one));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, carry, bit_zero, &carry_zero));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1,
        carry_clear, bit_zero, &clear_is_zero));
    require_sym(xair_sym_state_assume(state, count_is_zero));
    require_sym(xair_sym_check(state, carry_one, &sat));
    assert(sat == XAIR_SYM_SAT);
    require_sym(xair_sym_check(state, carry_zero, &sat));
    assert(sat == XAIR_SYM_UNSAT);
    require_sym(xair_sym_check(state, clear_is_zero, &sat));
    assert(sat == XAIR_SYM_SAT);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
}

int main(void) {
    test_symbolic_zero_shift_select_preserves_prior_flags();
    test_byte_vector_uses_one_model();
    test_wide_value_uses_one_model();
    test_solver_memory_limit_is_explicit();
    test_parallel_workers_share_solver_budget_without_cross_charging();
    test_limited_queries_reuse_translation_runtime();
    test_solver_caches_charge_shared_budget();
    test_query_cache_growth_hits_shared_cap();
    return 0;
}
