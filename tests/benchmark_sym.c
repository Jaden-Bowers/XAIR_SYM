#include "xair_sym/xair_sym.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#if !defined(_WIN32)
#include <sys/resource.h>
#endif

static uint64_t elapsed_ms(clock_t started) {
    return (uint64_t)(clock() - started) * UINT64_C(1000) / (uint64_t)CLOCKS_PER_SEC;
}

static uint64_t peak_kib(void) {
#if defined(_WIN32)
    return 0;
#else
    struct rusage usage;
    return getrusage(RUSAGE_SELF, &usage) == 0 ? (uint64_t)usage.ru_maxrss : 0;
#endif
}

int main(void) {
    xair_module *module = NULL;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL, *clone = NULL;
    xair_block_id block;
    xair_value_id parameter;
    xair_sym_object_id object;
    xair_sym_expr_id symbol, constant, equality;
    xair_sym_sat sat;
    xair_sym_stats stats;
    xair_sym_explore_options options;
    xair_sym_explore_result result;
    xair_diagnostic diagnostic;
    clock_t started;
    uint64_t clone_time, write_time, solver_time, explore_time;
    size_t i;
    xair_module *explore_module = NULL;
    xair_sym_context *explore_context = NULL;
    xair_sym_state *explore_state = NULL;
    xair_block_id *chain = NULL;
    if (xair_module_create(&module) != XAIR_OK || xair_block_create(module, "bench", &block) != XAIR_OK ||
        xair_block_add_param(module, block, xair_type_i(64), "input", &parameter) != XAIR_OK ||
        xair_set_return(module, block, &parameter, 1) != XAIR_OK || xair_sym_context_create(&context) != XAIR_SYM_OK ||
        xair_sym_state_create(context, module, block, &state) != XAIR_SYM_OK ||
        xair_sym_symbol(context, 64, "benchmark_input", &symbol) != XAIR_SYM_OK ||
        xair_sym_state_set_value(state, parameter, symbol) != XAIR_SYM_OK ||
        xair_sym_object_add(state, UINT64_C(0x100000000), 100u * 1024u * 1024u, 3u, &object) != XAIR_SYM_OK) return 1;
    xair_sym_context_stats(context, &stats);
    if (stats.memory_pages != 0) return 1;
    started = clock();
    for (i = 0; i < 2000; ++i) {
        if (xair_sym_state_clone(state, &clone) != XAIR_SYM_OK) return 1;
        xair_sym_state_destroy(clone); clone = NULL;
    }
    clone_time = elapsed_ms(started);
    if (xair_sym_state_clone(state, &clone) != XAIR_SYM_OK || xair_sym_const(context, 8, 0x5a, &constant) != XAIR_SYM_OK) return 1;
    started = clock();
    if (xair_sym_memory_store8(clone, UINT64_C(0x100001234), constant) != XAIR_SYM_OK) return 1;
    write_time = elapsed_ms(started);
    started = clock();
    if (xair_sym_const(context, 64, 42, &constant) != XAIR_SYM_OK ||
        xair_sym_binary(context, XAIR_OP_EQ, 1, symbol, constant, &equality) != XAIR_SYM_OK ||
        xair_sym_check(state, equality, &sat) != XAIR_SYM_OK ||
        xair_sym_const(context, 64, 43, &constant) != XAIR_SYM_OK ||
        xair_sym_binary(context, XAIR_OP_EQ, 1, symbol, constant, &equality) != XAIR_SYM_OK ||
        xair_sym_check(state, equality, &sat) != XAIR_SYM_OK) return 1;
    solver_time = elapsed_ms(started);
    chain = (xair_block_id *)malloc(2001u * sizeof(*chain));
    if (chain == NULL || xair_module_create(&explore_module) != XAIR_OK) return 1;
    for (i = 0; i < 2001u; ++i)
        if (xair_block_create(explore_module, "chain", &chain[i]) != XAIR_OK) return 1;
    for (i = 0; i < 2000u; ++i)
        if (xair_set_jump(explore_module, chain[i], chain[i + 1], NULL, 0) != XAIR_OK) return 1;
    if (xair_set_return(explore_module, chain[2000], NULL, 0) != XAIR_OK ||
        xair_sym_context_create(&explore_context) != XAIR_SYM_OK ||
        xair_sym_state_create(explore_context, explore_module, chain[0], &explore_state) != XAIR_SYM_OK) return 1;
    xair_sym_explore_options_init(&options); options.max_states = 2000; options.max_block_steps = 2000;
    started = clock();
    if (xair_sym_explore_detailed(explore_state, &options, NULL, NULL, &result, &diagnostic) != XAIR_SYM_ERR_RESOURCE_LIMIT ||
        result.states_processed != 2000 || result.completion_reason != XAIR_SYM_LIMIT_REACHED) return 1;
    explore_time = elapsed_ms(started);
    xair_sym_context_stats(context, &stats);
    printf("{\"mapped_bytes\":104857600,\"peak_kib\":%llu,\"lazy_pages_before_write\":0,"
        "\"clone_without_writes_near_o1\":%s,\"clone_2000_ms\":%llu,"
        "\"one_byte_write_ms\":%llu,\"page_copies\":%zu,\"page_copy_bound\":1,"
        "\"solver_related_queries_ms\":%llu,\"solver_translation_hits\":%zu,"
        "\"explore_budget\":2000,\"explore_ms\":%llu,\"states_processed\":%zu}\n",
        (unsigned long long)peak_kib(), clone_time < 1000 ? "true" : "false", (unsigned long long)clone_time,
        (unsigned long long)write_time, stats.memory_page_copies,
        (unsigned long long)solver_time, stats.solver_translation_hits,
        (unsigned long long)explore_time, result.states_processed);
    xair_sym_state_destroy(clone); xair_sym_state_destroy(state);
    xair_sym_context_destroy(context); xair_module_destroy(module);
    xair_sym_state_destroy(explore_state); xair_sym_context_destroy(explore_context);
    xair_module_destroy(explore_module); free(chain);
    return 0;
}
