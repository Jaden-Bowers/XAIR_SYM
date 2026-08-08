#include "xair_sym/xair_sym.h"
#include "../src/xair_sym_internal.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void xair_sym_test_state_destroy(xair_sym_state *state);

/* Compile a private copy so the scheduler's defensive predicates can be
 * driven deterministically without changing the public API. */
#define xair_sym_state_create xair_sym_test_state_create
#define xair_sym_state_clone xair_sym_test_state_clone
#define xair_sym_state_destroy xair_sym_test_state_destroy
#define xair_sym_state_set_value xair_sym_test_state_set_value
#define xair_sym_state_get_value xair_sym_test_state_get_value
#define xair_sym_state_set_call_model xair_sym_test_state_set_call_model
#define xair_sym_state_assume xair_sym_test_state_assume
#define xair_sym_state_block xair_sym_test_state_block
#define xair_sym_explore_options_init xair_sym_test_explore_options_init
#define xair_sym_explore_with_options_ex xair_sym_test_explore_with_options_ex
#define xair_sym_explore_with_options xair_sym_test_explore_with_options
#define xair_sym_explore_detailed xair_sym_test_explore_detailed
#define xair_sym_explore xair_sym_test_explore
#include "../src/xair_sym_exec.c"
#undef xair_sym_state_create
#undef xair_sym_state_clone
#undef xair_sym_state_destroy
#undef xair_sym_state_set_value
#undef xair_sym_state_get_value
#undef xair_sym_state_set_call_model
#undef xair_sym_state_assume
#undef xair_sym_state_block
#undef xair_sym_explore_options_init
#undef xair_sym_explore_with_options_ex
#undef xair_sym_explore_with_options
#undef xair_sym_explore_detailed
#undef xair_sym_explore

static void require_xair(xair_status status) { assert(status == XAIR_OK); }
static void require_sym(xair_sym_status status) { assert(status == XAIR_SYM_OK); }

typedef struct {
    xair_module *module;
    xair_block_id block;
    xair_value_id value;
    xair_sym_context *context;
    xair_sym_state *state;
    xair_sym_expr_id symbol;
    xair_sym_expr_id one;
    xair_sym_expr_id guard;
    xair_sym_taint_id source;
} fixture;

static void fixture_init(fixture *f) {
    xair_sym_object_id object;
    memset(f, 0, sizeof(*f));
    require_xair(xair_module_create(&f->module));
    require_xair(xair_block_create(f->module, "exec_internal", &f->block));
    require_xair(xair_block_add_param(f->module, f->block, xair_type_i(8), "v", &f->value));
    require_xair(xair_set_return(f->module, f->block, &f->value, 1));
    require_xair(xair_module_freeze(f->module));
    require_sym(xair_sym_context_create(&f->context));
    require_sym(xair_sym_state_create(f->context, f->module, f->block, &f->state));
    require_sym(xair_sym_symbol(f->context, 8, "exec_symbol", &f->symbol));
    require_sym(xair_sym_const(f->context, 8, 1, &f->one));
    require_sym(xair_sym_binary(f->context, XAIR_OP_EQ, 1, f->symbol, f->one, &f->guard));
    require_sym(xair_sym_state_set_value(f->state, f->value, f->symbol));
    require_sym(xair_sym_taint_source(f->context, "exec_source", &f->source));
    require_sym(xair_sym_state_set_taint(f->state, f->value, f->source));
    require_sym(xair_sym_object_add(f->state, 0x4000, 2, 3, &object));
    require_sym(xair_sym_memory_store8(f->state, 0x4000, f->symbol));
    require_sym(xair_sym_memory_store_taint8(f->state, 0x4000, f->source));
    require_sym(xair_sym_state_assume(f->state, f->guard));
}

static void fixture_destroy(fixture *f) {
    xair_sym_state_destroy(f->state);
    xair_sym_context_destroy(f->context);
    xair_module_destroy(f->module);
}

static void test_address_and_control(fixture *f) {
    xair_sym_expr_id address, concrete;
    uint64_t value;
    xair_block_id postdominators[1] = {7};
    assert(expression_constant(f->state, f->symbol, &value) == XAIR_SYM_ERR_UNSUPPORTED);
    assert(offset_symbolic_address(NULL, f->symbol, 1, &address) == XAIR_SYM_ERR_BAD_ARG);
    assert(offset_symbolic_address(f->state, f->symbol, 1, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(offset_symbolic_address(f->state, 9999, 1, &address) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(offset_symbolic_address(f->state, f->symbol, 0, &address));
    assert(address == f->symbol);
    require_sym(offset_symbolic_address(f->state, f->symbol, 3, &address));
    assert(address != XAIR_SYM_INVALID_ID);
    assert(concretize_memory_address(NULL, f->symbol, &value) == XAIR_SYM_ERR_BAD_ARG);
    assert(concretize_memory_address(f->state, f->symbol, NULL) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(concretize_memory_address(f->state, f->symbol, &value));
    require_sym(xair_sym_const(f->context, 8, value, &concrete));
    assert(f->context->stats.concretizations == 1);

    require_sym(push_control_scope(f->state, XAIR_SYM_TAINT_NONE));
    require_sym(push_control_scope(f->state, f->source));
    assert(f->state->control_scope_count == 0 && f->state->control_taint != XAIR_SYM_TAINT_NONE);
    f->context->immediate_postdominators = postdominators;
    f->context->immediate_postdominator_count = 1;
    f->state->control_taint = XAIR_SYM_TAINT_NONE;
    require_sym(push_control_scope(f->state, f->source));
    assert(f->state->control_scope_count == 1);
    f->state->control_scopes[1] = f->state->control_scopes[0];
    f->state->control_scopes[1].postdominator = f->block;
    f->state->control_scope_count = 2;
    require_sym(refresh_control_taint(f->state));
    assert(f->state->control_scope_count == 1);
    f->state->block = 7;
    require_sym(refresh_control_taint(f->state));
    assert(f->state->control_scope_count == 0 && f->state->control_taint == XAIR_SYM_TAINT_NONE);
    require_sym(refresh_control_taint(f->state));
    f->state->block = f->block;
    f->state->control_scope_count = 32;
    assert(push_control_scope(f->state, f->source) == XAIR_SYM_ERR_RESOURCE_LIMIT);
    f->state->control_scope_count = 0;
    f->context->immediate_postdominators = NULL;
    f->context->immediate_postdominator_count = 0;
}

static void test_public_defenses(fixture *f) {
    xair_sym_state *state = NULL;
    xair_sym_expr_id expression;
    xair_sym_explore_options options;
    xair_analysis_result result;
    xair_sym_explore_result detailed_result;
    xair_diagnostic diagnostic;
    assert(xair_sym_test_state_create(NULL, f->module, f->block, &state) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_create(f->context, NULL, f->block, &state) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_create(f->context, f->module, f->block, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_create(f->context, f->module, 9999, &state) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_clone(NULL, &state) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_clone(f->state, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_set_value(NULL, f->value, f->symbol) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_set_value(f->state, 9999, f->symbol) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_set_value(f->state, f->value, 9999) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_set_value(f->state, f->value, f->guard) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_get_value(NULL, f->value, &expression) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_get_value(f->state, f->value, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_get_value(f->state, 9999, &expression) == XAIR_SYM_ERR_BAD_ARG);
    f->state->defined[f->value] = 0;
    assert(xair_sym_test_state_get_value(f->state, f->value, &expression) == XAIR_SYM_ERR_BAD_ARG);
    f->state->defined[f->value] = 1;
    assert(xair_sym_test_state_assume(NULL, f->guard) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_assume(f->state, 9999) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_assume(f->state, f->symbol) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_state_block(NULL) == XAIR_INVALID_ID);
    xair_sym_test_explore_options_init(NULL);
    xair_sym_test_explore_options_init(&options);
#define BAD_OPTION(field, value) do { xair_sym_explore_options saved = options; options.field = (value); assert(xair_sym_test_explore_with_options_ex(f->state, &options, NULL, NULL, &result, &diagnostic) == XAIR_SYM_ERR_BAD_ARG); options = saved; } while (0)
    assert(xair_sym_test_explore_with_options_ex(NULL, &options, NULL, NULL, &result, &diagnostic) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_explore_with_options_ex(f->state, NULL, NULL, NULL, &result, &diagnostic) == XAIR_SYM_ERR_BAD_ARG);
    BAD_OPTION(max_states, 0); BAD_OPTION(max_block_steps, 0); BAD_OPTION(max_visits_per_block, 0);
    BAD_OPTION(search, (xair_sym_search_policy)99);
    BAD_OPTION(execution_mode, (xair_sym_execution_mode)99);
#undef BAD_OPTION
    assert(xair_sym_test_explore_detailed(NULL, &options, NULL, NULL, &detailed_result, &diagnostic) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_explore_detailed(f->state, NULL, NULL, NULL, &detailed_result, &diagnostic) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_test_explore_detailed(f->state, &options, NULL, NULL, NULL, &diagnostic) == XAIR_SYM_ERR_BAD_ARG);
}

static void test_queue(fixture *f) {
    xair_sym_state **queue = NULL;
    size_t count = 0, capacity = 0, cursor = 0;
    size_t visits[8] = {0};
    require_sym(enqueue(&queue, &count, &capacity, f->state));
    assert(dequeue(queue, count, &cursor, XAIR_SYM_SEARCH_DFS, visits) == f->state);
    assert(dequeue(queue, count, &cursor, XAIR_SYM_SEARCH_DFS, visits) == NULL);
    queue[0] = f->state; cursor = 0;
    assert(dequeue(queue, count, &cursor, XAIR_SYM_SEARCH_COVERAGE, visits) == f->state);
    queue[0] = f->state; cursor = 0; visits[f->state->block] = 1;
    assert(dequeue(queue, count, &cursor, XAIR_SYM_SEARCH_COVERAGE, visits) == f->state);
    assert(dequeue(queue, count, &cursor, XAIR_SYM_SEARCH_BFS, visits) == NULL);
    free(queue);
    xair_sym_parallel_memory_release(f->context, capacity * sizeof(*queue));
    queue = NULL; count = SIZE_MAX; capacity = SIZE_MAX;
    assert(enqueue(&queue, &count, &capacity, f->state) == XAIR_SYM_ERR_RESOURCE_LIMIT);
}

static void test_exact_equality(fixture *f) {
    xair_sym_state *clone = NULL;
    xair_sym_expr_id second_guard;
    xair_sym_page *saved_page;
    uint64_t saved_u64;
    size_t saved_size;
    uint32_t saved_u32;
    uint8_t saved_u8;
    static const uint8_t changed_backing[1] = {0xff};
    require_sym(xair_sym_state_clone(f->state, &clone));
    require_sym(xair_sym_memory_store8(clone, 0x4001, f->one));
    require_sym(xair_sym_memory_store8(f->state, 0x4001, f->one));
    assert(exact_constraints_equal(f->state->constraints, clone->constraints));
    assert(exact_constraints_equal(NULL, NULL));
    assert(!exact_constraints_equal(f->state->constraints, NULL));
    require_sym(xair_sym_binary(f->context, XAIR_OP_NE, 1, f->symbol, f->one, &second_guard));
    require_sym(xair_sym_state_assume(clone, second_guard));
    assert(!exact_constraints_equal(f->state->constraints, clone->constraints));
    constraint_release(clone->constraints); clone->constraints = f->state->constraints;
    constraint_retain(clone->constraints);

    assert(exact_memory_equal(f->state->memory, clone->memory));
    clone->memory->count = 0; assert(!exact_memory_equal(f->state->memory, clone->memory)); clone->memory->count = 1;
#define DIFFER_FIELD(field, value) do { saved_u64 = clone->memory->objects[0].field; clone->memory->objects[0].field = (value); assert(!exact_memory_equal(f->state->memory, clone->memory)); clone->memory->objects[0].field = saved_u64; } while (0)
    DIFFER_FIELD(base, 0x5000);
    saved_size = clone->memory->objects[0].size; clone->memory->objects[0].size++; assert(!exact_memory_equal(f->state->memory, clone->memory)); clone->memory->objects[0].size = saved_size;
    saved_u32 = clone->memory->objects[0].permissions; clone->memory->objects[0].permissions ^= 1u; assert(!exact_memory_equal(f->state->memory, clone->memory)); clone->memory->objects[0].permissions = saved_u32;
    saved_u8 = clone->memory->objects[0].zero_fill; clone->memory->objects[0].zero_fill ^= 1u; assert(!exact_memory_equal(f->state->memory, clone->memory)); clone->memory->objects[0].zero_fill = saved_u8;
    saved_size = clone->memory->objects[0].backing_size; clone->memory->objects[0].backing_size = 1; assert(!exact_memory_equal(f->state->memory, clone->memory)); clone->memory->objects[0].backing_size = saved_size;
    {
        static const uint8_t original_backing[1] = {0};
        const uint8_t *left_backing = f->state->memory->objects[0].backing;
        const uint8_t *right_backing = clone->memory->objects[0].backing;
        f->state->memory->objects[0].backing_size = 1; clone->memory->objects[0].backing_size = 1;
        f->state->memory->objects[0].backing = original_backing; clone->memory->objects[0].backing = changed_backing;
        assert(!exact_memory_equal(f->state->memory, clone->memory));
        f->state->memory->objects[0].backing_size = saved_size; clone->memory->objects[0].backing_size = saved_size;
        f->state->memory->objects[0].backing = left_backing; clone->memory->objects[0].backing = right_backing;
    }
    saved_size = clone->memory->objects[0].page_count; clone->memory->objects[0].page_count = 0; assert(!exact_memory_equal(f->state->memory, clone->memory)); clone->memory->objects[0].page_count = saved_size;
    saved_page = clone->memory->objects[0].pages[0]; clone->memory->objects[0].pages[0] = NULL; assert(!exact_memory_equal(f->state->memory, clone->memory)); clone->memory->objects[0].pages[0] = saved_page;
    {
        xair_sym_page *left_page = f->state->memory->objects[0].pages[0];
        f->state->memory->objects[0].pages[0] = NULL; clone->memory->objects[0].pages[0] = NULL;
        assert(exact_memory_equal(f->state->memory, clone->memory));
        f->state->memory->objects[0].pages[0] = left_page; clone->memory->objects[0].pages[0] = saved_page;
    }
    saved_u64 = saved_page->bytes[0]; saved_page->bytes[0] = f->one; assert(!exact_memory_equal(f->state->memory, clone->memory)); saved_page->bytes[0] = (xair_sym_expr_id)saved_u64;
    saved_u64 = saved_page->taints[0]; saved_page->taints[0] = XAIR_SYM_TAINT_NONE; assert(!exact_memory_equal(f->state->memory, clone->memory)); saved_page->taints[0] = (xair_sym_taint_id)saved_u64;
#undef DIFFER_FIELD
    xair_sym_state_destroy(clone);
}

static void test_seen_state(fixture *f) {
    xair_sym_seen_state *seen = NULL;
    size_t count = 0, capacity = 0;
    int duplicate = -1;
    uint64_t saved_u64;
    size_t saved_size;
    uint8_t saved_u8;
    assert(remember_state(f->state, &seen, &count, &capacity, NULL) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(remember_state(f->state, &seen, &count, &capacity, &duplicate));
    assert(!duplicate && count == 1 && state_matches_seen(f->state, &seen[0]));
#define DIFFER_SEEN_TYPED(field, type) do { \
        type saved = seen[0].field; \
        seen[0].field++; \
        assert(!state_matches_seen(f->state, &seen[0])); \
        seen[0].field = saved; \
    } while (0)
    DIFFER_SEEN_TYPED(block, xair_block_id);
    DIFFER_SEEN_TYPED(constraint_hash, uint64_t);
    DIFFER_SEEN_TYPED(memory_hash, uint64_t);
    DIFFER_SEEN_TYPED(value_count, size_t);
    DIFFER_SEEN_TYPED(control_taint, xair_sym_taint_id);
    DIFFER_SEEN_TYPED(memory_havoc_version, uint64_t);
    DIFFER_SEEN_TYPED(unresolved_operations, size_t);
    DIFFER_SEEN_TYPED(completeness, uint8_t);
    DIFFER_SEEN_TYPED(terminate_requested, uint8_t);
    DIFFER_SEEN_TYPED(model_output_confidence, uint8_t);
    DIFFER_SEEN_TYPED(control_scope_count, size_t);
#undef DIFFER_SEEN_TYPED
    saved_u8 = seen[0].defined[0]; seen[0].defined[0] ^= 1u; assert(!state_matches_seen(f->state, &seen[0])); seen[0].defined[0] = saved_u8;
    seen[0].taints[0] = XAIR_SYM_TAINT_NONE; assert(!state_matches_seen(f->state, &seen[0])); seen[0].taints[0] = f->source;
    saved_u64 = seen[0].values[0]; seen[0].values[0] = f->one; assert(!state_matches_seen(f->state, &seen[0])); seen[0].values[0] = (xair_sym_expr_id)saved_u64;
    f->state->control_scope_count = 1; f->state->control_scopes[0].postdominator = 4; f->state->control_scopes[0].taint = f->source;
    seen[0].control_scope_count = 1; seen[0].scope_postdominators[0] = 4; seen[0].scope_taints[0] = f->source;
    saved_size = seen[0].scope_postdominators[0]; seen[0].scope_postdominators[0]++; assert(!state_matches_seen(f->state, &seen[0])); seen[0].scope_postdominators[0] = (xair_block_id)saved_size;
    seen[0].scope_taints[0] = XAIR_SYM_TAINT_NONE; assert(!state_matches_seen(f->state, &seen[0])); seen[0].scope_taints[0] = f->source;
    f->state->control_scope_count = 0; seen[0].control_scope_count = 0;
    {
        xair_sym_state *saved = seen[0].exact_state; seen[0].exact_state = NULL;
        assert(!state_matches_seen(f->state, &seen[0])); seen[0].exact_state = saved;
    }
    require_sym(remember_state(f->state, &seen, &count, &capacity, &duplicate));
    assert(duplicate && count == 1);
    destroy_seen_states(f->context, seen, count, capacity);
}

int main(void) {
    fixture f;
    fixture_init(&f);
    test_public_defenses(&f);
    test_address_and_control(&f);
    test_queue(&f);
    test_exact_equality(&f);
    test_seen_state(&f);
    fixture_destroy(&f);
    return 0;
}
