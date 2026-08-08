#include "xair_sym/xair_sym.h"
#include "../src/xair_sym_internal.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

/* Compile a private copy so deterministic unit cases can exercise the deep
 * equivalence predicates used for parallel terminal-state deduplication. */
#define xair_sym_parallel_options_init xair_sym_test_parallel_options_init
#define xair_sym_parallel_explore_detailed xair_sym_test_parallel_explore_detailed
#define xair_sym_parallel_explore xair_sym_test_parallel_explore
#include "../src/xair_sym_parallel.c"
#undef xair_sym_parallel_options_init
#undef xair_sym_parallel_explore_detailed
#undef xair_sym_parallel_explore

static void require_xair(xair_status status) { assert(status == XAIR_OK); }
static void require_sym(xair_sym_status status) { assert(status == XAIR_SYM_OK); }

typedef struct {
    xair_sym_context *context;
    xair_sym_state *state;
    xair_sym_expr_id symbol;
    xair_sym_expr_id sum;
    xair_sym_taint_id source;
    xair_sym_taint_id transformed;
} equivalent_side;

static void make_side(const xair_module *module, xair_block_id block,
    xair_value_id value, equivalent_side *side) {
    xair_sym_expr_id one, guard;
    xair_sym_object_id object;
    memset(side, 0, sizeof(*side));
    require_sym(xair_sym_context_create(&side->context));
    require_sym(xair_sym_state_create(side->context, module, block, &side->state));
    require_sym(xair_sym_symbol(side->context, 8, "equivalent_symbol", &side->symbol));
    require_sym(xair_sym_const(side->context, 8, 1, &one));
    require_sym(xair_sym_binary(side->context, XAIR_OP_ADD, 8,
        side->symbol, one, &side->sum));
    require_sym(xair_sym_binary(side->context, XAIR_OP_EQ, 1,
        side->sum, one, &guard));
    require_sym(xair_sym_taint_source(side->context, "equivalent_source", &side->source));
    require_sym(xair_sym_taint_transform(side->context, side->source,
        "equivalent_transform", guard, 1, &side->transformed));
    require_sym(xair_sym_state_set_value(side->state, value, side->sum));
    require_sym(xair_sym_state_set_taint(side->state, value, side->transformed));
    require_sym(xair_sym_object_add(side->state, 0x4000, 2, 3, &object));
    require_sym(xair_sym_memory_store8(side->state, 0x4000, side->sum));
    require_sym(xair_sym_memory_store_taint8(side->state, 0x4000, side->transformed));
    require_sym(xair_sym_state_assume(side->state, guard));
}

static void destroy_side(equivalent_side *side) {
    xair_sym_state_destroy(side->state);
    xair_sym_context_destroy(side->context);
}

static void test_budget_and_estimates(const xair_module *module,
    const equivalent_side *side) {
    xair_sym_parallel_budget budget;
    size_t total, estimate, saved;
    memset(&budget, 0, sizeof(budget));
    assert(xair_mutex_init(&budget.lock));
    assert(budget_memory_reserve(&budget, 100));
    budget.max_memory = 100; budget.remaining_memory = 100;
    assert(budget_memory_reserve(&budget, 0));
    assert(!budget_memory_reserve(&budget, 101));
    assert(budget_memory_reserve(&budget, 40));
    assert(budget.remaining_memory == 60 && budget.peak_memory == 40);
    budget_memory_release(&budget, 101); assert(budget.remaining_memory == 60);
    budget_memory_release(&budget, 40); assert(budget.remaining_memory == 100);
    xair_mutex_destroy(&budget.lock);

    total = 0; assert(add_allocation(&total, 3, 4) && total == 12);
    total = SIZE_MAX; assert(!add_allocation(&total, 1, 1));
    assert(isolated_allocation_estimate(side->context, side->state, &estimate));
    assert(estimate != 0);
    saved = side->context->object_bytes;
    ((xair_sym_context *)side->context)->object_bytes = SIZE_MAX;
    assert(!isolated_allocation_estimate(side->context, side->state, &estimate));
    ((xair_sym_context *)side->context)->object_bytes = saved;
    assert(program_allocation_estimate(module, &estimate) && estimate != 0);
}

static void test_expression_and_taint_equivalence(equivalent_side *lhs,
    equivalent_side *rhs) {
    xair_sym_expr saved_expression;
    xair_sym_taint_node saved_taint;
    assert(nullable_string_equal(NULL, NULL));
    assert(!nullable_string_equal(NULL, "x"));
    assert(nullable_string_equal("same", "same"));
    assert(nullable_string_equal("same", (char[]){'s','a','m','e','\0'}));
    assert(expression_equal(lhs->context, XAIR_SYM_INVALID_ID,
        rhs->context, XAIR_SYM_INVALID_ID));
    assert(!expression_equal(lhs->context, lhs->sum,
        rhs->context, XAIR_SYM_INVALID_ID));
    assert(!expression_equal(lhs->context, 9999, rhs->context, rhs->sum));
    assert(expression_equal(lhs->context, lhs->sum, rhs->context, rhs->sum));
    saved_expression = *rhs->context->expressions[rhs->sum];
    rhs->context->expressions[rhs->sum]->kind = XAIR_SYM_EXPR_SYMBOL;
    assert(!expression_equal(lhs->context, lhs->sum, rhs->context, rhs->sum));
    *rhs->context->expressions[rhs->sum] = saved_expression;
    rhs->context->expressions[rhs->sum]->opcode = XAIR_OP_SUB;
    assert(!expression_equal(lhs->context, lhs->sum, rhs->context, rhs->sum));
    *rhs->context->expressions[rhs->sum] = saved_expression;
    rhs->context->expressions[rhs->sum]->bits = 7;
    assert(!expression_equal(lhs->context, lhs->sum, rhs->context, rhs->sum));
    *rhs->context->expressions[rhs->sum] = saved_expression;
    rhs->context->expressions[rhs->sum]->arg_count = 1;
    assert(!expression_equal(lhs->context, lhs->sum, rhs->context, rhs->sum));
    *rhs->context->expressions[rhs->sum] = saved_expression;
    rhs->context->expressions[rhs->sum]->immediate = 7;
    assert(!expression_equal(lhs->context, lhs->sum, rhs->context, rhs->sum));
    *rhs->context->expressions[rhs->sum] = saved_expression;
    rhs->context->expressions[rhs->sum]->immediate_hi = 7;
    assert(!expression_equal(lhs->context, lhs->sum, rhs->context, rhs->sum));
    *rhs->context->expressions[rhs->sum] = saved_expression;
    saved_expression = *rhs->context->expressions[rhs->symbol];
    rhs->context->expressions[rhs->symbol]->symbol = "different_symbol";
    assert(!expression_equal(lhs->context, lhs->symbol, rhs->context, rhs->symbol));
    *rhs->context->expressions[rhs->symbol] = saved_expression;

    assert(taint_equal(lhs->context, XAIR_SYM_TAINT_NONE,
        rhs->context, XAIR_SYM_TAINT_NONE));
    assert(!taint_equal(lhs->context, lhs->source,
        rhs->context, XAIR_SYM_TAINT_NONE));
    assert(!taint_equal(lhs->context, 9999, rhs->context, rhs->source));
    assert(taint_equal(lhs->context, lhs->transformed,
        rhs->context, rhs->transformed));
    saved_taint = *rhs->context->taints[rhs->transformed - 1u];
    rhs->context->taints[rhs->transformed - 1u]->kind = XAIR_SYM_TAINT_NODE_SINK;
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.category = XAIR_SYM_TAINT_CATEGORY_FILE;
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.source_address = 1;
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.call_site = 1;
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.sink_address = 1;
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.byte_offset = 1;
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.byte_length++;
    assert(!taint_equal(lhs->context, lhs->transformed,
        rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.confidence = 1;
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.implicit = 0;
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.sanitizer_validated = 1;
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.transform = "different_transform";
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    rhs->context->taints[rhs->transformed - 1u]->details.sink = "different_sink";
    assert(!taint_equal(lhs->context, lhs->transformed, rhs->context, rhs->transformed));
    *rhs->context->taints[rhs->transformed - 1u] = saved_taint;
    saved_taint = *rhs->context->taints[rhs->source - 1u];
    rhs->context->taints[rhs->source - 1u]->name = "different_source";
    assert(!taint_equal(lhs->context, lhs->source, rhs->context, rhs->source));
    *rhs->context->taints[rhs->source - 1u] = saved_taint;
}

static void test_memory_and_terminal_equivalence(equivalent_side *lhs,
    equivalent_side *rhs) {
    uint64_t saved_u64;
    size_t saved_size;
    uint32_t saved_u32;
    uint8_t saved_u8;
    xair_sym_expr_id saved_expr;
    xair_sym_taint_id saved_taint;
    xair_sym_page *saved_page;
    assert(memory_equal(lhs->state, rhs->state));
    assert(terminal_equal(lhs->state, rhs->state));

    rhs->state->memory_havoc_version = 1;
    assert(!memory_equal(lhs->state, rhs->state));
    rhs->state->memory_havoc_version = 0;
    saved_u32 = rhs->state->memory->objects[0].permissions;
    rhs->state->memory->objects[0].permissions = 1;
    assert(!memory_equal(lhs->state, rhs->state));
    rhs->state->memory->objects[0].permissions = saved_u32;
    saved_u64 = rhs->state->memory->objects[0].base;
    rhs->state->memory->objects[0].base++;
    assert(!memory_equal(lhs->state, rhs->state));
    rhs->state->memory->objects[0].base = saved_u64;
    saved_size = rhs->state->memory->objects[0].size;
    rhs->state->memory->objects[0].size++;
    assert(!memory_equal(lhs->state, rhs->state));
    rhs->state->memory->objects[0].size = saved_size;
    saved_u8 = rhs->state->memory->objects[0].zero_fill;
    rhs->state->memory->objects[0].zero_fill ^= 1u;
    assert(!memory_equal(lhs->state, rhs->state));
    rhs->state->memory->objects[0].zero_fill = saved_u8;
    saved_size = rhs->state->memory->objects[0].page_count;
    rhs->state->memory->objects[0].page_count = 0;
    assert(!memory_equal(lhs->state, rhs->state));
    rhs->state->memory->objects[0].page_count = saved_size;
    saved_page = rhs->state->memory->objects[0].pages[0];
    rhs->state->memory->objects[0].pages[0] = NULL;
    assert(!memory_equal(lhs->state, rhs->state));
    rhs->state->memory->objects[0].pages[0] = saved_page;
    saved_expr = rhs->state->memory->objects[0].pages[0]->bytes[0];
    rhs->state->memory->objects[0].pages[0]->bytes[0] = rhs->symbol;
    assert(!memory_equal(lhs->state, rhs->state));
    rhs->state->memory->objects[0].pages[0]->bytes[0] = saved_expr;
    saved_taint = rhs->state->memory->objects[0].pages[0]->taints[0];
    rhs->state->memory->objects[0].pages[0]->taints[0] = rhs->source;
    assert(!memory_equal(lhs->state, rhs->state));
    rhs->state->memory->objects[0].pages[0]->taints[0] = saved_taint;

    saved_u64 = rhs->state->heap_next; rhs->state->heap_next++;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->heap_next = saved_u64;
    rhs->state->completeness = XAIR_SYM_INCOMPLETE;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->completeness = lhs->state->completeness;
    rhs->state->unresolved_operations++;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->unresolved_operations--;
    rhs->state->terminate_requested ^= 1u;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->terminate_requested ^= 1u;
    rhs->state->model_output_confidence++;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->model_output_confidence--;
    rhs->state->fs_base++;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->fs_base--;
    rhs->state->gs_base++;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->gs_base--;
    saved_size = rhs->state->control_scope_count; rhs->state->control_scope_count = 1;
    rhs->state->control_scopes[0].postdominator = 1;
    rhs->state->control_scopes[0].taint = rhs->source;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->control_scope_count = saved_size;
    saved_u8 = rhs->state->defined[0]; rhs->state->defined[0] = 0;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->defined[0] = saved_u8;
    saved_taint = rhs->state->value_taints[0]; rhs->state->value_taints[0] = rhs->source;
    assert(!terminal_equal(lhs->state, rhs->state)); rhs->state->value_taints[0] = saved_taint;
    assert(terminal_equal(lhs->state, rhs->state));
}

int main(void) {
    xair_module *module = NULL;
    xair_block_id block;
    xair_value_id value;
    equivalent_side lhs, rhs;
    require_xair(xair_module_create(&module));
    require_xair(xair_block_create(module, "equivalence_entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value));
    require_xair(xair_set_return(module, block, &value, 1));
    require_xair(xair_module_freeze(module));
    make_side(module, block, value, &lhs);
    make_side(module, block, value, &rhs);
    test_budget_and_estimates(module, &lhs);
    test_expression_and_taint_equivalence(&lhs, &rhs);
    test_memory_and_terminal_equivalence(&lhs, &rhs);
    destroy_side(&rhs); destroy_side(&lhs); xair_module_destroy(module);
    return 0;
}
