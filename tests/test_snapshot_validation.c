#include "xair_sym/xair_sym.h"
#include "../src/xair_sym_internal.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define xair_sym_snapshot_take xair_sym_test_snapshot_take
#define xair_sym_snapshot_destroy xair_sym_test_snapshot_destroy
#define xair_sym_snapshot_restore xair_sym_test_snapshot_restore
#define xair_sym_snapshot_metadata_get xair_sym_test_snapshot_metadata_get
#define xair_sym_snapshot_fingerprint xair_sym_test_snapshot_fingerprint
#define xair_sym_snapshot_save xair_sym_test_snapshot_save
#define xair_sym_snapshot_load xair_sym_test_snapshot_load
#define xair_sym_snapshot_load_bytes xair_sym_test_snapshot_load_bytes
#define xair_sym_snapshot_load_bytes_checked xair_sym_test_snapshot_load_bytes_checked
#define xair_sym_snapshot_clone_isolated xair_sym_test_snapshot_clone_isolated
#include "../src/xair_sym_snapshot.c"
#undef xair_sym_snapshot_take
#undef xair_sym_snapshot_destroy
#undef xair_sym_snapshot_restore
#undef xair_sym_snapshot_metadata_get
#undef xair_sym_snapshot_fingerprint
#undef xair_sym_snapshot_save
#undef xair_sym_snapshot_load
#undef xair_sym_snapshot_load_bytes
#undef xair_sym_snapshot_load_bytes_checked
#undef xair_sym_snapshot_clone_isolated

static void require_sym(xair_sym_status status) { assert(status == XAIR_SYM_OK); }

static void test_budget_blob_and_reader(void) {
    snapshot_budget budget = {0, 10};
    snapshot_blob blob = {0};
    uint8_t encoded[] = {4,0,0,0,'a','b','c',0,0xff};
    snapshot_reader reader = {encoded, sizeof(encoded), 0};
    const char *text = NULL;
    size_t size = 0;
    uint8_t byte;
    uint8_t null_string[] = {0,0,0,0};
    uint8_t bad_string[] = {2,0,0,0,'x','y'};
    snapshot_reader null_reader = {null_string, sizeof(null_string), 0};
    snapshot_reader bad_reader = {bad_string, sizeof(bad_string), 0};
    xair_sym_taint_details left = {0}, right = {0};
    assert(budget_charge(&budget, 4));
    assert(!budget_charge(&budget, 7));
    assert(budget_charge_array(&budget, 2, 3));
    assert(!budget_charge_array(&budget, UINT64_MAX, 2));
    assert(blob_bytes(&blob, "abc", 3));
    assert(blob_u8(&blob, 7));
    assert(blob_u32(&blob, 9));
    assert(blob_u64(&blob, 11));
    assert(blob_string(&blob, NULL));
    assert(blob_string(&blob, "snapshot validation"));
    assert(blob.size != 0 && blob.capacity >= blob.size);
    free(blob.data);
    memset(&blob, 0, sizeof(blob));
    blob.size = SIZE_MAX / 2u + 1u; blob.capacity = blob.size;
    assert(!blob_reserve(&blob, 1));
    assert(read_string(&reader, &text, &size));
    assert(size == 4 && strcmp(text, "abc") == 0);
    assert(read_u8(&reader, &byte) && byte == 0xff);
    assert(!read_u8(&reader, &byte));
    assert(read_string(&null_reader, &text, &size) && text == NULL && size == 0);
    assert(!read_string(&bad_reader, &text, &size));
    assert(snapshot_mask_bits(64) == UINT64_MAX);
    assert(snapshot_mask_bits(8) == 0xff);
    assert(snapshot_hash(encoded, sizeof(encoded)) != 0);
    assert(nullable_string_equal(NULL, ""));
    assert(snapshot_taint_details_equal(&left, &right));
    right.byte_offset = 1;
    assert(!snapshot_taint_details_equal(&left, &right));
}

static void test_context_budget(void) {
    xair_sym_context *context = NULL;
    xair_sym_expr_id symbol;
    snapshot_budget budget;
    xair_analysis_options analysis;
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_symbol(context, 64, "budget_shape", &symbol));
    assert(context_allocation_estimate(context) != 0);
    xair_analysis_options_init(&analysis);
    xair_sym_context_set_analysis_options(context, &analysis);
    assert(budget_init(&budget, context));
    analysis.max_memory = 1;
    xair_sym_context_set_analysis_options(context, &analysis);
    assert(!budget_init(&budget, context));
    xair_sym_context_destroy(context);
}

static void assert_valid_context(const xair_sym_context *context) {
    size_t i;
    for (i = 0; i < context->expression_count; ++i)
        assert(snapshot_expression_shape_valid(context, context->expressions[i]));
}

static void test_expression_shapes(void) {
    xair_sym_context *context = NULL;
    xair_sym_expr_id c8, c128, symbol, zext, sext, trunc, extract, to_addr, to_int;
    xair_sym_expr_id flags_logic, flag, add, compare, concat, flags_add, select;
    xair_sym_expr changed;
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_const(context, 8, 3, &c8));
    require_sym(xair_sym_const_wide(context, 128, 1, 2, &c128));
    require_sym(xair_sym_symbol(context, 8, "shape_symbol", &symbol));
    require_sym(xair_sym_unary(context, XAIR_OP_ZEXT, 16, symbol, 0, &zext));
    require_sym(xair_sym_unary(context, XAIR_OP_SEXT, 16, symbol, 0, &sext));
    require_sym(xair_sym_unary(context, XAIR_OP_TRUNC, 4, symbol, 0, &trunc));
    require_sym(xair_sym_unary(context, XAIR_OP_EXTRACT, 4, symbol, 4, &extract));
    require_sym(xair_sym_unary(context, XAIR_OP_INT_TO_ADDR, 8, symbol, 0, &to_addr));
    require_sym(xair_sym_unary(context, XAIR_OP_ADDR_TO_INT, 8, symbol, 0, &to_int));
    require_sym(xair_sym_unary(context, XAIR_OP_FLAGS_LOGIC, 6, symbol, 0, &flags_logic));
    require_sym(xair_sym_unary(context, XAIR_OP_FLAG_AF, 1, flags_logic, 0, &flag));
    require_sym(xair_sym_binary(context, XAIR_OP_ADD, 8, symbol, c8, &add));
    require_sym(xair_sym_binary(context, XAIR_OP_SLE, 1, symbol, c8, &compare));
    require_sym(xair_sym_binary(context, XAIR_OP_CONCAT, 8, trunc, extract, &concat));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_ADD, 6, symbol, c8, &flags_add));
    require_sym(xair_sym_select(context, compare, symbol, c8, &select));
    assert_valid_context(context);

    changed = *context->expressions[c8]; changed.arg_count = 1;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[c8]; changed.immediate = 0x100;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[c128]; changed.immediate_hi = 0;
    assert(snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[symbol]; changed.symbol = NULL;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[symbol]; changed.immediate = 1;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[add]; changed.symbol = "invalid";
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[add]; changed.immediate_hi = 1;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[zext]; changed.bits = 8;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[trunc]; changed.immediate = 1;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[extract]; changed.immediate = 8;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[flag]; context->expressions[flags_logic]->flags_pack = 0;
    assert(!snapshot_expression_shape_valid(context, &changed));
    context->expressions[flags_logic]->flags_pack = 1;
    changed = *context->expressions[add]; changed.immediate = 1;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[add]; changed.bits = 7;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[concat]; changed.bits = 7;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[select]; changed.immediate = 1;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[select]; changed.bits = 7;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[select]; changed.arg_count = 0;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[add]; changed.arg_count = 1; changed.opcode = XAIR_OP_ADD;
    assert(!snapshot_expression_shape_valid(context, &changed));
    changed = *context->expressions[add]; changed.opcode = XAIR_OP_SELECT;
    assert(!snapshot_expression_shape_valid(context, &changed));
    xair_sym_context_destroy(context);
}

static void test_clone_select(void) {
    xair_module *module = NULL;
    xair_block_id block;
    xair_value_id value;
    xair_sym_context *context = NULL, *isolated_context = NULL;
    xair_sym_state *state = NULL, *isolated_state = NULL;
    xair_sym_snapshot *snapshot = NULL;
    xair_sym_expr_id a, b, condition, selected;
    assert(xair_module_create(&module) == XAIR_OK);
    assert(xair_block_create(module, "clone_select", &block) == XAIR_OK);
    assert(xair_block_add_param(module, block, xair_type_i(8), "value", &value) == XAIR_OK);
    assert(xair_set_return(module, block, &value, 1) == XAIR_OK);
    assert(xair_module_freeze(module) == XAIR_OK);
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "select_a", &a));
    require_sym(xair_sym_symbol(context, 8, "select_b", &b));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, a, b, &condition));
    require_sym(xair_sym_select(context, condition, a, b, &selected));
    require_sym(xair_sym_state_set_value(state, value, selected));
    require_sym(xair_sym_test_snapshot_take(state, &snapshot));
    require_sym(xair_sym_test_snapshot_clone_isolated(snapshot, &isolated_context, &isolated_state));
    xair_sym_state_destroy(isolated_state); xair_sym_context_destroy(isolated_context);
    isolated_state = NULL; isolated_context = NULL;
    {
        xair_sym_expr saved = *context->expressions[selected];
        context->expressions[selected]->opcode = XAIR_OP_ADD;
        assert(xair_sym_test_snapshot_clone_isolated(snapshot, &isolated_context,
            &isolated_state) == XAIR_SYM_ERR_UNSUPPORTED);
        assert(isolated_context == NULL && isolated_state == NULL);
        *context->expressions[selected] = saved;
    }
    xair_sym_test_snapshot_destroy(snapshot); xair_sym_state_destroy(state);
    xair_sym_context_destroy(context); xair_module_destroy(module);
}

int main(void) {
    test_budget_blob_and_reader();
    test_context_budget();
    test_expression_shapes();
    test_clone_select();
    return 0;
}
