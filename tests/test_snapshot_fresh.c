#include "xair_sym/xair_sym.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void require_xair(xair_status status) {
    assert(status == XAIR_OK);
}

static void require_sym(xair_sym_status status) {
    if (status != XAIR_SYM_OK)
        fprintf(stderr, "unexpected symbolic status: %s\n", xair_sym_status_name(status));
    assert(status == XAIR_SYM_OK);
}

int main(void) {
    static const char path[] = "xair_sym_snapshot_fresh.bin";
    xair_module *module = NULL;
    xair_sym_context *source_context = NULL, *fresh_context = NULL, *limited_context = NULL;
    xair_sym_state *source = NULL, *restored = NULL;
    xair_sym_snapshot *snapshot = NULL, *loaded = NULL;
    xair_block_id block;
    xair_value_id value, flag_value, returns[2];
    xair_sym_expr_id symbol, one, sum, five, condition, flags, zero_flag;
    xair_sym_expr_id restored_expr, restored_flag, memory_expr;
    xair_sym_taint_id source_taint, transformed_taint, restored_taint, memory_taint;
    xair_sym_expr_view expression_view, guard_view;
    xair_sym_taint_view taint_view;
    xair_sym_taint_details details;
    xair_sym_object_id object;
    xair_analysis_options limits;
    uint64_t model = 0;

    remove(path);
    require_xair(xair_module_create(&module));
    require_xair(xair_block_create(module, "entry", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(8), "value", &value));
    require_xair(xair_block_add_param(module, block, xair_type_i(1), "zero_flag", &flag_value));
    returns[0] = value; returns[1] = flag_value;
    require_xair(xair_set_return(module, block, returns, 2));
    require_xair(xair_module_freeze(module));

    require_sym(xair_sym_context_create(&source_context));
    require_sym(xair_sym_state_create(source_context, module, block, &source));
    require_sym(xair_sym_symbol(source_context, 8, "fresh_snapshot_symbol", &symbol));
    require_sym(xair_sym_const(source_context, 8, 1, &one));
    require_sym(xair_sym_binary(source_context, XAIR_OP_ADD, 8, symbol, one, &sum));
    require_sym(xair_sym_const(source_context, 8, 5, &five));
    require_sym(xair_sym_binary(source_context, XAIR_OP_EQ, 1, sum, five, &condition));
    require_sym(xair_sym_unary(source_context, XAIR_OP_FLAGS_LOGIC, 6, sum, 0, &flags));
    require_sym(xair_sym_unary(source_context, XAIR_OP_FLAG_ZF, 1, flags, 0, &zero_flag));
    require_sym(xair_sym_state_set_value(source, value, sum));
    require_sym(xair_sym_state_set_value(source, flag_value, zero_flag));
    require_sym(xair_sym_state_assume(source, condition));
    require_sym(xair_sym_taint_source(source_context, "fresh_snapshot_source", &source_taint));
    require_sym(xair_sym_taint_transform(source_context, source_taint, "guarded_transform",
        condition, 1, &transformed_taint));
    require_sym(xair_sym_state_set_taint(source, value, transformed_taint));
    require_sym(xair_sym_object_add(source, UINT64_C(0x7000), 16, 3, &object));
    require_sym(xair_sym_memory_store8(source, UINT64_C(0x7003), sum));
    require_sym(xair_sym_memory_store_taint8(source, UINT64_C(0x7003), transformed_taint));
    require_sym(xair_sym_snapshot_take(source, &snapshot));
    require_sym(xair_sym_snapshot_save(snapshot, path));

    xair_sym_snapshot_destroy(snapshot);
    xair_sym_state_destroy(source);
    xair_sym_context_destroy(source_context);
    snapshot = NULL; source = NULL; source_context = NULL;

    require_sym(xair_sym_context_create(&fresh_context));
    require_sym(xair_sym_snapshot_load(fresh_context, module, path, &loaded));
    require_sym(xair_sym_snapshot_restore(loaded, &restored));
    require_sym(xair_sym_state_get_value(restored, value, &restored_expr));
    require_sym(xair_sym_expr_get(fresh_context, restored_expr, &expression_view));
    assert(expression_view.kind == XAIR_SYM_EXPR_XAIR && expression_view.opcode == XAIR_OP_ADD &&
        expression_view.bits == 8 && expression_view.arg_count == 2);
    require_sym(xair_sym_state_get_value(restored, flag_value, &restored_flag));
    require_sym(xair_sym_expr_get(fresh_context, restored_flag, &expression_view));
    assert(expression_view.kind == XAIR_SYM_EXPR_XAIR && expression_view.opcode == XAIR_OP_FLAG_ZF &&
        expression_view.bits == 1 && expression_view.arg_count == 1);
    require_sym(xair_sym_model_u64(restored, restored_expr, &model));
    assert(model == 5);
    require_sym(xair_sym_state_get_taint(restored, value, &restored_taint));
    require_sym(xair_sym_taint_get(fresh_context, restored_taint, &taint_view));
    require_sym(xair_sym_taint_get_details(fresh_context, restored_taint, &details));
    assert(taint_view.kind == XAIR_SYM_TAINT_NODE_TRANSFORM &&
        strcmp(taint_view.name, "guarded_transform") == 0 && details.implicit == 1 &&
        details.guard != XAIR_SYM_INVALID_ID);
    require_sym(xair_sym_expr_get(fresh_context, details.guard, &guard_view));
    assert(guard_view.bits == 1 && guard_view.opcode == XAIR_OP_EQ);
    require_sym(xair_sym_memory_load8(restored, UINT64_C(0x7003), &memory_expr));
    require_sym(xair_sym_memory_load_taint8(restored, UINT64_C(0x7003), &memory_taint));
    assert(memory_expr == restored_expr && memory_taint == restored_taint);
    xair_sym_state_destroy(restored);
    xair_sym_snapshot_destroy(loaded);
    xair_sym_context_destroy(fresh_context);

    require_sym(xair_sym_context_create(&limited_context));
    xair_analysis_options_init(&limits);
    limits.max_memory = 64;
    xair_sym_context_set_analysis_options(limited_context, &limits);
    loaded = (xair_sym_snapshot *)(uintptr_t)1u;
    assert(xair_sym_snapshot_load(limited_context, module, path, &loaded) == XAIR_SYM_ERR_RESOURCE_LIMIT);
    assert(loaded == NULL);
    xair_sym_context_destroy(limited_context);
    xair_module_destroy(module);
    remove(path);
    return 0;
}
