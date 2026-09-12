#include "xair_sym/xair_sym.h"
#include "../src/xair_sym_internal.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *pointer, size_t size);

static size_t allocation_index;
static size_t fail_index;

static int allocation_fails(void) {
    ++allocation_index;
    return fail_index != 0 && allocation_index == fail_index;
}

void *__wrap_malloc(size_t size) {
    return allocation_fails() ? NULL : __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size) {
    return allocation_fails() ? NULL : __real_calloc(count, size);
}

void *__wrap_realloc(void *pointer, size_t size) {
    return allocation_fails() ? NULL : __real_realloc(pointer, size);
}

static void disable_failure(void) { fail_index = 0; allocation_index = 0; }
static void fail_allocation(size_t index) { allocation_index = 0; fail_index = index; }
static void require_xair(xair_status status) { assert(status == XAIR_OK); }
static void require_sym(xair_sym_status status) { assert(status == XAIR_SYM_OK); }

static void make_module(xair_module **out_module, xair_block_id *out_block) {
    require_xair(xair_module_create(out_module));
    require_xair(xair_block_create(*out_module, "allocation_entry", out_block));
    require_xair(xair_set_return(*out_module, *out_block, NULL, 0));
    require_xair(xair_module_freeze(*out_module));
}

static void sweep_context_and_expression(void) {
    size_t index;
    for (index = 1; index <= 24; ++index) {
        xair_sym_context *context = NULL;
        xair_sym_expr_id expression = XAIR_SYM_INVALID_ID;
        xair_sym_status status;
        fail_allocation(index);
        status = xair_sym_context_create(&context);
        if (status == XAIR_SYM_OK)
            status = xair_sym_symbol(context, 64, "allocation_symbol", &expression);
        assert(status == XAIR_SYM_OK || status == XAIR_SYM_ERR_OOM ||
            status == XAIR_SYM_ERR_RESOURCE_LIMIT);
        disable_failure();
        xair_sym_context_destroy(context);
    }
}

static void sweep_trace(void) {
    size_t index;
    for (index = 1; index <= 4; ++index) {
        xair_sym_trace *trace = NULL;
        xair_sym_status status;
        fail_allocation(index);
        status = xair_sym_trace_create(&trace);
        if (status == XAIR_SYM_OK)
            status = xair_sym_trace_add_branch(trace, 0, 0, 1);
        assert(status == XAIR_SYM_OK || status == XAIR_SYM_ERR_OOM);
        disable_failure();
        xair_sym_trace_destroy(trace);
    }
}

static void sweep_state_and_memory(const xair_module *module, xair_block_id block) {
    size_t operation, index;
    for (operation = 0; operation < 5; ++operation) {
      for (index = 1; index <= 20; ++index) {
        xair_sym_context *context = NULL;
        xair_sym_state *state = NULL, *clone = NULL;
        xair_sym_object_id object;
        xair_sym_expr_id byte;
        xair_sym_status status;
        require_sym(xair_sym_context_create(&context));
        require_sym(xair_sym_const(context, 8, 0x5a, &byte));
        if (operation != 0) require_sym(xair_sym_state_create(context, module, block, &state));
        if (operation >= 2) require_sym(xair_sym_object_add(state, 0x1000, 0x1001, 3, &object));
        if (operation >= 3) require_sym(xair_sym_memory_store8(state, 0x1000, byte));
        if (operation >= 4) require_sym(xair_sym_state_clone(state, &clone));
        fail_allocation(index);
        if (operation == 0) status = xair_sym_state_create(context, module, block, &state);
        else if (operation == 1) status = xair_sym_object_add(state, 0x1000, 0x1001, 3, &object);
        else if (operation == 2) status = xair_sym_memory_store8(state, 0x1000, byte);
        else if (operation == 3) status = xair_sym_state_clone(state, &clone);
        else status = xair_sym_memory_store8(clone, 0x1001, byte);
        assert(status == XAIR_SYM_OK || status == XAIR_SYM_ERR_OOM ||
            status == XAIR_SYM_ERR_RESOURCE_LIMIT);
        disable_failure();
        xair_sym_state_destroy(clone);
        xair_sym_state_destroy(state);
        xair_sym_context_destroy(context);
      }
    }
}

static void sweep_taint(void) {
    size_t index;
    for (index = 1; index <= 16; ++index) {
        xair_sym_context *context = NULL;
        xair_sym_taint_id source, transformed;
        xair_sym_status status;
        require_sym(xair_sym_context_create(&context));
        fail_allocation(index);
        status = xair_sym_taint_source(context, "allocation_source", &source);
        if (status == XAIR_SYM_OK)
            status = xair_sym_taint_transform(context, source, "allocation_transform",
                XAIR_SYM_INVALID_ID, 0, &transformed);
        assert(status == XAIR_SYM_OK || status == XAIR_SYM_ERR_OOM ||
            status == XAIR_SYM_ERR_RESOURCE_LIMIT);
        disable_failure();
        xair_sym_context_destroy(context);
    }
}

static void sweep_snapshot_and_environment(const xair_module *module,
    xair_block_id block) {
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_snapshot *snapshot = NULL;
    xair_sym_environment *environment = NULL;
    size_t index;
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64,
        XAIR_CC_SYSV_X64, UINT64_C(0x00010001), UINT64_C(0x70000000),
        0x1000, UINT64_C(0x40000000), &environment));
    xair_sym_environment_attach_builtin(state, environment);
    environment = NULL;
    require_sym(xair_sym_snapshot_take(state, &snapshot));
    for (index = 1; index <= 96; ++index) {
        xair_sym_context *isolated_context = NULL;
        xair_sym_state *isolated_state = NULL;
        xair_sym_status status;
        fail_allocation(index);
        status = xair_sym_snapshot_clone_isolated(snapshot, &isolated_context, &isolated_state);
        assert(status == XAIR_SYM_OK || status == XAIR_SYM_ERR_OOM ||
            status == XAIR_SYM_ERR_RESOURCE_LIMIT);
        disable_failure();
        xair_sym_state_destroy(isolated_state);
        xair_sym_context_destroy(isolated_context);
    }
    xair_sym_snapshot_destroy(snapshot);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
}

int main(void) {
    xair_module *module = NULL;
    xair_block_id block;
    disable_failure();
    make_module(&module, &block);
    puts("allocation sweep: context/expression");
    sweep_context_and_expression();
    puts("allocation sweep: trace");
    sweep_trace();
    puts("allocation sweep: state/memory");
    sweep_state_and_memory(module, block);
    puts("allocation sweep: taint");
    sweep_taint();
    puts("allocation sweep: snapshot/environment");
    sweep_snapshot_and_environment(module, block);
    xair_module_destroy(module);
    return 0;
}
