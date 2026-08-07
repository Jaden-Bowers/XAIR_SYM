#include "xair_sym_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const char *name; xair_sym_model_kind kind; } builtin_model;

static const builtin_model builtin_models[] = {
    {"malloc", XAIR_SYM_MODEL_ALLOC}, {"calloc", XAIR_SYM_MODEL_ALLOC}, {"realloc", XAIR_SYM_MODEL_ALLOC},
    {"free", XAIR_SYM_MODEL_FREE}, {"memcpy", XAIR_SYM_MODEL_COPY}, {"memmove", XAIR_SYM_MODEL_COPY},
    {"memset", XAIR_SYM_MODEL_FILL}, {"read", XAIR_SYM_MODEL_INPUT}, {"recv", XAIR_SYM_MODEL_INPUT},
    {"recvfrom", XAIR_SYM_MODEL_INPUT}, {"strlen", XAIR_SYM_MODEL_LENGTH}, {"exit", XAIR_SYM_MODEL_NO_RETURN},
    {"abort", XAIR_SYM_MODEL_NO_RETURN}, {"HeapAlloc", XAIR_SYM_MODEL_ALLOC}, {"HeapFree", XAIR_SYM_MODEL_FREE},
    {"RtlAllocateHeap", XAIR_SYM_MODEL_ALLOC}, {"RtlFreeHeap", XAIR_SYM_MODEL_FREE},
    {"RtlCopyMemory", XAIR_SYM_MODEL_COPY}, {"ReadFile", XAIR_SYM_MODEL_INPUT},
    {"ExitProcess", XAIR_SYM_MODEL_NO_RETURN}, {"ExAllocatePool", XAIR_SYM_MODEL_ALLOC},
    {"ExAllocatePoolWithTag", XAIR_SYM_MODEL_ALLOC}, {"ExFreePool", XAIR_SYM_MODEL_FREE},
    {"ProbeForRead", XAIR_SYM_MODEL_DRIVER_INPUT}, {"ProbeForWrite", XAIR_SYM_MODEL_DRIVER_INPUT},
    {"IoCompleteRequest", XAIR_SYM_MODEL_DRIVER_COMPLETE}
};

void xair_sym_process_options_init(xair_sym_process_options *options, xair_arch arch) {
    if (options == NULL) return;
    memset(options, 0, sizeof(*options));
    options->stack_size = 1024u * 1024u;
    options->max_segment_size = 512u * 1024u * 1024u;
    options->stack_base = arch == XAIR_ARCH_X86_32 ? UINT64_C(0x70000000) : UINT64_C(0x00007fff00000000);
}

static xair_sym_status initialize_segment(
    xair_sym_context *context,
    xair_sym_state *state,
    const xair_binary_segment *segment,
    size_t max_segment_size) {
    xair_sym_object_id object;
    size_t size;
    size_t i;
    xair_sym_status status;
    if (segment->mem_size == 0) return XAIR_SYM_OK;
    if (segment->mem_size > max_segment_size || segment->mem_size > SIZE_MAX || segment->file_size > segment->mem_size) {
        return XAIR_SYM_ERR_RANGE;
    }
    if (segment->file_size != 0 && segment->bytes == NULL) return XAIR_SYM_ERR_BAD_ARG;
    size = (size_t)segment->mem_size;
    status = xair_sym_object_add(state, segment->va, size, segment->perms, &object);
    if (status != XAIR_SYM_OK) return status;
    (void)object;
    for (i = 0; i < size; ++i) {
        xair_sym_expr_id byte;
        uint8_t concrete = i < segment->file_size ? segment->bytes[i] : 0;
        status = xair_sym_const(context, 8, concrete, &byte);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_initialize8(state, segment->va + i, byte);
        if (status != XAIR_SYM_OK) return status;
    }
    return XAIR_SYM_OK;
}

static xair_sym_status initialize_entry_parameters(
    xair_sym_context *context,
    xair_sym_state *state,
    xair_block_id entry,
    uint64_t stack_pointer) {
    size_t count = xair_block_param_count(state->module, entry);
    size_t i;
    for (i = 0; i < count; ++i) {
        xair_value_id parameter;
        xair_type type;
        const char *name;
        xair_sym_expr_id value;
        xair_sym_status status;
        if (xair_block_param_value(state->module, entry, i, &parameter) != XAIR_OK) return XAIR_SYM_ERR_BAD_ARG;
        type = xair_value_type(state->module, parameter);
        name = xair_value_name(state->module, parameter);
        if (type.kind == XAIR_TYPE_MEM) {
            status = xair_sym_const(context, 1, 0, &value);
        } else if (type.kind == XAIR_TYPE_INT || type.kind == XAIR_TYPE_ADDR) {
            if (name != NULL && (strcmp(name, "rsp") == 0 || strcmp(name, "esp") == 0)) {
                status = xair_sym_const(context, type.bits, stack_pointer, &value);
            } else {
                char symbol_name[80];
                (void)snprintf(symbol_name, sizeof(symbol_name), "initial_%s_%u", name == NULL ? "value" : name, (unsigned)parameter);
                status = xair_sym_symbol(context, type.bits, symbol_name, &value);
            }
        } else {
            return XAIR_SYM_ERR_UNSUPPORTED;
        }
        if (status != XAIR_SYM_OK) return status;
        status = xair_sym_state_set_value(state, parameter, value);
        if (status != XAIR_SYM_OK) return status;
    }
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_process_create(
    xair_sym_context *context,
    const xair_cfg *cfg,
    const xair_binary_view *binary,
    const xair_sym_process_options *options,
    xair_sym_environment **out_environment,
    xair_sym_state **out_state) {
    xair_cfg_node_id entry_node;
    const xair_cfg_node *node;
    xair_sym_environment *environment;
    xair_sym_state *state = NULL;
    xair_sym_object_id stack_object;
    uint64_t stack_pointer;
    size_t i;
    xair_sym_status status;
    if (context == NULL || cfg == NULL || binary == NULL || options == NULL || out_environment == NULL || out_state == NULL ||
        options->stack_size < 64 || options->max_segment_size == 0 || !xair_cfg_is_frozen(cfg)) return XAIR_SYM_ERR_BAD_ARG;
    if (options->stack_base > UINT64_MAX - options->stack_size) return XAIR_SYM_ERR_RANGE;
    entry_node = xair_cfg_find_node_start(cfg, binary->entry);
    if (entry_node == XAIR_CFG_INVALID_ID) entry_node = xair_cfg_find_node_containing(cfg, binary->entry);
    node = xair_cfg_get_node(cfg, entry_node);
    if (node == NULL || node->ir_block == XAIR_INVALID_ID) return XAIR_SYM_ERR_UNSUPPORTED;
    environment = (xair_sym_environment *)calloc(1, sizeof(*environment));
    if (environment == NULL) return XAIR_SYM_ERR_OOM;
    environment->context = context; environment->arch = binary->arch;
    environment->stack_base = options->stack_base; environment->stack_size = options->stack_size;
    environment->heap_next = binary->arch == XAIR_ARCH_X86_32 ? UINT64_C(0x50000000) : UINT64_C(0x0000600000000000);
    status = xair_sym_state_create(context, xair_cfg_module(cfg), node->ir_block, &state);
    if (status != XAIR_SYM_OK) goto fail;
    for (i = 0; i < binary->segment_count; ++i) {
        status = initialize_segment(context, state, &binary->segments[i], options->max_segment_size);
        if (status != XAIR_SYM_OK) goto fail;
    }
    status = xair_sym_object_add(state, options->stack_base, options->stack_size, 3u, &stack_object);
    if (status != XAIR_SYM_OK) goto fail;
    (void)stack_object;
    stack_pointer = options->stack_base + options->stack_size - 32u;
    for (i = 0; i < 32u; ++i) {
        xair_sym_expr_id zero;
        status = xair_sym_const(context, 8, 0, &zero);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_store8(state, stack_pointer + i, zero);
        if (status != XAIR_SYM_OK) goto fail;
    }
    status = initialize_entry_parameters(context, state, node->ir_block, stack_pointer);
    if (status != XAIR_SYM_OK) goto fail;
    *out_environment = environment; *out_state = state;
    return XAIR_SYM_OK;
fail:
    xair_sym_state_destroy(state); free(environment); return status;
}

void xair_sym_environment_destroy(xair_sym_environment *environment) { free(environment); }

xair_sym_status xair_sym_environment_model(
    const xair_sym_environment *environment,
    const char *name,
    xair_sym_model_kind *out_kind) {
    xair_sym_model_info info;
    if (environment == NULL || name == NULL || out_kind == NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (xair_sym_environment_model_info(environment, name, &info) != XAIR_SYM_OK) return XAIR_SYM_ERR_BAD_ARG;
    *out_kind = info.kind;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_environment_model_info(
    const xair_sym_environment *environment,
    const char *name,
    xair_sym_model_info *out_info) {
    size_t i;
    if (environment == NULL || name == NULL || out_info == NULL) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < sizeof(builtin_models) / sizeof(builtin_models[0]); ++i) {
        if (strcmp(name, builtin_models[i].name) == 0) {
            out_info->kind = builtin_models[i].kind;
            out_info->version_major = 1;
            out_info->version_minor = 0;
            return XAIR_SYM_OK;
        }
    }
    out_info->kind = XAIR_SYM_MODEL_UNKNOWN;
    out_info->version_major = 0;
    out_info->version_minor = 0;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_environment_allocate(
    xair_sym_environment *environment,
    xair_sym_state *state,
    size_t size,
    uint64_t *out_address) {
    xair_sym_object_id object;
    uint64_t aligned;
    xair_sym_status status;
    if (environment == NULL || state == NULL || out_address == NULL || size == 0 || state->context != environment->context) return XAIR_SYM_ERR_BAD_ARG;
    if (size > SIZE_MAX - 15u) return XAIR_SYM_ERR_RANGE;
    aligned = (uint64_t)((size + 15u) & ~(size_t)15u);
    if (aligned < size || environment->heap_next > UINT64_MAX - aligned) return XAIR_SYM_ERR_RANGE;
    status = xair_sym_object_add(state, environment->heap_next, size, 3u, &object);
    if (status != XAIR_SYM_OK) return status;
    (void)object; *out_address = environment->heap_next; environment->heap_next += aligned;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_environment_input(
    xair_sym_environment *environment,
    xair_sym_state *state,
    uint64_t address,
    size_t size,
    const char *source_name,
    xair_sym_expr_id *out_symbols) {
    xair_sym_taint_id taint;
    size_t i;
    xair_sym_status status;
    if (environment == NULL || state == NULL || source_name == NULL || state->context != environment->context ||
        (size != 0 && out_symbols == NULL)) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_taint_source(environment->context, source_name, &taint);
    if (status != XAIR_SYM_OK) return status;
    for (i = 0; i < size; ++i) {
        char name[96];
        (void)snprintf(name, sizeof(name), "%s_%zu", source_name, i);
        status = xair_sym_symbol(environment->context, 8, name, &out_symbols[i]);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_store8(state, address + i, out_symbols[i]);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_store_taint8(state, address + i, taint);
        if (status != XAIR_SYM_OK) return status;
    }
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_environment_copy(
    xair_sym_environment *environment,
    xair_sym_state *state,
    uint64_t destination,
    uint64_t source,
    size_t size) {
    size_t i;
    if (environment == NULL || state == NULL || state->context != environment->context) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < size; ++i) {
        xair_sym_expr_id value;
        xair_sym_taint_id taint = XAIR_SYM_TAINT_NONE;
        xair_sym_status status = xair_sym_memory_load8(state, source + i, &value);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_load_taint8(state, source + i, &taint);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_store8(state, destination + i, value);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_store_taint8(state, destination + i, taint);
        if (status != XAIR_SYM_OK) return status;
    }
    return XAIR_SYM_OK;
}
