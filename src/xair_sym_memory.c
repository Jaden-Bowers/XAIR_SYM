#include "xair_sym_internal.h"

#include <stdlib.h>
#include <string.h>

xair_sym_memory *xair_sym_memory_create(void) {
    xair_sym_memory *memory = (xair_sym_memory *)calloc(1, sizeof(*memory));
    if (memory != NULL) memory->refs = 1;
    return memory;
}

void xair_sym_memory_retain(xair_sym_memory *memory) { if (memory != NULL) memory->refs++; }

void xair_sym_memory_release(xair_sym_memory *memory) {
    size_t i;
    if (memory == NULL || --memory->refs != 0) return;
    for (i = 0; i < memory->count; ++i) { free(memory->objects[i].taints); free(memory->objects[i].bytes); }
    free(memory->objects); free(memory);
}

xair_sym_status xair_sym_memory_make_unique(xair_sym_state *state) {
    xair_sym_memory *copy;
    size_t i;
    if (state == NULL || state->memory == NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (state->memory->refs == 1) return XAIR_SYM_OK;
    copy = xair_sym_memory_create();
    if (copy == NULL) return XAIR_SYM_ERR_OOM;
    if (state->memory->count != 0) {
        copy->objects = (xair_sym_object *)calloc(state->memory->count, sizeof(*copy->objects));
        if (copy->objects == NULL) { xair_sym_memory_release(copy); return XAIR_SYM_ERR_OOM; }
        copy->capacity = state->memory->count;
        for (i = 0; i < state->memory->count; ++i) {
            copy->objects[i].base = state->memory->objects[i].base;
            copy->objects[i].size = state->memory->objects[i].size;
            copy->objects[i].permissions = state->memory->objects[i].permissions;
            copy->objects[i].bytes = (xair_sym_expr_id *)malloc(copy->objects[i].size * sizeof(*copy->objects[i].bytes));
            copy->objects[i].taints = (xair_sym_taint_id *)malloc(copy->objects[i].size * sizeof(*copy->objects[i].taints));
            if (copy->objects[i].bytes == NULL || copy->objects[i].taints == NULL) { xair_sym_memory_release(copy); return XAIR_SYM_ERR_OOM; }
            memcpy(copy->objects[i].bytes, state->memory->objects[i].bytes,
                copy->objects[i].size * sizeof(*copy->objects[i].bytes));
            memcpy(copy->objects[i].taints, state->memory->objects[i].taints,
                copy->objects[i].size * sizeof(*copy->objects[i].taints));
            copy->count++;
        }
    }
    xair_sym_memory_release(state->memory); state->memory = copy;
    state->context->stats.memory_cow_copies++;
    return XAIR_SYM_OK;
}

static xair_sym_object *find_object(xair_sym_memory *memory, uint64_t address) {
    size_t i;
    for (i = 0; i < memory->count; ++i) {
        xair_sym_object *object = &memory->objects[i];
        if (address >= object->base && address - object->base < object->size) return object;
    }
    return NULL;
}

xair_sym_status xair_sym_object_add(xair_sym_state *state, uint64_t base, size_t size,
    uint32_t permissions, xair_sym_object_id *out_object) {
    xair_sym_object *next;
    size_t capacity;
    xair_sym_status status;
    if (state == NULL || out_object == NULL || size == 0 || base > UINT64_MAX - (size - 1)) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_memory_make_unique(state); if (status != XAIR_SYM_OK) return status;
    if (find_object(state->memory, base) != NULL || find_object(state->memory, base + size - 1) != NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (state->memory->count == state->memory->capacity) {
        capacity = state->memory->capacity == 0 ? 4 : state->memory->capacity * 2;
        next = (xair_sym_object *)realloc(state->memory->objects, capacity * sizeof(*next));
        if (next == NULL) return XAIR_SYM_ERR_OOM;
        state->memory->objects = next; state->memory->capacity = capacity;
    }
    if (state->memory->count >= UINT32_MAX) return XAIR_SYM_ERR_RANGE;
    next = &state->memory->objects[state->memory->count]; memset(next, 0, sizeof(*next));
    next->base = base; next->size = size; next->permissions = permissions;
    next->bytes = (xair_sym_expr_id *)malloc(size * sizeof(*next->bytes));
    next->taints = (xair_sym_taint_id *)calloc(size, sizeof(*next->taints));
    if (next->bytes == NULL || next->taints == NULL) { free(next->taints); free(next->bytes); return XAIR_SYM_ERR_OOM; }
    for (capacity = 0; capacity < size; ++capacity) next->bytes[capacity] = XAIR_SYM_INVALID_ID;
    *out_object = (xair_sym_object_id)state->memory->count++;
    state->context->stats.memory_objects++;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_store8(xair_sym_state *state, uint64_t address, xair_sym_expr_id value) {
    xair_sym_object *object; xair_sym_status status;
    if (state == NULL || value >= state->context->expression_count || state->context->expressions[value]->bits != 8) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_memory_make_unique(state); if (status != XAIR_SYM_OK) return status;
    object = find_object(state->memory, address); if (object == NULL || (object->permissions & 2u) == 0) return XAIR_SYM_ERR_RANGE;
    object->bytes[address - object->base] = value; return XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_load8(const xair_sym_state *state, uint64_t address, xair_sym_expr_id *out_value) {
    xair_sym_object *object;
    if (state == NULL || out_value == NULL) return XAIR_SYM_ERR_BAD_ARG;
    object = find_object(state->memory, address); if (object == NULL || (object->permissions & 1u) == 0) return XAIR_SYM_ERR_RANGE;
    *out_value = object->bytes[address - object->base];
    return *out_value == XAIR_SYM_INVALID_ID ? XAIR_SYM_ERR_RANGE : XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_store_taint8(
    xair_sym_state *state,
    uint64_t address,
    xair_sym_taint_id taint) {
    xair_sym_object *object;
    xair_sym_status status;
    if (state == NULL || taint > state->context->taint_count) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_memory_make_unique(state);
    if (status != XAIR_SYM_OK) return status;
    object = find_object(state->memory, address);
    if (object == NULL || (object->permissions & 2u) == 0) return XAIR_SYM_ERR_RANGE;
    object->taints[address - object->base] = taint;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_load_taint8(
    const xair_sym_state *state,
    uint64_t address,
    xair_sym_taint_id *out_taint) {
    xair_sym_object *object;
    if (state == NULL || out_taint == NULL) return XAIR_SYM_ERR_BAD_ARG;
    object = find_object(state->memory, address);
    if (object == NULL || (object->permissions & 1u) == 0) return XAIR_SYM_ERR_RANGE;
    *out_taint = object->taints[address - object->base];
    return XAIR_SYM_OK;
}

static xair_sym_status address_condition(
    xair_sym_state *state,
    xair_sym_expr_id address,
    uint64_t concrete,
    xair_sym_expr_id *out_condition) {
    uint16_t bits = state->context->expressions[address]->bits;
    xair_sym_expr_id constant;
    xair_sym_status status = xair_sym_const(state->context, bits, concrete, &constant);
    if (status != XAIR_SYM_OK) return status;
    return xair_sym_binary(state->context, XAIR_OP_EQ, 1, address, constant, out_condition);
}

xair_sym_status xair_sym_memory_load_symbolic8(
    xair_sym_state *state,
    xair_sym_expr_id address,
    xair_sym_expr_id *out_value) {
    xair_sym_expr_id result = XAIR_SYM_INVALID_ID;
    xair_sym_expr_id valid = XAIR_SYM_INVALID_ID;
    size_t object_i;

    if (state == NULL || out_value == NULL || address >= state->context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    for (object_i = 0; object_i < state->memory->count; ++object_i) {
        xair_sym_object *object = &state->memory->objects[object_i];
        size_t offset;
        if ((object->permissions & 1u) == 0) continue;
        for (offset = 0; offset < object->size; ++offset) {
            xair_sym_expr_id condition;
            xair_sym_status status;
            if (object->bytes[offset] == XAIR_SYM_INVALID_ID) return XAIR_SYM_ERR_RANGE;
            status = address_condition(state, address, object->base + offset, &condition);
            if (status != XAIR_SYM_OK) return status;
            if (result == XAIR_SYM_INVALID_ID) {
                result = object->bytes[offset];
                valid = condition;
            } else {
                xair_sym_expr_id selected;
                xair_sym_expr_id combined;
                status = xair_sym_select(state->context, condition, object->bytes[offset], result, &selected);
                if (status != XAIR_SYM_OK) return status;
                status = xair_sym_binary(state->context, XAIR_OP_OR, 1, valid, condition, &combined);
                if (status != XAIR_SYM_OK) return status;
                result = selected;
                valid = combined;
            }
        }
    }
    if (result == XAIR_SYM_INVALID_ID) return XAIR_SYM_ERR_RANGE;
    if (xair_sym_state_assume(state, valid) != XAIR_SYM_OK) return XAIR_SYM_ERR_OOM;
    *out_value = result;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_store_symbolic8(
    xair_sym_state *state,
    xair_sym_expr_id address,
    xair_sym_expr_id value) {
    xair_sym_expr_id valid = XAIR_SYM_INVALID_ID;
    size_t object_i;
    xair_sym_status status;

    if (state == NULL || address >= state->context->expression_count || value >= state->context->expression_count ||
        state->context->expressions[value]->bits != 8) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_memory_make_unique(state);
    if (status != XAIR_SYM_OK) return status;
    for (object_i = 0; object_i < state->memory->count; ++object_i) {
        xair_sym_object *object = &state->memory->objects[object_i];
        size_t offset;
        if ((object->permissions & 2u) == 0) continue;
        for (offset = 0; offset < object->size; ++offset) {
            xair_sym_expr_id condition;
            xair_sym_expr_id selected;
            if (object->bytes[offset] == XAIR_SYM_INVALID_ID) return XAIR_SYM_ERR_RANGE;
            status = address_condition(state, address, object->base + offset, &condition);
            if (status != XAIR_SYM_OK) return status;
            status = xair_sym_select(state->context, condition, value, object->bytes[offset], &selected);
            if (status != XAIR_SYM_OK) return status;
            object->bytes[offset] = selected;
            if (valid == XAIR_SYM_INVALID_ID) valid = condition;
            else {
                xair_sym_expr_id combined;
                status = xair_sym_binary(state->context, XAIR_OP_OR, 1, valid, condition, &combined);
                if (status != XAIR_SYM_OK) return status;
                valid = combined;
            }
        }
    }
    if (valid == XAIR_SYM_INVALID_ID) return XAIR_SYM_ERR_RANGE;
    return xair_sym_state_assume(state, valid);
}

xair_sym_status xair_sym_memory_union_taint(
    xair_sym_state *state,
    uint32_t permission,
    xair_sym_taint_id taint,
    int update,
    xair_sym_taint_id *out_taint) {
    xair_sym_taint_id result = XAIR_SYM_TAINT_NONE;
    size_t object_i;
    xair_sym_status status;
    if (state == NULL || out_taint == NULL || taint > state->context->taint_count) return XAIR_SYM_ERR_BAD_ARG;
    if (update) {
        status = xair_sym_memory_make_unique(state);
        if (status != XAIR_SYM_OK) return status;
    }
    for (object_i = 0; object_i < state->memory->count; ++object_i) {
        xair_sym_object *object = &state->memory->objects[object_i];
        size_t offset;
        if ((object->permissions & permission) == 0) continue;
        for (offset = 0; offset < object->size; ++offset) {
            status = xair_sym_taint_union(state->context, result, object->taints[offset], &result);
            if (status != XAIR_SYM_OK) return status;
            if (update) {
                status = xair_sym_taint_union(state->context, object->taints[offset], taint, &object->taints[offset]);
                if (status != XAIR_SYM_OK) return status;
            }
        }
    }
    *out_taint = result;
    return XAIR_SYM_OK;
}
