#include "xair_sym_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XAIR_SYM_SNAPSHOT_MAX_OBJECTS UINT64_C(1048576)
#define XAIR_SYM_SNAPSHOT_MAX_OBJECT_SIZE UINT64_C(536870912)
#define XAIR_SYM_SNAPSHOT_MAX_MEMORY UINT64_C(1073741824)

static uint64_t snapshot_mix(uint64_t hash, uint64_t value) {
    return hash ^ (value + UINT64_C(0x9e3779b97f4a7c15) + (hash << 6u) + (hash >> 2u));
}

static uint64_t context_signature(const xair_sym_context *context) {
    uint64_t signature = UINT64_C(0x58414952534e4150);
    size_t i;
    signature = snapshot_mix(signature, context->expression_count);
    for (i = 0; i < context->expression_count; ++i) signature = snapshot_mix(signature, context->expressions[i]->hash);
    signature = snapshot_mix(signature, context->taint_count);
    for (i = 0; i < context->taint_count; ++i) signature = snapshot_mix(signature, context->taints[i]->hash);
    return signature;
}

xair_sym_status xair_sym_snapshot_take(const xair_sym_state *state, xair_sym_snapshot **out_snapshot) {
    xair_sym_snapshot *snapshot;
    xair_status status;
    if (state == NULL || out_snapshot == NULL) return XAIR_SYM_ERR_BAD_ARG;
    snapshot = (xair_sym_snapshot *)calloc(1, sizeof(*snapshot));
    if (snapshot == NULL) return XAIR_SYM_ERR_OOM;
    status = xair_module_fingerprint(state->module, &snapshot->module_fingerprint);
    if (status != XAIR_OK) { free(snapshot); return XAIR_SYM_ERR_BAD_ARG; }
    if (xair_sym_state_clone(state, &snapshot->state) != XAIR_SYM_OK) { free(snapshot); return XAIR_SYM_ERR_OOM; }
    snapshot->state->program = NULL;
    *out_snapshot = snapshot;
    return XAIR_SYM_OK;
}

void xair_sym_snapshot_destroy(xair_sym_snapshot *snapshot) {
    if (snapshot != NULL) { xair_sym_state_destroy(snapshot->state); free(snapshot); }
}

xair_sym_status xair_sym_snapshot_restore(const xair_sym_snapshot *snapshot, xair_sym_state **out_state) {
    if (snapshot == NULL || out_state == NULL) return XAIR_SYM_ERR_BAD_ARG;
    return xair_sym_state_clone(snapshot->state, out_state);
}

static int write_u8(FILE *file, uint8_t value) { return fwrite(&value, 1, 1, file) == 1; }
static int write_u32(FILE *file, uint32_t value) {
    uint8_t bytes[4]; unsigned i;
    for (i = 0; i < 4; ++i) bytes[i] = (uint8_t)(value >> (i * 8u));
    return fwrite(bytes, 1, 4, file) == 4;
}
static int write_u64(FILE *file, uint64_t value) {
    uint8_t bytes[8]; unsigned i;
    for (i = 0; i < 8; ++i) bytes[i] = (uint8_t)(value >> (i * 8u));
    return fwrite(bytes, 1, 8, file) == 8;
}
static int read_u8(FILE *file, uint8_t *value) { return fread(value, 1, 1, file) == 1; }
static int read_u32(FILE *file, uint32_t *value) {
    uint8_t bytes[4]; unsigned i; uint32_t result = 0;
    if (fread(bytes, 1, 4, file) != 4) return 0;
    for (i = 0; i < 4; ++i) result |= (uint32_t)bytes[i] << (i * 8u);
    *value = result; return 1;
}
static int read_u64(FILE *file, uint64_t *value) {
    uint8_t bytes[8]; unsigned i; uint64_t result = 0;
    if (fread(bytes, 1, 8, file) != 8) return 0;
    for (i = 0; i < 8; ++i) result |= (uint64_t)bytes[i] << (i * 8u);
    *value = result; return 1;
}

xair_sym_status xair_sym_snapshot_save(const xair_sym_snapshot *snapshot, const char *path) {
    static const uint8_t magic[8] = {'X','A','I','R','S','N','0','1'};
    const xair_sym_state *state;
    xair_sym_constraint *constraint;
    xair_sym_expr_id *constraints = NULL;
    FILE *file;
    size_t i;
    int ok = 1;
    if (snapshot == NULL || path == NULL) return XAIR_SYM_ERR_BAD_ARG;
    state = snapshot->state;
    file = fopen(path, "wb"); if (file == NULL) return XAIR_SYM_ERR_BAD_ARG;
    ok = fwrite(magic, 1, sizeof(magic), file) == sizeof(magic) &&
        write_u64(file, snapshot->module_fingerprint) && write_u64(file, context_signature(state->context)) &&
        write_u32(file, state->block) && write_u64(file, state->depth) && write_u32(file, state->control_taint) &&
        write_u64(file, state->value_count);
    for (i = 0; ok && i < state->value_count; ++i) {
        ok = write_u8(file, state->defined[i]) &&
            write_u32(file, state->defined[i] ? state->values[i] : XAIR_SYM_INVALID_ID) &&
            write_u32(file, state->value_taints[i]);
    }
    if (state->constraints != NULL) {
        constraints = (xair_sym_expr_id *)malloc(state->constraints->count * sizeof(*constraints));
        if (constraints == NULL) ok = 0;
        else {
            size_t index = state->constraints->count;
            for (constraint = state->constraints; constraint != NULL; constraint = constraint->parent) constraints[--index] = constraint->expression;
        }
    }
    if (ok) ok = write_u64(file, state->constraints == NULL ? 0 : state->constraints->count);
    for (i = 0; ok && state->constraints != NULL && i < state->constraints->count; ++i) ok = write_u32(file, constraints[i]);
    if (ok) ok = write_u64(file, state->memory->count);
    for (i = 0; ok && i < state->memory->count; ++i) {
        const xair_sym_object *object = &state->memory->objects[i];
        size_t byte_i;
        ok = write_u64(file, object->base) && write_u64(file, object->size) && write_u32(file, object->permissions);
        for (byte_i = 0; ok && byte_i < object->size; ++byte_i) {
            ok = write_u32(file, object->bytes[byte_i]) && write_u32(file, object->taints[byte_i]);
        }
    }
    free(constraints);
    if (fclose(file) != 0) ok = 0;
    return ok ? XAIR_SYM_OK : XAIR_SYM_ERR_BAD_ARG;
}

xair_sym_status xair_sym_snapshot_load(
    xair_sym_context *context,
    const xair_module *module,
    const char *path,
    xair_sym_snapshot **out_snapshot) {
    static const uint8_t magic[8] = {'X','A','I','R','S','N','0','1'};
    uint8_t actual_magic[8];
    uint64_t module_fingerprint, signature, value_count, constraint_count, object_count;
    uint32_t block, control_taint;
    uint64_t depth;
    xair_sym_state *state = NULL;
    xair_sym_snapshot *snapshot = NULL;
    FILE *file;
    size_t i;
    xair_sym_status result = XAIR_SYM_ERR_BAD_ARG;
    if (context == NULL || module == NULL || path == NULL || out_snapshot == NULL) return XAIR_SYM_ERR_BAD_ARG;
    file = fopen(path, "rb"); if (file == NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (fread(actual_magic, 1, sizeof(actual_magic), file) != sizeof(actual_magic) || memcmp(actual_magic, magic, sizeof(magic)) != 0 ||
        !read_u64(file, &module_fingerprint) || !read_u64(file, &signature) ||
        !read_u32(file, &block) || !read_u64(file, &depth) || !read_u32(file, &control_taint) || !read_u64(file, &value_count)) goto done;
    {
        uint64_t current_fingerprint;
        if (xair_module_fingerprint(module, &current_fingerprint) != XAIR_OK || current_fingerprint != module_fingerprint ||
            signature != context_signature(context) || value_count != xair_module_value_count(module) ||
            block >= xair_module_block_count(module) || control_taint > context->taint_count) goto done;
    }
    result = xair_sym_state_create(context, module, block, &state); if (result != XAIR_SYM_OK) goto done;
    if (depth > SIZE_MAX) { result = XAIR_SYM_ERR_RANGE; goto done; }
    state->depth = (size_t)depth; state->control_taint = control_taint;
    for (i = 0; i < state->value_count; ++i) {
        uint8_t defined; uint32_t expression, taint;
        if (!read_u8(file, &defined) || !read_u32(file, &expression) || !read_u32(file, &taint) ||
            defined > 1 || (defined && expression >= context->expression_count) || taint > context->taint_count) { result = XAIR_SYM_ERR_BAD_ARG; goto done; }
        state->defined[i] = defined; state->values[i] = expression; state->value_taints[i] = taint;
    }
    if (!read_u64(file, &constraint_count) || constraint_count > SIZE_MAX) { result = XAIR_SYM_ERR_RANGE; goto done; }
    for (i = 0; i < (size_t)constraint_count; ++i) {
        uint32_t expression;
        if (!read_u32(file, &expression) || expression >= context->expression_count) { result = XAIR_SYM_ERR_BAD_ARG; goto done; }
        result = xair_sym_state_assume(state, expression); if (result != XAIR_SYM_OK) goto done;
    }
    if (!read_u64(file, &object_count) || object_count > XAIR_SYM_SNAPSHOT_MAX_OBJECTS || object_count > SIZE_MAX) {
        result = XAIR_SYM_ERR_RANGE; goto done;
    }
    {
        uint64_t total_memory = 0;
    for (i = 0; i < (size_t)object_count; ++i) {
        uint64_t base, size64; uint32_t permissions; xair_sym_object_id object; size_t byte_i;
        if (!read_u64(file, &base) || !read_u64(file, &size64) || !read_u32(file, &permissions) ||
            size64 == 0 || size64 > XAIR_SYM_SNAPSHOT_MAX_OBJECT_SIZE || size64 > SIZE_MAX ||
            total_memory > XAIR_SYM_SNAPSHOT_MAX_MEMORY - size64) { result = XAIR_SYM_ERR_BAD_ARG; goto done; }
        total_memory += size64;
        result = xair_sym_object_add(state, base, (size_t)size64, permissions, &object); if (result != XAIR_SYM_OK) goto done;
        (void)object;
        for (byte_i = 0; byte_i < (size_t)size64; ++byte_i) {
            uint32_t expression, taint;
            if (!read_u32(file, &expression) || !read_u32(file, &taint) ||
                (expression != XAIR_SYM_INVALID_ID && expression >= context->expression_count) || taint > context->taint_count) {
                result = XAIR_SYM_ERR_BAD_ARG; goto done;
            }
            if (expression != XAIR_SYM_INVALID_ID) {
                result = xair_sym_memory_initialize8(state, base + byte_i, expression); if (result != XAIR_SYM_OK) goto done;
            }
            result = xair_sym_memory_initialize_taint8(state, base + byte_i, taint); if (result != XAIR_SYM_OK) goto done;
        }
    }
    }
    snapshot = (xair_sym_snapshot *)calloc(1, sizeof(*snapshot));
    if (snapshot == NULL) { result = XAIR_SYM_ERR_OOM; goto done; }
    snapshot->state = state; snapshot->module_fingerprint = module_fingerprint; state = NULL;
    *out_snapshot = snapshot; result = XAIR_SYM_OK;
done:
    if (fclose(file) != 0 && result == XAIR_SYM_OK) result = XAIR_SYM_ERR_BAD_ARG;
    if (result != XAIR_SYM_OK) { xair_sym_snapshot_destroy(snapshot); xair_sym_state_destroy(state); }
    return result;
}

xair_sym_status xair_sym_snapshot_clone_isolated(
    const xair_sym_snapshot *snapshot,
    xair_sym_context **out_context,
    xair_sym_state **out_state) {
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    const xair_sym_context *source_context;
    const xair_sym_state *source_state;
    xair_sym_expr_id *constraints = NULL;
    size_t i;
    xair_sym_status status;
    if (snapshot == NULL || out_context == NULL || out_state == NULL) return XAIR_SYM_ERR_BAD_ARG;
    source_state = snapshot->state; source_context = source_state->context;
    status = xair_sym_context_create(&context); if (status != XAIR_SYM_OK) return status;
    xair_sym_context_set_taint_mode(context, source_context->taint_mode);
    for (i = 0; i < source_context->expression_count; ++i) {
        const xair_sym_expr *expression = source_context->expressions[i];
        xair_sym_expr_id rebuilt;
        if (expression->kind == XAIR_SYM_EXPR_CONST) status = xair_sym_const(context, expression->bits, expression->immediate, &rebuilt);
        else if (expression->kind == XAIR_SYM_EXPR_SYMBOL) status = xair_sym_symbol(context, expression->bits, expression->symbol, &rebuilt);
        else if (expression->arg_count == 1) status = xair_sym_unary(context, expression->opcode, expression->bits,
            expression->args[0], expression->immediate, &rebuilt);
        else if (expression->arg_count == 2) status = xair_sym_binary(context, expression->opcode, expression->bits,
            expression->args[0], expression->args[1], &rebuilt);
        else if (expression->opcode == XAIR_OP_SELECT) status = xair_sym_select(context,
            expression->args[0], expression->args[1], expression->args[2], &rebuilt);
        else status = XAIR_SYM_ERR_UNSUPPORTED;
        if (status != XAIR_SYM_OK || rebuilt != i) { status = XAIR_SYM_ERR_UNSUPPORTED; goto fail; }
    }
    for (i = 0; i < source_context->taint_count; ++i) {
        const xair_sym_taint_node *node = source_context->taints[i];
        xair_sym_taint_id rebuilt;
        if (node->kind == XAIR_SYM_TAINT_NODE_SOURCE) status = xair_sym_taint_source(context, node->name, &rebuilt);
        else if (node->kind == XAIR_SYM_TAINT_NODE_UNION) status = xair_sym_taint_union(context, node->lhs, node->rhs, &rebuilt);
        else status = xair_sym_taint_sanitize(context, node->lhs, node->name, &rebuilt);
        if (status != XAIR_SYM_OK || rebuilt != i + 1) { status = XAIR_SYM_ERR_UNSUPPORTED; goto fail; }
    }
    status = xair_sym_state_create(context, source_state->module, source_state->block, &state); if (status != XAIR_SYM_OK) goto fail;
    state->depth = source_state->depth; state->control_taint = source_state->control_taint;
    memcpy(state->defined, source_state->defined, source_state->value_count);
    memcpy(state->values, source_state->values, source_state->value_count * sizeof(*state->values));
    memcpy(state->value_taints, source_state->value_taints, source_state->value_count * sizeof(*state->value_taints));
    if (source_state->constraints != NULL) {
        xair_sym_constraint *constraint;
        size_t index = source_state->constraints->count;
        constraints = (xair_sym_expr_id *)malloc(index * sizeof(*constraints));
        if (constraints == NULL) { status = XAIR_SYM_ERR_OOM; goto fail; }
        for (constraint = source_state->constraints; constraint != NULL; constraint = constraint->parent) constraints[--index] = constraint->expression;
        for (index = 0; index < source_state->constraints->count; ++index) {
            status = xair_sym_state_assume(state, constraints[index]); if (status != XAIR_SYM_OK) goto fail;
        }
    }
    for (i = 0; i < source_state->memory->count; ++i) {
        const xair_sym_object *object = &source_state->memory->objects[i];
        xair_sym_object_id object_id;
        size_t byte_i;
        status = xair_sym_object_add(state, object->base, object->size, object->permissions, &object_id); if (status != XAIR_SYM_OK) goto fail;
        (void)object_id;
        for (byte_i = 0; byte_i < object->size; ++byte_i) {
            if (object->bytes[byte_i] != XAIR_SYM_INVALID_ID) {
                status = xair_sym_memory_initialize8(state, object->base + byte_i, object->bytes[byte_i]); if (status != XAIR_SYM_OK) goto fail;
            }
            status = xair_sym_memory_initialize_taint8(state, object->base + byte_i, object->taints[byte_i]); if (status != XAIR_SYM_OK) goto fail;
        }
    }
    free(constraints); *out_context = context; *out_state = state; return XAIR_SYM_OK;
fail:
    free(constraints); xair_sym_state_destroy(state); xair_sym_context_destroy(context); return status;
}
