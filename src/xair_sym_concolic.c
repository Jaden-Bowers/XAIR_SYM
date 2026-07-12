#include "xair_sym_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

xair_sym_status xair_sym_trace_create(xair_sym_trace **out_trace) {
    xair_sym_trace *trace;
    if (out_trace == NULL) return XAIR_SYM_ERR_BAD_ARG;
    trace = (xair_sym_trace *)calloc(1, sizeof(*trace));
    if (trace == NULL) return XAIR_SYM_ERR_OOM;
    *out_trace = trace;
    return XAIR_SYM_OK;
}

void xair_sym_trace_destroy(xair_sym_trace *trace) {
    if (trace != NULL) { free(trace->branches); free(trace); }
}

xair_sym_status xair_sym_trace_add_branch(
    xair_sym_trace *trace,
    xair_block_id block,
    xair_sym_expr_id condition,
    int taken) {
    xair_sym_trace_branch *branches;
    size_t capacity;
    if (trace == NULL || condition == XAIR_SYM_INVALID_ID) return XAIR_SYM_ERR_BAD_ARG;
    if (trace->count == trace->capacity) {
        capacity = trace->capacity == 0 ? 16 : trace->capacity * 2;
        branches = (xair_sym_trace_branch *)realloc(trace->branches, capacity * sizeof(*branches));
        if (branches == NULL) return XAIR_SYM_ERR_OOM;
        trace->branches = branches;
        trace->capacity = capacity;
    }
    trace->branches[trace->count].block = block;
    trace->branches[trace->count].condition = condition;
    trace->branches[trace->count].taken = taken ? 1u : 0u;
    trace->count++;
    return XAIR_SYM_OK;
}

size_t xair_sym_trace_count(const xair_sym_trace *trace) { return trace == NULL ? 0 : trace->count; }

xair_sym_status xair_sym_trace_get(
    const xair_sym_trace *trace,
    size_t index,
    xair_sym_trace_branch *out_branch) {
    if (trace == NULL || out_branch == NULL || index >= trace->count) return XAIR_SYM_ERR_BAD_ARG;
    *out_branch = trace->branches[index];
    return XAIR_SYM_OK;
}

static xair_sym_status branch_constraint(
    xair_sym_state *state,
    xair_sym_expr_id condition,
    int taken,
    xair_sym_expr_id *out_constraint) {
    xair_sym_expr_id zero;
    xair_sym_status status;
    if (taken) { *out_constraint = condition; return XAIR_SYM_OK; }
    status = xair_sym_const(state->context, 1, 0, &zero);
    if (status != XAIR_SYM_OK) return status;
    return xair_sym_binary(state->context, XAIR_OP_EQ, 1, condition, zero, out_constraint);
}

xair_sym_status xair_sym_concolic_invert(
    const xair_sym_state *base,
    const xair_sym_trace *trace,
    size_t branch_index,
    xair_sym_state **out_state) {
    xair_sym_state *state;
    size_t i;
    xair_sym_status status;
    xair_sym_sat sat;
    if (base == NULL || trace == NULL || out_state == NULL || branch_index >= trace->count) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_state_clone(base, &state);
    if (status != XAIR_SYM_OK) return status;
    for (i = 0; i <= branch_index; ++i) {
        xair_sym_expr_id constraint;
        int taken = trace->branches[i].taken != 0;
        if (trace->branches[i].condition >= state->context->expression_count) { status = XAIR_SYM_ERR_BAD_ARG; goto fail; }
        if (i == branch_index) taken = !taken;
        status = branch_constraint(state, trace->branches[i].condition, taken, &constraint);
        if (status != XAIR_SYM_OK) goto fail;
        status = xair_sym_check(state, constraint, &sat);
        if (status != XAIR_SYM_OK) goto fail;
        if (sat != XAIR_SYM_SAT) { status = XAIR_SYM_ERR_INFEASIBLE; goto fail; }
        status = xair_sym_state_assume(state, constraint);
        if (status != XAIR_SYM_OK) goto fail;
    }
    *out_state = state;
    return XAIR_SYM_OK;
fail:
    xair_sym_state_destroy(state);
    return status;
}

xair_sym_status xair_sym_model_bytes(
    xair_sym_state *state,
    const xair_sym_expr_id *symbols,
    size_t count,
    uint8_t *out_bytes) {
    size_t i;
    if (state == NULL || (count != 0 && (symbols == NULL || out_bytes == NULL))) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < count; ++i) {
        uint64_t value;
        xair_sym_status status = xair_sym_model_u64(state, symbols[i], &value);
        if (status != XAIR_SYM_OK) return status;
        out_bytes[i] = (uint8_t)value;
    }
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_state_concretize(
    xair_sym_state *state,
    xair_sym_expr_id expression,
    xair_sym_expr_id *out_constant) {
    uint64_t value;
    xair_sym_status status;
    if (state == NULL || out_constant == NULL || expression >= state->context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    if (state->context->expressions[expression]->bits > 64) return XAIR_SYM_ERR_UNSUPPORTED;
    status = xair_sym_model_u64(state, expression, &value);
    if (status != XAIR_SYM_OK) return status;
    return xair_sym_const(state->context, state->context->expressions[expression]->bits, value, out_constant);
}

static void encode_u64(uint8_t bytes[8], uint64_t value) {
    unsigned i;
    for (i = 0; i < 8; ++i) bytes[i] = (uint8_t)(value >> (i * 8u));
}

static uint64_t decode_u64(const uint8_t bytes[8]) {
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (i * 8u);
    return value;
}

xair_sym_status xair_sym_testcase_write(const char *path, const uint8_t *bytes, size_t size) {
    static const uint8_t magic[8] = {'X','A','I','R','I','N','0','1'};
    uint8_t encoded_size[8];
    FILE *file;
    int failed;
    if (path == NULL || (size != 0 && bytes == NULL) || (uint64_t)size != size) return XAIR_SYM_ERR_BAD_ARG;
    file = fopen(path, "wb"); if (file == NULL) return XAIR_SYM_ERR_BAD_ARG;
    encode_u64(encoded_size, (uint64_t)size);
    failed = fwrite(magic, 1, sizeof(magic), file) != sizeof(magic) ||
        fwrite(encoded_size, 1, sizeof(encoded_size), file) != sizeof(encoded_size) ||
        (size != 0 && fwrite(bytes, 1, size, file) != size);
    if (fclose(file) != 0) failed = 1;
    if (failed) return XAIR_SYM_ERR_BAD_ARG;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_testcase_read(const char *path, uint8_t *bytes, size_t capacity, size_t *out_size) {
    static const uint8_t magic[8] = {'X','A','I','R','I','N','0','1'};
    uint8_t header[16];
    uint64_t size;
    FILE *file;
    if (path == NULL || out_size == NULL) return XAIR_SYM_ERR_BAD_ARG;
    file = fopen(path, "rb"); if (file == NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (fread(header, 1, sizeof(header), file) != sizeof(header) || memcmp(header, magic, sizeof(magic)) != 0) {
        fclose(file); return XAIR_SYM_ERR_BAD_ARG;
    }
    size = decode_u64(header + 8);
    if (size > capacity || size > SIZE_MAX || (size != 0 && bytes == NULL) ||
        (size != 0 && fread(bytes, 1, (size_t)size, file) != (size_t)size)) {
        fclose(file); return XAIR_SYM_ERR_RANGE;
    }
    if (fclose(file) != 0) return XAIR_SYM_ERR_BAD_ARG;
    *out_size = (size_t)size;
    return XAIR_SYM_OK;
}
