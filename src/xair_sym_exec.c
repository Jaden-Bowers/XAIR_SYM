#include "xair_sym_internal.h"

#include <stdlib.h>
#include <string.h>

static void constraint_retain(xair_sym_constraint *constraint) {
    if (constraint != NULL) constraint->refs++;
}

static void constraint_release(xair_sym_constraint *constraint) {
    while (constraint != NULL) {
        xair_sym_constraint *parent;
        if (--constraint->refs != 0) return;
        parent = constraint->parent;
        free(constraint);
        constraint = parent;
    }
}

xair_sym_status xair_sym_state_create(xair_sym_context *context, const xair_module *module,
    xair_block_id entry, xair_sym_state **out_state) {
    xair_sym_state *state;
    if (context == NULL || module == NULL || out_state == NULL || entry >= xair_module_block_count(module)) return XAIR_SYM_ERR_BAD_ARG;
    state = (xair_sym_state *)calloc(1, sizeof(*state)); if (state == NULL) return XAIR_SYM_ERR_OOM;
    state->context = context; state->module = module; state->block = entry; state->value_count = xair_module_value_count(module);
    state->values = (xair_sym_expr_id *)malloc((state->value_count != 0 ? state->value_count : 1) * sizeof(*state->values));
    state->defined = (uint8_t *)calloc(state->value_count != 0 ? state->value_count : 1, 1);
    state->memory = xair_sym_memory_create();
    if (state->values == NULL || state->defined == NULL || state->memory == NULL) { xair_sym_state_destroy(state); return XAIR_SYM_ERR_OOM; }
    context->stats.states_created++; *out_state = state; return XAIR_SYM_OK;
}

xair_sym_status xair_sym_state_clone(const xair_sym_state *source, xair_sym_state **out_state) {
    xair_sym_state *state;
    if (source == NULL || out_state == NULL) return XAIR_SYM_ERR_BAD_ARG;
    state = (xair_sym_state *)calloc(1, sizeof(*state)); if (state == NULL) return XAIR_SYM_ERR_OOM;
    *state = *source; state->values = NULL; state->defined = NULL; state->constraints = NULL; state->memory = NULL;
    state->values = (xair_sym_expr_id *)malloc((state->value_count != 0 ? state->value_count : 1) * sizeof(*state->values));
    state->defined = (uint8_t *)malloc(state->value_count != 0 ? state->value_count : 1);
    if (state->values == NULL || state->defined == NULL) { xair_sym_state_destroy(state); return XAIR_SYM_ERR_OOM; }
    memcpy(state->values, source->values, state->value_count * sizeof(*state->values));
    memcpy(state->defined, source->defined, state->value_count);
    state->constraints = source->constraints; constraint_retain(state->constraints);
    state->memory = source->memory; xair_sym_memory_retain(state->memory);
    state->context->stats.states_created++; *out_state = state; return XAIR_SYM_OK;
}

void xair_sym_state_destroy(xair_sym_state *state) {
    if (state == NULL) return;
    xair_sym_memory_release(state->memory); constraint_release(state->constraints); free(state->defined); free(state->values); free(state);
}

xair_sym_status xair_sym_state_set_value(xair_sym_state *state, xair_value_id value, xair_sym_expr_id expr) {
    if (state == NULL || value >= state->value_count || expr >= state->context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    if (xair_value_type(state->module, value).kind != XAIR_TYPE_MEM &&
        xair_value_type(state->module, value).kind != XAIR_TYPE_FLAGS &&
        xair_value_type(state->module, value).kind != XAIR_TYPE_ADDR &&
        xair_value_type(state->module, value).kind != XAIR_TYPE_INT) return XAIR_SYM_ERR_BAD_ARG;
    state->values[value] = expr; state->defined[value] = 1; return XAIR_SYM_OK;
}

xair_sym_status xair_sym_state_get_value(const xair_sym_state *state, xair_value_id value, xair_sym_expr_id *out_expr) {
    if (state == NULL || out_expr == NULL || value >= state->value_count || !state->defined[value]) return XAIR_SYM_ERR_BAD_ARG;
    *out_expr = state->values[value]; return XAIR_SYM_OK;
}

xair_sym_status xair_sym_state_assume(xair_sym_state *state, xair_sym_expr_id condition) {
    xair_sym_constraint *constraint;
    if (state == NULL || condition >= state->context->expression_count || state->context->expressions[condition]->bits != 1) return XAIR_SYM_ERR_BAD_ARG;
    constraint = (xair_sym_constraint *)malloc(sizeof(*constraint));
    if (constraint == NULL) return XAIR_SYM_ERR_OOM;
    constraint->refs = 1;
    constraint->count = state->constraints == NULL ? 1 : state->constraints->count + 1;
    constraint->expression = condition;
    constraint->parent = state->constraints;
    state->constraints = constraint;
    return XAIR_SYM_OK;
}

xair_block_id xair_sym_state_block(const xair_sym_state *state) { return state == NULL ? XAIR_INVALID_ID : state->block; }

static xair_sym_status expression_constant(const xair_sym_state *state, xair_sym_expr_id id, uint64_t *out) {
    if (id >= state->context->expression_count || state->context->expressions[id]->kind != XAIR_SYM_EXPR_CONST) return XAIR_SYM_ERR_UNSUPPORTED;
    *out = state->context->expressions[id]->immediate; return XAIR_SYM_OK;
}

static xair_sym_status execute_memory(xair_sym_state *state, const xair_op_view *op, xair_type out_type) {
    xair_sym_expr_id address_expr; uint64_t address; size_t bytes; size_t i; int address_is_concrete; xair_sym_status status;
    status = xair_sym_state_get_value(state, op->src[1], &address_expr); if (status != XAIR_SYM_OK) return status;
    status = expression_constant(state, address_expr, &address);
    address_is_concrete = status == XAIR_SYM_OK;
    if (op->opcode == XAIR_OP_LOAD) {
        xair_sym_expr_id result = XAIR_SYM_INVALID_ID;
        bytes = out_type.bits / 8u; if (out_type.bits == 0 || out_type.bits > 64 || out_type.bits % 8u != 0) return XAIR_SYM_ERR_UNSUPPORTED;
        for (i = 0; i < bytes; ++i) {
            xair_sym_expr_id byte;
            if (address_is_concrete) status = xair_sym_memory_load8(state, address + i, &byte);
            else if (bytes == 1) status = xair_sym_memory_load_symbolic8(state, address_expr, &byte);
            else return XAIR_SYM_ERR_UNSUPPORTED;
            if (status != XAIR_SYM_OK) return status;
            if (result == XAIR_SYM_INVALID_ID) result = byte;
            else { xair_sym_expr_id joined; status = xair_sym_binary(state->context, XAIR_OP_CONCAT,
                (uint16_t)((i + 1) * 8u), byte, result, &joined); if (status != XAIR_SYM_OK) return status; result = joined; }
        }
        return xair_sym_state_set_value(state, op->dst, result);
    }
    if (op->opcode == XAIR_OP_STORE) {
        xair_sym_expr_id data; xair_type type = xair_value_type(state->module, op->src[2]);
        status = xair_sym_state_get_value(state, op->src[2], &data); if (status != XAIR_SYM_OK) return status;
        bytes = type.bits / 8u; if (type.bits == 0 || type.bits > 64 || type.bits % 8u != 0) return XAIR_SYM_ERR_UNSUPPORTED;
        for (i = 0; i < bytes; ++i) {
            xair_sym_expr_id byte; status = xair_sym_unary(state->context, XAIR_OP_EXTRACT, 8, data, i * 8u, &byte);
            if (status != XAIR_SYM_OK) return status;
            if (address_is_concrete) status = xair_sym_memory_store8(state, address + i, byte);
            else if (bytes == 1) status = xair_sym_memory_store_symbolic8(state, address_expr, byte);
            else return XAIR_SYM_ERR_UNSUPPORTED;
            if (status != XAIR_SYM_OK) return status;
        }
        status = xair_sym_state_get_value(state, op->src[0], &data);
        return status == XAIR_SYM_OK ? xair_sym_state_set_value(state, op->dst, data) : status;
    }
    return XAIR_SYM_ERR_UNSUPPORTED;
}

static xair_sym_status execute_op(xair_sym_state *state, xair_op_id id) {
    xair_op_view op; xair_type out; xair_sym_expr_id args[3]; xair_sym_expr_id result; xair_sym_status status; size_t i;
    if (xair_module_get_op(state->module, id, &op) != XAIR_OK) return XAIR_SYM_ERR_BAD_ARG;
    out = xair_value_type(state->module, op.dst);
    if (op.opcode == XAIR_OP_CONST_U64) { status = xair_sym_const(state->context, out.bits, op.immediate, &result); }
    else if (op.opcode == XAIR_OP_LOAD || op.opcode == XAIR_OP_STORE) return execute_memory(state, &op, out);
    else {
        for (i = 0; i < op.src_count; ++i) { status = xair_sym_state_get_value(state, op.src[i], &args[i]); if (status != XAIR_SYM_OK) return status; }
        if (op.src_count == 1) status = xair_sym_unary(state->context, op.opcode, out.bits, args[0], op.immediate, &result);
        else if (op.src_count == 2) status = xair_sym_binary(state->context, op.opcode, out.bits, args[0], args[1], &result);
        else if (op.opcode == XAIR_OP_SELECT) status = xair_sym_select(state->context, args[0], args[1], args[2], &result);
        else return XAIR_SYM_ERR_UNSUPPORTED;
    }
    if (status != XAIR_SYM_OK) return status;
    return xair_sym_state_set_value(state, op.dst, result);
}

static xair_sym_status transfer(xair_sym_state *state, xair_block_id target, const xair_value_id *args, size_t count) {
    xair_sym_expr_id *copies; size_t i; xair_value_id parameter; xair_sym_status status;
    if (xair_block_param_count(state->module, target) != count) return XAIR_SYM_ERR_BAD_ARG;
    copies = (xair_sym_expr_id *)malloc((count != 0 ? count : 1) * sizeof(*copies)); if (copies == NULL) return XAIR_SYM_ERR_OOM;
    for (i = 0; i < count; ++i) { status = xair_sym_state_get_value(state, args[i], &copies[i]); if (status != XAIR_SYM_OK) { free(copies); return status; } }
    for (i = 0; i < count; ++i) { if (xair_block_param_value(state->module, target, i, &parameter) != XAIR_OK) { free(copies); return XAIR_SYM_ERR_BAD_ARG; }
        status = xair_sym_state_set_value(state, parameter, copies[i]); if (status != XAIR_SYM_OK) { free(copies); return status; } }
    free(copies); state->block = target; return XAIR_SYM_OK;
}

static xair_sym_status enqueue(xair_sym_state ***queue, size_t *count, size_t *capacity, xair_sym_state *state) {
    xair_sym_state **next; size_t cap;
    if (*count == *capacity) {
        cap = *capacity == 0 ? 16 : *capacity * 2;
        next = (xair_sym_state **)realloc(*queue, cap * sizeof(*next));
        if (next == NULL) return XAIR_SYM_ERR_OOM;
        *queue = next;
        *capacity = cap;
    }
    (*queue)[(*count)++] = state; return XAIR_SYM_OK;
}

xair_sym_status xair_sym_explore(xair_sym_state *initial, size_t max_states, size_t max_steps,
    xair_sym_terminal_cb callback, void *user) {
    xair_sym_state **queue = NULL;
    size_t queued = 0, capacity = 0, cursor = 0, steps = 0;
    xair_sym_state *state = NULL;
    xair_sym_status status;
    if (initial == NULL || max_states == 0 || max_steps == 0) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_state_clone(initial, &state); if (status != XAIR_SYM_OK) return status;
    status = enqueue(&queue, &queued, &capacity, state);
    if (status != XAIR_SYM_OK) { xair_sym_state_destroy(state); return status; }
    state = NULL;
    while (cursor < queued && cursor < max_states && steps < max_steps) {
        const xair_op_id *ops; size_t op_count, i; xair_term_view term;
        state = queue[cursor]; queue[cursor++] = NULL;
        steps++; if (xair_block_ops(state->module, state->block, &ops, &op_count) != XAIR_OK) { status = XAIR_SYM_ERR_BAD_ARG; goto fail; }
        for (i = 0; i < op_count; ++i) { status = execute_op(state, ops[i]); if (status != XAIR_SYM_OK) goto fail; }
        if (xair_block_terminator(state->module, state->block, &term) != XAIR_OK) { status = XAIR_SYM_ERR_BAD_ARG; goto fail; }
        if (term.kind == XAIR_TERM_VIEW_JUMP) {
            status = transfer(state, term.true_target, term.true_args, term.true_arg_count);
            if (status != XAIR_SYM_OK) goto fail;
            status = enqueue(&queue, &queued, &capacity, state);
            if (status != XAIR_SYM_OK) goto fail;
            state = NULL;
            continue;
        }
        if (term.kind == XAIR_TERM_VIEW_CBRANCH) {
            xair_sym_expr_id condition, zero, negated; xair_sym_state *false_state = NULL; xair_sym_sat sat;
            status = xair_sym_state_get_value(state, term.condition, &condition); if (status != XAIR_SYM_OK) goto fail;
            status = xair_sym_const(state->context, 1, 0, &zero); if (status != XAIR_SYM_OK) goto fail;
            status = xair_sym_binary(state->context, XAIR_OP_EQ, 1, condition, zero, &negated); if (status != XAIR_SYM_OK) goto fail;
            status = xair_sym_state_clone(state, &false_state); if (status != XAIR_SYM_OK) goto fail; state->context->stats.forks++;
            status = xair_sym_state_assume(state, condition); if (status == XAIR_SYM_OK) status = xair_sym_check(state, XAIR_SYM_INVALID_ID, &sat);
            if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); goto fail; }
            if (sat == XAIR_SYM_SAT) {
                status = transfer(state, term.true_target, term.true_args, term.true_arg_count);
                if (status == XAIR_SYM_OK) status = enqueue(&queue, &queued, &capacity, state);
                if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); goto fail; }
                state = NULL;
            } else {
                state->context->stats.states_pruned++;
                xair_sym_state_destroy(state);
                state = NULL;
            }
            status = xair_sym_state_assume(false_state, negated); if (status == XAIR_SYM_OK) status = xair_sym_check(false_state, XAIR_SYM_INVALID_ID, &sat);
            if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); false_state = NULL; goto fail; }
            if (sat == XAIR_SYM_SAT) {
                status = transfer(false_state, term.false_target, term.false_args, term.false_arg_count);
                if (status == XAIR_SYM_OK) status = enqueue(&queue, &queued, &capacity, false_state);
                if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); goto fail; }
                false_state = NULL;
            } else {
                false_state->context->stats.states_pruned++;
                xair_sym_state_destroy(false_state);
                false_state = NULL;
            }
            continue;
        }
        state->context->stats.states_completed++; if (callback != NULL) { status = callback(state, user); if (status != XAIR_SYM_OK) goto fail; }
        xair_sym_state_destroy(state);
        state = NULL;
    }
    for (cursor = 0; cursor < queued; ++cursor) xair_sym_state_destroy(queue[cursor]);
    free(queue);
    return XAIR_SYM_OK;
fail:
    xair_sym_state_destroy(state);
    for (cursor = 0; cursor < queued; ++cursor) xair_sym_state_destroy(queue[cursor]);
    free(queue);
    return status;
}
