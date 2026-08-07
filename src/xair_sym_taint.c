#include "xair_sym_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t taint_hash(uint64_t hash, uint64_t value) {
    return (hash ^ value) * UINT64_C(1099511628211);
}

static xair_sym_status reserve_taints(xair_sym_context *context) {
    size_t capacity;
    xair_sym_taint_node **nodes;
    if (context->taint_count < context->taint_capacity) return XAIR_SYM_OK;
    capacity = context->taint_capacity == 0 ? 16 : context->taint_capacity * 2;
    nodes = (xair_sym_taint_node **)realloc(context->taints, capacity * sizeof(*nodes));
    if (nodes == NULL) return XAIR_SYM_ERR_OOM;
    context->taints = nodes;
    context->taint_capacity = capacity;
    return XAIR_SYM_OK;
}

static xair_sym_status intern_taint(
    xair_sym_context *context,
    const xair_sym_taint_node *candidate,
    xair_sym_taint_id *out_taint) {
    size_t i;
    xair_sym_status status;
    xair_sym_taint_node *node;

    for (i = 0; i < context->taint_count; ++i) {
        node = context->taints[i];
        if (node->hash == candidate->hash && node->kind == candidate->kind &&
            node->lhs == candidate->lhs && node->rhs == candidate->rhs &&
            strcmp(node->name == NULL ? "" : node->name,
                candidate->name == NULL ? "" : candidate->name) == 0) {
            context->stats.taint_nodes_reused++;
            *out_taint = (xair_sym_taint_id)(i + 1);
            return XAIR_SYM_OK;
        }
    }
    status = reserve_taints(context);
    if (status != XAIR_SYM_OK) return status;
    if (context->taint_count >= UINT32_MAX - 1u) return XAIR_SYM_ERR_RANGE;
    node = (xair_sym_taint_node *)malloc(sizeof(*node));
    if (node == NULL) return XAIR_SYM_ERR_OOM;
    *node = *candidate;
    if (candidate->name != NULL) {
        size_t name_size = strlen(candidate->name) + 1u;
        node->name = (char *)malloc(name_size);
        if (node->name == NULL) { free(node); return XAIR_SYM_ERR_OOM; }
        memcpy(node->name, candidate->name, name_size);
    }
    context->taints[context->taint_count++] = node;
    context->stats.taint_nodes = context->taint_count;
    *out_taint = (xair_sym_taint_id)context->taint_count;
    return XAIR_SYM_OK;
}

void xair_sym_context_set_taint_mode(xair_sym_context *context, xair_sym_taint_mode mode) {
    if (context != NULL && mode <= XAIR_SYM_TAINT_STRICT_IMPLICIT) context->taint_mode = mode;
}

xair_sym_status xair_sym_taint_source(
    xair_sym_context *context,
    const char *name,
    xair_sym_taint_id *out_taint) {
    xair_sym_taint_node node;
    const unsigned char *cursor;
    if (context == NULL || name == NULL || name[0] == '\0' || out_taint == NULL) return XAIR_SYM_ERR_BAD_ARG;
    memset(&node, 0, sizeof(node));
    node.kind = XAIR_SYM_TAINT_NODE_SOURCE;
    node.name = (char *)name;
    node.hash = UINT64_C(1469598103934665603);
    cursor = (const unsigned char *)name;
    while (*cursor != 0) node.hash = taint_hash(node.hash, *cursor++);
    return intern_taint(context, &node, out_taint);
}

xair_sym_status xair_sym_taint_union(
    xair_sym_context *context,
    xair_sym_taint_id lhs,
    xair_sym_taint_id rhs,
    xair_sym_taint_id *out_taint) {
    xair_sym_taint_node node;
    if (context == NULL || out_taint == NULL || lhs > context->taint_count || rhs > context->taint_count) return XAIR_SYM_ERR_BAD_ARG;
    if (lhs == XAIR_SYM_TAINT_NONE) { *out_taint = rhs; return XAIR_SYM_OK; }
    if (rhs == XAIR_SYM_TAINT_NONE || lhs == rhs) { *out_taint = lhs; return XAIR_SYM_OK; }
    if (lhs > rhs) { xair_sym_taint_id temporary = lhs; lhs = rhs; rhs = temporary; }
    memset(&node, 0, sizeof(node));
    node.kind = XAIR_SYM_TAINT_NODE_UNION;
    node.lhs = lhs;
    node.rhs = rhs;
    node.hash = taint_hash(taint_hash(UINT64_C(1469598103934665603), lhs), rhs);
    return intern_taint(context, &node, out_taint);
}

xair_sym_status xair_sym_taint_sanitize(
    xair_sym_context *context,
    xair_sym_taint_id input,
    const char *sanitizer,
    xair_sym_taint_id *out_taint) {
    xair_sym_taint_node node;
    const unsigned char *cursor;
    if (context == NULL || input == XAIR_SYM_TAINT_NONE || input > context->taint_count ||
        sanitizer == NULL || sanitizer[0] == '\0' || out_taint == NULL) return XAIR_SYM_ERR_BAD_ARG;
    memset(&node, 0, sizeof(node));
    node.kind = XAIR_SYM_TAINT_NODE_SANITIZER;
    node.lhs = input;
    node.name = (char *)sanitizer;
    node.hash = taint_hash(UINT64_C(1469598103934665603), input);
    cursor = (const unsigned char *)sanitizer;
    while (*cursor != 0) node.hash = taint_hash(node.hash, *cursor++);
    return intern_taint(context, &node, out_taint);
}

xair_sym_status xair_sym_taint_get(
    const xair_sym_context *context,
    xair_sym_taint_id taint,
    xair_sym_taint_view *out_view) {
    const xair_sym_taint_node *node;
    if (context == NULL || taint == XAIR_SYM_TAINT_NONE || taint > context->taint_count || out_view == NULL) {
        return XAIR_SYM_ERR_BAD_ARG;
    }
    node = context->taints[taint - 1];
    out_view->kind = node->kind;
    out_view->lhs = node->lhs;
    out_view->rhs = node->rhs;
    out_view->name = node->name == NULL || node->name[0] == '\0' ? NULL : node->name;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_state_set_taint(
    xair_sym_state *state,
    xair_value_id value,
    xair_sym_taint_id taint) {
    if (state == NULL || value >= state->value_count || taint > state->context->taint_count) return XAIR_SYM_ERR_BAD_ARG;
    state->value_taints[value] = taint;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_state_get_taint(
    const xair_sym_state *state,
    xair_value_id value,
    xair_sym_taint_id *out_taint) {
    if (state == NULL || out_taint == NULL || value >= state->value_count) return XAIR_SYM_ERR_BAD_ARG;
    *out_taint = state->value_taints[value];
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_taint_operands(
    xair_sym_state *state,
    const xair_op_view *op,
    xair_sym_taint_id *out_taint) {
    xair_sym_taint_id result = XAIR_SYM_TAINT_NONE;
    size_t i;
    if (state == NULL || op == NULL || out_taint == NULL) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < op->src_count; ++i) {
        xair_sym_taint_id source = state->value_taints[op->src[i]];
        xair_sym_status status;
        if (op->opcode == XAIR_OP_SELECT && i == 0 && state->context->taint_mode == XAIR_SYM_TAINT_EXPLICIT) continue;
        status = xair_sym_taint_union(state->context, result, source, &result);
        if (status != XAIR_SYM_OK) return status;
    }
    *out_taint = result;
    return XAIR_SYM_OK;
}
