#include "xair_sym_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t taint_hash(uint64_t hash, uint64_t value) {
    return (hash ^ value) * UINT64_C(1099511628211);
}

static int nullable_equal(const char *lhs, const char *rhs) {
    return strcmp(lhs == NULL ? "" : lhs, rhs == NULL ? "" : rhs) == 0;
}

static int details_equal(const xair_sym_taint_details *lhs, const xair_sym_taint_details *rhs) {
    return lhs->category == rhs->category && lhs->source_address == rhs->source_address &&
        lhs->call_site == rhs->call_site && lhs->sink_address == rhs->sink_address &&
        lhs->byte_offset == rhs->byte_offset && lhs->guard == rhs->guard &&
        lhs->byte_length == rhs->byte_length && lhs->confidence == rhs->confidence &&
        lhs->implicit == rhs->implicit && lhs->sanitizer_validated == rhs->sanitizer_validated &&
        nullable_equal(lhs->transform, rhs->transform) && nullable_equal(lhs->sink, rhs->sink);
}

static xair_sym_status reserve_taints(xair_sym_context *context) {
    size_t capacity;
    xair_sym_taint_node **nodes;
    if (context->taint_count < context->taint_capacity) return XAIR_SYM_OK;
    capacity = context->taint_capacity == 0 ? 16 : context->taint_capacity * 2;
    if (capacity < context->taint_capacity || capacity > SIZE_MAX / sizeof(*nodes))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (!xair_sym_parallel_memory_reserve(context,
        (capacity - context->taint_capacity) * sizeof(*nodes))) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    nodes = (xair_sym_taint_node **)realloc(context->taints, capacity * sizeof(*nodes));
    if (nodes == NULL) {
        xair_sym_parallel_memory_release(context,
            (capacity - context->taint_capacity) * sizeof(*nodes)); return XAIR_SYM_ERR_OOM;
    }
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
            candidate->name == NULL ? "" : candidate->name) == 0 &&
            details_equal(&node->details, &candidate->details)) {
            context->stats.taint_nodes_reused++;
            *out_taint = (xair_sym_taint_id)(i + 1);
            return XAIR_SYM_OK;
        }
    }
    status = reserve_taints(context);
    if (status != XAIR_SYM_OK) return status;
    if (context->taint_count >= UINT32_MAX - 1u) return XAIR_SYM_ERR_RANGE;
    {
        size_t allocation = sizeof(*node) + (candidate->name != NULL ? strlen(candidate->name) + 1u : 0u);
        if (!xair_sym_parallel_memory_reserve(context, allocation)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    node = (xair_sym_taint_node *)malloc(sizeof(*node));
    if (node == NULL) {
        xair_sym_parallel_memory_release(context, sizeof(*node) +
            (candidate->name != NULL ? strlen(candidate->name) + 1u : 0u)); return XAIR_SYM_ERR_OOM;
    }
    *node = *candidate;
    if (candidate->name != NULL) {
        size_t name_size = strlen(candidate->name) + 1u;
        node->name = (char *)malloc(name_size);
        if (node->name == NULL) {
            free(node); xair_sym_parallel_memory_release(context, sizeof(*node) + name_size);
            return XAIR_SYM_ERR_OOM;
        }
        memcpy(node->name, candidate->name, name_size);
        if (candidate->details.transform == candidate->name) node->details.transform = node->name;
        if (candidate->details.sink == candidate->name) node->details.sink = node->name;
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
    xair_sym_taint_details details;
    memset(&details, 0, sizeof(details));
    return xair_sym_taint_source_ex(context, name, &details, out_taint);
}

xair_sym_status xair_sym_taint_source_ex(
    xair_sym_context *context, const char *name,
    const xair_sym_taint_details *details, xair_sym_taint_id *out_taint) {
    xair_sym_taint_node node;
    const unsigned char *cursor;
    if (context == NULL || name == NULL || name[0] == '\0' || details == NULL || out_taint == NULL ||
        details->transform != NULL || details->sink != NULL ||
        (details->guard != 0 && details->guard != XAIR_SYM_INVALID_ID &&
         details->guard >= context->expression_count))
        return XAIR_SYM_ERR_BAD_ARG;
    memset(&node, 0, sizeof(node));
    node.kind = XAIR_SYM_TAINT_NODE_SOURCE;
    node.name = (char *)name;
    node.details = *details;
    node.hash = UINT64_C(1469598103934665603);
    cursor = (const unsigned char *)name;
    while (*cursor != 0) node.hash = taint_hash(node.hash, *cursor++);
    node.hash = taint_hash(node.hash, details->category);
    node.hash = taint_hash(node.hash, details->source_address);
    node.hash = taint_hash(node.hash, details->call_site);
    node.hash = taint_hash(node.hash, details->sink_address);
    node.hash = taint_hash(node.hash, details->byte_offset);
    node.hash = taint_hash(node.hash, details->byte_length);
    node.hash = taint_hash(node.hash, details->guard);
    node.hash = taint_hash(node.hash, details->implicit);
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
    return xair_sym_taint_sanitize_ex(context, input, sanitizer, 0, out_taint);
}

xair_sym_status xair_sym_taint_sanitize_ex(
    xair_sym_context *context,
    xair_sym_taint_id input,
    const char *sanitizer,
    int validated,
    xair_sym_taint_id *out_taint) {
    xair_sym_taint_node node;
    const unsigned char *cursor;
    if (context == NULL || input == XAIR_SYM_TAINT_NONE || input > context->taint_count ||
        sanitizer == NULL || sanitizer[0] == '\0' || out_taint == NULL) return XAIR_SYM_ERR_BAD_ARG;
    memset(&node, 0, sizeof(node));
    node.kind = XAIR_SYM_TAINT_NODE_SANITIZER;
    node.lhs = input;
    node.name = (char *)sanitizer;
    node.details = context->taints[input - 1]->details;
    node.details.sanitizer_validated = validated != 0;
    node.details.transform = sanitizer;
    node.hash = taint_hash(UINT64_C(1469598103934665603), input);
    cursor = (const unsigned char *)sanitizer;
    while (*cursor != 0) node.hash = taint_hash(node.hash, *cursor++);
    return intern_taint(context, &node, out_taint);
}

xair_sym_status xair_sym_taint_transform(xair_sym_context *context,
    xair_sym_taint_id input, const char *transform, xair_sym_expr_id guard,
    int implicit, xair_sym_taint_id *out_taint) {
    xair_sym_taint_node node;
    const unsigned char *cursor;
    if (context == NULL || input == XAIR_SYM_TAINT_NONE || input > context->taint_count ||
        transform == NULL || transform[0] == '\0' || out_taint == NULL ||
        (guard != XAIR_SYM_INVALID_ID &&
         (guard >= context->expression_count || context->expressions[guard]->bits != 1u))) return XAIR_SYM_ERR_BAD_ARG;
    memset(&node, 0, sizeof(node));
    node.kind = XAIR_SYM_TAINT_NODE_TRANSFORM;
    node.lhs = input;
    node.name = (char *)transform;
    node.details = context->taints[input - 1]->details;
    node.details.transform = transform;
    node.details.guard = guard;
    node.details.implicit = implicit != 0;
    node.hash = taint_hash(UINT64_C(1469598103934665603), input);
    node.hash = taint_hash(node.hash, guard);
    node.hash = taint_hash(node.hash, implicit != 0);
    cursor = (const unsigned char *)transform;
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

xair_sym_status xair_sym_taint_get_details(const xair_sym_context *context,
    xair_sym_taint_id taint, xair_sym_taint_details *out_details) {
    if (context == NULL || taint == XAIR_SYM_TAINT_NONE || taint > context->taint_count || out_details == NULL)
        return XAIR_SYM_ERR_BAD_ARG;
    *out_details = context->taints[taint - 1]->details;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_taint_sink(xair_sym_context *context, xair_sym_taint_id input,
    const char *sink, uint64_t address, xair_sym_taint_id *out_taint) {
    xair_sym_taint_node node;
    const unsigned char *cursor;
    if (context == NULL || input == XAIR_SYM_TAINT_NONE || input > context->taint_count ||
        sink == NULL || sink[0] == '\0' || out_taint == NULL) return XAIR_SYM_ERR_BAD_ARG;
    memset(&node, 0, sizeof(node));
    node.kind = XAIR_SYM_TAINT_NODE_SINK;
    node.lhs = input;
    node.name = (char *)sink;
    node.details = context->taints[input - 1]->details;
    node.details.sink = sink;
    node.details.sink_address = address;
    node.hash = taint_hash(UINT64_C(1469598103934665603), input);
    cursor = (const unsigned char *)sink;
    while (*cursor != 0) node.hash = taint_hash(node.hash, *cursor++);
    node.hash = taint_hash(node.hash, address);
    return intern_taint(context, &node, out_taint);
}

size_t xair_sym_taint_sink_count(const xair_sym_context *context) {
    size_t i, count = 0;
    if (context == NULL) return 0;
    for (i = 0; i < context->taint_count; ++i)
        if (context->taints[i]->kind == XAIR_SYM_TAINT_NODE_SINK) count++;
    return count;
}

xair_sym_status xair_sym_taint_sink_get(const xair_sym_context *context,
    size_t index, xair_sym_taint_id *out_taint) {
    size_t i;
    if (out_taint != NULL) *out_taint = XAIR_SYM_TAINT_NONE;
    if (context == NULL || out_taint == NULL) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < context->taint_count; ++i) {
        if (context->taints[i]->kind != XAIR_SYM_TAINT_NODE_SINK) continue;
        if (index-- == 0) { *out_taint = (xair_sym_taint_id)(i + 1u); return XAIR_SYM_OK; }
    }
    return XAIR_SYM_ERR_RANGE;
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
    if (result != XAIR_SYM_TAINT_NONE) {
        xair_sym_taint_id transformed;
        xair_sym_status status = xair_sym_taint_transform(state->context, result,
            xair_opcode_name(op->opcode), XAIR_SYM_INVALID_ID, 0, &transformed);
        if (status != XAIR_SYM_OK) return status;
        result = transformed;
    }
    *out_taint = result;
    return XAIR_SYM_OK;
}
