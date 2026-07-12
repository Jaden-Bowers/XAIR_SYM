#include "xair_sym_internal.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static uint64_t mix(uint64_t hash, uint64_t value) {
    hash ^= value + UINT64_C(0x9e3779b97f4a7c15) + (hash << 6u) + (hash >> 2u);
    return hash;
}

static void *arena_allocate(xair_sym_context *context, size_t size) {
    xair_sym_arena_chunk *chunk = context->arena;
    size_t aligned = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
    if (chunk == NULL || aligned > chunk->capacity - chunk->used) {
        size_t capacity = aligned > 65536 ? aligned : 65536;
        chunk = (xair_sym_arena_chunk *)malloc(sizeof(*chunk) + capacity);
        if (chunk == NULL) return NULL;
        chunk->next = context->arena; chunk->used = 0; chunk->capacity = capacity; context->arena = chunk;
    }
    {
        void *result = chunk->data + chunk->used;
        chunk->used += aligned;
        return result;
    }
}

static uint64_t expr_hash(const xair_sym_expr *expr) {
    uint64_t hash = UINT64_C(0x5841495253594d31);
    size_t i;
    const unsigned char *text = (const unsigned char *)expr->symbol;

    hash = mix(hash, (uint64_t)expr->kind);
    hash = mix(hash, (uint64_t)expr->opcode);
    hash = mix(hash, expr->bits);
    hash = mix(hash, expr->arg_count);
    hash = mix(hash, expr->immediate);
    for (i = 0; i < expr->arg_count; ++i) {
        hash = mix(hash, expr->args[i]);
    }
    while (*text != 0) {
        hash = mix(hash, *text++);
    }
    return hash == 0 ? 1 : hash;
}

static int expr_equal(const xair_sym_expr *lhs, const xair_sym_expr *rhs) {
    return lhs->kind == rhs->kind && lhs->opcode == rhs->opcode &&
        lhs->bits == rhs->bits && lhs->arg_count == rhs->arg_count &&
        lhs->immediate == rhs->immediate &&
        memcmp(lhs->args, rhs->args, sizeof(lhs->args)) == 0 &&
        strcmp(lhs->symbol, rhs->symbol) == 0;
}

static xair_sym_status reserve(void **data, size_t element, size_t *capacity, size_t needed) {
    size_t next = *capacity == 0 ? 16 : *capacity;
    void *allocation;

    if (needed <= *capacity) {
        return XAIR_SYM_OK;
    }
    while (next < needed) {
        if (next > SIZE_MAX / 2) {
            return XAIR_SYM_ERR_OOM;
        }
        next *= 2;
    }
    if (element != 0 && next > SIZE_MAX / element) {
        return XAIR_SYM_ERR_OOM;
    }
    allocation = realloc(*data, next * element);
    if (allocation == NULL) {
        return XAIR_SYM_ERR_OOM;
    }
    *data = allocation;
    *capacity = next;
    return XAIR_SYM_OK;
}

static xair_sym_status rebuild_hash(xair_sym_context *context, size_t capacity) {
    xair_sym_hash_entry *table;
    size_t i;

    table = (xair_sym_hash_entry *)calloc(capacity, sizeof(*table));
    if (table == NULL) {
        return XAIR_SYM_ERR_OOM;
    }
    for (i = 0; i < context->expression_count; ++i) {
        size_t slot = (size_t)(context->expressions[i]->hash & (capacity - 1));
        while (table[slot].used) {
            slot = (slot + 1) & (capacity - 1);
        }
        table[slot].used = 1;
        table[slot].hash = context->expressions[i]->hash;
        table[slot].expr = (xair_sym_expr_id)i;
    }
    free(context->hash);
    context->hash = table;
    context->hash_capacity = capacity;
    context->hash_count = context->expression_count;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_intern(xair_sym_context *context, const xair_sym_expr *key, xair_sym_expr_id *out_expr) {
    xair_sym_expr candidate;
    size_t slot;
    xair_sym_status status;

    if (context == NULL || key == NULL || out_expr == NULL || key->bits == 0 || key->bits > 128) {
        return XAIR_SYM_ERR_BAD_ARG;
    }
    candidate = *key;
    candidate.hash = expr_hash(&candidate);
    candidate.dependencies = 0;
    if (candidate.kind == XAIR_SYM_EXPR_SYMBOL) {
        candidate.dependencies = UINT64_C(1) << (candidate.hash & 63u);
    } else if (candidate.kind == XAIR_SYM_EXPR_XAIR) {
        size_t dependency_i;
        for (dependency_i = 0; dependency_i < candidate.arg_count; ++dependency_i) {
            candidate.dependencies |= context->expressions[candidate.args[dependency_i]]->dependencies;
        }
    }
    if (context->hash_capacity == 0 || (context->hash_count + 1) * 10 >= context->hash_capacity * 7) {
        size_t next = context->hash_capacity == 0 ? 32 : context->hash_capacity * 2;
        status = rebuild_hash(context, next);
        if (status != XAIR_SYM_OK) {
            return status;
        }
    }
    slot = (size_t)(candidate.hash & (context->hash_capacity - 1));
    while (context->hash[slot].used) {
        xair_sym_expr_id existing = context->hash[slot].expr;
        if (context->hash[slot].hash == candidate.hash && expr_equal(context->expressions[existing], &candidate)) {
            context->stats.expressions_reused++;
            *out_expr = existing;
            return XAIR_SYM_OK;
        }
        context->stats.hash_collisions++;
        slot = (slot + 1) & (context->hash_capacity - 1);
    }
    status = reserve((void **)&context->expressions, sizeof(*context->expressions),
        &context->expression_capacity, context->expression_count + 1);
    if (status != XAIR_SYM_OK) {
        return status;
    }
    if (context->expression_count >= UINT32_MAX) {
        return XAIR_SYM_ERR_RANGE;
    }
    *out_expr = (xair_sym_expr_id)context->expression_count;
    context->expressions[context->expression_count] = (xair_sym_expr *)arena_allocate(context, sizeof(candidate));
    if (context->expressions[context->expression_count] == NULL) return XAIR_SYM_ERR_OOM;
    *context->expressions[context->expression_count++] = candidate;
    context->hash[slot].used = 1;
    context->hash[slot].hash = candidate.hash;
    context->hash[slot].expr = *out_expr;
    context->hash_count++;
    context->stats.expressions = context->expression_count;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_context_create(xair_sym_context **out_context) {
    xair_sym_context *context;
    if (out_context == NULL) {
        return XAIR_SYM_ERR_BAD_ARG;
    }
    context = (xair_sym_context *)calloc(1, sizeof(*context));
    if (context == NULL) {
        return XAIR_SYM_ERR_OOM;
    }
    *out_context = context;
    return XAIR_SYM_OK;
}

void xair_sym_context_destroy(xair_sym_context *context) {
    if (context != NULL) {
        xair_sym_arena_chunk *chunk = context->arena;
        size_t taint_i;
        while (chunk != NULL) { xair_sym_arena_chunk *next = chunk->next; free(chunk); chunk = next; }
        for (taint_i = 0; taint_i < context->taint_count; ++taint_i) free(context->taints[taint_i]);
        free(context->taints);
        free(context->query_cache);
        free(context->model_cache);
        free(context->hash);
        free(context->expressions);
        free(context);
    }
}

void xair_sym_context_stats(const xair_sym_context *context, xair_sym_stats *out_stats) {
    if (context != NULL && out_stats != NULL) {
        *out_stats = context->stats;
    }
}

static uint64_t mask_bits(uint16_t bits) {
    return bits >= 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
}

xair_sym_status xair_sym_const(xair_sym_context *context, uint16_t bits, uint64_t value, xair_sym_expr_id *out_expr) {
    xair_sym_expr expr;
    memset(&expr, 0, sizeof(expr));
    expr.kind = XAIR_SYM_EXPR_CONST;
    expr.bits = bits;
    expr.immediate = value & mask_bits(bits);
    return xair_sym_intern(context, &expr, out_expr);
}

xair_sym_status xair_sym_symbol(xair_sym_context *context, uint16_t bits, const char *name, xair_sym_expr_id *out_expr) {
    xair_sym_expr expr;
    if (name == NULL || name[0] == '\0') {
        return XAIR_SYM_ERR_BAD_ARG;
    }
    memset(&expr, 0, sizeof(expr));
    expr.kind = XAIR_SYM_EXPR_SYMBOL;
    expr.bits = bits;
    (void)snprintf(expr.symbol, sizeof(expr.symbol), "%s", name);
    return xair_sym_intern(context, &expr, out_expr);
}

xair_sym_status xair_sym_unary(xair_sym_context *context, xair_opcode opcode, uint16_t bits,
    xair_sym_expr_id src, uint64_t immediate, xair_sym_expr_id *out_expr) {
    xair_sym_expr expr;
    if (context == NULL || src >= context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    if (context->expressions[src]->kind == XAIR_SYM_EXPR_CONST) {
        uint64_t value = context->expressions[src]->immediate;
        if (opcode == XAIR_OP_TRUNC || opcode == XAIR_OP_ZEXT || opcode == XAIR_OP_INT_TO_ADDR ||
            opcode == XAIR_OP_ADDR_TO_INT) return xair_sym_const(context, bits, value, out_expr);
        if (opcode == XAIR_OP_SEXT && context->expressions[src]->bits <= 64) {
            uint16_t source_bits = context->expressions[src]->bits;
            uint64_t sign = UINT64_C(1) << (source_bits - 1);
            if ((value & sign) != 0) value |= ~mask_bits(source_bits);
            return xair_sym_const(context, bits, value, out_expr);
        }
        if (opcode == XAIR_OP_EXTRACT && immediate < 64) return xair_sym_const(context, bits, value >> immediate, out_expr);
    }
    memset(&expr, 0, sizeof(expr)); expr.kind = XAIR_SYM_EXPR_XAIR; expr.opcode = opcode;
    expr.bits = bits; expr.arg_count = 1; expr.args[0] = src; expr.immediate = immediate;
    return xair_sym_intern(context, &expr, out_expr);
}

xair_sym_status xair_sym_binary(xair_sym_context *context, xair_opcode opcode, uint16_t bits,
    xair_sym_expr_id lhs, xair_sym_expr_id rhs, xair_sym_expr_id *out_expr) {
    xair_sym_expr expr;
    if (context == NULL || lhs >= context->expression_count || rhs >= context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    if ((opcode == XAIR_OP_ADD || opcode == XAIR_OP_MUL || opcode == XAIR_OP_AND || opcode == XAIR_OP_OR ||
        opcode == XAIR_OP_XOR || opcode == XAIR_OP_EQ || opcode == XAIR_OP_NE) && lhs > rhs) {
        xair_sym_expr_id temporary = lhs; lhs = rhs; rhs = temporary;
    }
    if (context->expressions[rhs]->kind == XAIR_SYM_EXPR_CONST && context->expressions[rhs]->immediate == 0) {
        if (opcode == XAIR_OP_ADD || opcode == XAIR_OP_SUB || opcode == XAIR_OP_OR || opcode == XAIR_OP_XOR ||
            opcode == XAIR_OP_SHL || opcode == XAIR_OP_LSHR || opcode == XAIR_OP_ASHR ||
            opcode == XAIR_OP_ROL || opcode == XAIR_OP_ROR) {
            *out_expr = lhs;
            context->stats.expressions_reused++;
            return XAIR_SYM_OK;
        }
    }
    if (context->expressions[lhs]->kind == XAIR_SYM_EXPR_CONST && context->expressions[rhs]->kind == XAIR_SYM_EXPR_CONST && bits <= 64) {
        uint64_t left = context->expressions[lhs]->immediate;
        uint64_t right = context->expressions[rhs]->immediate;
        uint64_t value;
        switch (opcode) {
        case XAIR_OP_ADD: value = left + right; break;
        case XAIR_OP_SUB: value = left - right; break;
        case XAIR_OP_MUL: value = left * right; break;
        case XAIR_OP_AND: value = left & right; break;
        case XAIR_OP_OR: value = left | right; break;
        case XAIR_OP_XOR: value = left ^ right; break;
        case XAIR_OP_SHL: value = right >= bits ? 0 : left << right; break;
        case XAIR_OP_LSHR: value = right >= bits ? 0 : left >> right; break;
        case XAIR_OP_EQ: value = left == right ? 1 : 0; break;
        case XAIR_OP_NE: value = left != right ? 1 : 0; break;
        case XAIR_OP_ULT: value = left < right ? 1 : 0; break;
        case XAIR_OP_ULE: value = left <= right ? 1 : 0; break;
        default: goto not_folded;
        }
        return xair_sym_const(context, bits, value, out_expr);
    }
not_folded:
    memset(&expr, 0, sizeof(expr)); expr.kind = XAIR_SYM_EXPR_XAIR; expr.opcode = opcode;
    expr.bits = bits; expr.arg_count = 2; expr.args[0] = lhs; expr.args[1] = rhs;
    return xair_sym_intern(context, &expr, out_expr);
}

xair_sym_status xair_sym_select(xair_sym_context *context, xair_sym_expr_id condition,
    xair_sym_expr_id true_value, xair_sym_expr_id false_value, xair_sym_expr_id *out_expr) {
    xair_sym_expr expr;
    if (context == NULL || condition >= context->expression_count || true_value >= context->expression_count ||
        false_value >= context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    if (context->expressions[condition]->bits != 1 ||
        context->expressions[true_value]->bits != context->expressions[false_value]->bits) return XAIR_SYM_ERR_BAD_ARG;
    if (true_value == false_value) { *out_expr = true_value; context->stats.expressions_reused++; return XAIR_SYM_OK; }
    if (context->expressions[condition]->kind == XAIR_SYM_EXPR_CONST) {
        *out_expr = context->expressions[condition]->immediate != 0 ? true_value : false_value;
        context->stats.expressions_reused++;
        return XAIR_SYM_OK;
    }
    memset(&expr, 0, sizeof(expr)); expr.kind = XAIR_SYM_EXPR_XAIR; expr.opcode = XAIR_OP_SELECT;
    expr.bits = context->expressions[true_value]->bits; expr.arg_count = 3;
    expr.args[0] = condition; expr.args[1] = true_value; expr.args[2] = false_value;
    return xair_sym_intern(context, &expr, out_expr);
}

xair_sym_status xair_sym_expr_get(const xair_sym_context *context, xair_sym_expr_id id, xair_sym_expr_view *out) {
    const xair_sym_expr *expr;
    if (context == NULL || out == NULL || id >= context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    expr = context->expressions[id]; memset(out, 0, sizeof(*out)); out->kind = expr->kind;
    out->opcode = expr->opcode; out->bits = expr->bits; out->arg_count = expr->arg_count;
    memcpy(out->args, expr->args, sizeof(out->args)); out->immediate = expr->immediate;
    out->symbol = expr->kind == XAIR_SYM_EXPR_SYMBOL ? expr->symbol : NULL; return XAIR_SYM_OK;
}

const char *xair_sym_status_name(xair_sym_status status) {
    static const char *names[] = {"ok", "out of memory", "bad argument", "range error", "unsupported", "solver error", "infeasible"};
    return (unsigned)status < sizeof(names) / sizeof(names[0]) ? names[status] : "unknown";
}
