#include "xair_sym_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#define SNAPSHOT_SCHEMA 3u
#define SNAPSHOT_MAX_FILE ((size_t)512u * 1024u * 1024u)
#define SNAPSHOT_DEFAULT_LOAD_BUDGET ((size_t)128u * 1024u * 1024u)
#define SNAPSHOT_MAX_OBJECTS ((uint64_t)1048576u)
#define SNAPSHOT_MAX_CONSTRAINTS ((uint64_t)1048576u)

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} snapshot_blob;

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} snapshot_reader;

typedef struct {
    size_t used;
    size_t limit;
} snapshot_budget;

typedef struct {
    xair_sym_expr_id expression;
    uint64_t identity;
} snapshot_constraint_record;

static uint64_t snapshot_hash(const uint8_t *data, size_t size) {
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < size; ++i) hash = (hash ^ data[i]) * UINT64_C(1099511628211);
    return hash;
}

static int budget_charge(snapshot_budget *budget, size_t amount) {
    if (amount > budget->limit || budget->used > budget->limit - amount) return 0;
    budget->used += amount;
    return 1;
}

static size_t context_allocation_estimate(const xair_sym_context *context) {
    size_t total = context->arena_capacity_bytes + context->object_bytes;
    size_t amount;
#define ADD_CONTEXT_ALLOCATION(count, type) \
    do { \
        if ((count) > (SIZE_MAX - total) / sizeof(type)) return SIZE_MAX; \
        amount = (count) * sizeof(type); total += amount; \
    } while (0)
    ADD_CONTEXT_ALLOCATION(context->expression_capacity, xair_sym_expr *);
    ADD_CONTEXT_ALLOCATION(context->hash_capacity, xair_sym_hash_entry);
    ADD_CONTEXT_ALLOCATION(context->taint_capacity, xair_sym_taint_node *);
    ADD_CONTEXT_ALLOCATION(context->query_cache_capacity, xair_sym_query_cache_entry);
    ADD_CONTEXT_ALLOCATION(context->model_cache_capacity, xair_sym_model_cache_entry);
#undef ADD_CONTEXT_ALLOCATION
    return total;
}

static int budget_init(snapshot_budget *budget, const xair_sym_context *context) {
    size_t existing = 0;
    budget->limit = context->analysis.max_memory != 0 ?
        context->analysis.max_memory : SNAPSHOT_DEFAULT_LOAD_BUDGET;
    if (context->analysis.max_memory != 0) existing = context_allocation_estimate(context);
    budget->used = existing;
    return existing <= budget->limit;
}

static int blob_reserve(snapshot_blob *blob, size_t additional) {
    size_t needed, capacity;
    uint8_t *data;
    if (additional > SIZE_MAX - blob->size) return 0;
    needed = blob->size + additional;
    if (needed > SNAPSHOT_MAX_FILE) return 0;
    if (needed <= blob->capacity) return 1;
    capacity = blob->capacity == 0 ? 1024 : blob->capacity;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2) { capacity = needed; break; }
        capacity *= 2;
    }
    data = (uint8_t *)realloc(blob->data, capacity);
    if (data == NULL) return 0;
    blob->data = data; blob->capacity = capacity;
    return 1;
}

static int blob_bytes(snapshot_blob *blob, const void *data, size_t size) {
    if (size == 0) return 1;
    if (!blob_reserve(blob, size)) return 0;
    memcpy(blob->data + blob->size, data, size); blob->size += size; return 1;
}

static int blob_u8(snapshot_blob *blob, uint8_t value) { return blob_bytes(blob, &value, 1); }
static int blob_u32(snapshot_blob *blob, uint32_t value) {
    uint8_t bytes[4]; unsigned i;
    for (i = 0; i < 4; ++i) bytes[i] = (uint8_t)(value >> (i * 8u));
    return blob_bytes(blob, bytes, sizeof(bytes));
}
static int blob_u64(snapshot_blob *blob, uint64_t value) {
    uint8_t bytes[8]; unsigned i;
    for (i = 0; i < 8; ++i) bytes[i] = (uint8_t)(value >> (i * 8u));
    return blob_bytes(blob, bytes, sizeof(bytes));
}

static int blob_string(snapshot_blob *blob, const char *value) {
    size_t size;
    if (value == NULL) return blob_u32(blob, 0);
    size = strlen(value) + 1u;
    if (size > UINT32_MAX) return 0;
    return blob_u32(blob, (uint32_t)size) && blob_bytes(blob, value, size);
}

static int read_bytes(snapshot_reader *reader, void *out, size_t size) {
    if (size > reader->size - reader->offset) return 0;
    memcpy(out, reader->data + reader->offset, size); reader->offset += size; return 1;
}
static int read_u8(snapshot_reader *reader, uint8_t *out) { return read_bytes(reader, out, 1); }
static int read_u32(snapshot_reader *reader, uint32_t *out) {
    uint8_t bytes[4]; unsigned i; uint32_t value = 0;
    if (!read_bytes(reader, bytes, sizeof(bytes))) return 0;
    for (i = 0; i < 4; ++i) value |= (uint32_t)bytes[i] << (i * 8u);
    *out = value; return 1;
}
static int read_u64(snapshot_reader *reader, uint64_t *out) {
    uint8_t bytes[8]; unsigned i; uint64_t value = 0;
    if (!read_bytes(reader, bytes, sizeof(bytes))) return 0;
    for (i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (i * 8u);
    *out = value; return 1;
}

static int read_string(snapshot_reader *reader, const char **out, size_t *out_size) {
    uint32_t size;
    const uint8_t *value;
    if (!read_u32(reader, &size)) return 0;
    if (size == 0) {
        *out = NULL;
        if (out_size != NULL) *out_size = 0;
        return 1;
    }
    if ((size_t)size > reader->size - reader->offset) return 0;
    value = reader->data + reader->offset;
    if (value[size - 1u] != 0 || memchr(value, 0, size - 1u) != NULL) return 0;
    reader->offset += size;
    *out = (const char *)value;
    if (out_size != NULL) *out_size = size;
    return 1;
}

static int nullable_string_equal(const char *lhs, const char *rhs) {
    return strcmp(lhs == NULL ? "" : lhs, rhs == NULL ? "" : rhs) == 0;
}

static int snapshot_taint_details_equal(const xair_sym_taint_details *lhs,
    const xair_sym_taint_details *rhs) {
    return lhs->category == rhs->category && lhs->source_address == rhs->source_address &&
        lhs->call_site == rhs->call_site && lhs->sink_address == rhs->sink_address &&
        lhs->byte_offset == rhs->byte_offset && lhs->byte_length == rhs->byte_length &&
        lhs->guard == rhs->guard && lhs->confidence == rhs->confidence &&
        lhs->implicit == rhs->implicit && lhs->sanitizer_validated == rhs->sanitizer_validated &&
        nullable_string_equal(lhs->transform, rhs->transform) &&
        nullable_string_equal(lhs->sink, rhs->sink);
}

static int budget_charge_array(snapshot_budget *budget, uint64_t count, size_t element) {
    if (count > SIZE_MAX || (element != 0 && (size_t)count > SIZE_MAX / element)) return 0;
    return budget_charge(budget, (size_t)count * element);
}

static uint64_t snapshot_mask_bits(uint16_t bits) {
    return bits >= 64u ? UINT64_MAX : (UINT64_C(1) << bits) - 1u;
}

static int snapshot_expression_shape_valid(const xair_sym_context *context,
    const xair_sym_expr *expression) {
    uint16_t lhs_bits, rhs_bits;
    if (expression->kind == XAIR_SYM_EXPR_CONST) {
        return expression->arg_count == 0u && expression->symbol == NULL &&
            expression->immediate == (expression->immediate & snapshot_mask_bits(expression->bits)) &&
            (expression->bits <= 64u ? expression->immediate_hi == 0u :
             expression->immediate_hi ==
                (expression->immediate_hi & snapshot_mask_bits((uint16_t)(expression->bits - 64u))));
    }
    if (expression->kind == XAIR_SYM_EXPR_SYMBOL)
        return expression->arg_count == 0u && expression->symbol != NULL &&
            expression->immediate == 0u && expression->immediate_hi == 0u;
    if (expression->symbol != NULL || expression->immediate_hi != 0u) return 0;
    if (expression->arg_count == 1u) {
        uint16_t source_bits = context->expressions[expression->args[0]]->bits;
        switch (expression->opcode) {
        case XAIR_OP_ZEXT: case XAIR_OP_SEXT:
            return expression->immediate == 0u && expression->bits > source_bits;
        case XAIR_OP_TRUNC:
            return expression->immediate == 0u && expression->bits < source_bits;
        case XAIR_OP_EXTRACT:
            return expression->immediate < source_bits &&
                expression->bits <= source_bits - (uint16_t)expression->immediate;
        case XAIR_OP_INT_TO_ADDR: case XAIR_OP_ADDR_TO_INT:
            return expression->immediate == 0u && expression->bits == source_bits;
        case XAIR_OP_FLAGS_LOGIC:
            return expression->immediate == 0u && expression->bits == 6u;
        case XAIR_OP_FLAG_ZF: case XAIR_OP_FLAG_CF: case XAIR_OP_FLAG_OF:
        case XAIR_OP_FLAG_SF: case XAIR_OP_FLAG_PF: case XAIR_OP_FLAG_AF:
            return expression->immediate == 0u && expression->bits == 1u && source_bits == 6u &&
                context->expressions[expression->args[0]]->flags_pack;
        default:
            return 0;
        }
    }
    if (expression->arg_count == 2u) {
        lhs_bits = context->expressions[expression->args[0]]->bits;
        rhs_bits = context->expressions[expression->args[1]]->bits;
        if (expression->immediate != 0u) return 0;
        switch (expression->opcode) {
        case XAIR_OP_ADD: case XAIR_OP_SUB: case XAIR_OP_MUL:
        case XAIR_OP_UDIV: case XAIR_OP_SDIV: case XAIR_OP_UREM: case XAIR_OP_SREM:
        case XAIR_OP_AND: case XAIR_OP_OR: case XAIR_OP_XOR:
        case XAIR_OP_SHL: case XAIR_OP_LSHR: case XAIR_OP_ASHR:
        case XAIR_OP_ROL: case XAIR_OP_ROR: case XAIR_OP_ADDR_ADD: case XAIR_OP_ADDR_SUB:
            return lhs_bits == rhs_bits && expression->bits == lhs_bits;
        case XAIR_OP_EQ: case XAIR_OP_NE: case XAIR_OP_ULT: case XAIR_OP_ULE:
        case XAIR_OP_SLT: case XAIR_OP_SLE:
            return lhs_bits == rhs_bits && expression->bits == 1u;
        case XAIR_OP_CONCAT:
            return (uint32_t)lhs_bits + rhs_bits <= 128u &&
                expression->bits == (uint16_t)(lhs_bits + rhs_bits);
        case XAIR_OP_FLAGS_ADD: case XAIR_OP_FLAGS_SUB: case XAIR_OP_FLAGS_SHL:
            return lhs_bits == rhs_bits && expression->bits == 6u;
        default:
            return 0;
        }
    }
    if (expression->arg_count == 3u && expression->opcode == XAIR_OP_SELECT &&
        expression->immediate == 0u) {
        return context->expressions[expression->args[0]]->bits == 1u &&
            context->expressions[expression->args[1]]->bits ==
                context->expressions[expression->args[2]]->bits &&
            expression->bits == context->expressions[expression->args[1]]->bits;
    }
    return 0;
}

static xair_sym_status load_expression_dag(snapshot_reader *reader, xair_sym_context *context,
    snapshot_budget *budget, xair_sym_expr_id **out_map, size_t *out_count) {
    xair_sym_expr_id *map = NULL;
    uint64_t count;
    size_t i;
    if (!read_u64(reader, &count) || count >= UINT32_MAX ||
        count > (reader->size - reader->offset) / 42u) return XAIR_SYM_ERR_BAD_ARG;
    if (!budget_charge_array(budget, count, sizeof(*map) + sizeof(xair_sym_expr) +
        sizeof(xair_sym_arena_chunk) * 2u +
        sizeof(xair_sym_expr *) * 2u + sizeof(xair_sym_hash_entry) * 4u))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (count != 0 && (!budget_charge_array(budget, 16u, sizeof(xair_sym_expr *)) ||
        !budget_charge_array(budget, 32u, sizeof(xair_sym_hash_entry))))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (count != 0) {
        map = (xair_sym_expr_id *)malloc((size_t)count * sizeof(*map));
        if (map == NULL) return XAIR_SYM_ERR_OOM;
    }
    for (i = 0; i < (size_t)count; ++i) {
        xair_sym_expr candidate;
        const char *symbol;
        size_t symbol_size;
        uint8_t kind, arg_count, flags_pack;
        uint32_t opcode, bits, args[3];
        xair_sym_status status;
        size_t arg_i;
        memset(&candidate, 0, sizeof(candidate));
        if (!read_u8(reader, &kind) || !read_u32(reader, &opcode) || !read_u32(reader, &bits) ||
            !read_u8(reader, &arg_count) || !read_u8(reader, &flags_pack) ||
            !read_u32(reader, &args[0]) ||
            !read_u32(reader, &args[1]) || !read_u32(reader, &args[2]) ||
            !read_u64(reader, &candidate.immediate) || !read_u64(reader, &candidate.immediate_hi) ||
            !read_string(reader, &symbol, &symbol_size) || kind > XAIR_SYM_EXPR_XAIR ||
            bits == 0 || bits > 128u || arg_count > 3u || flags_pack > 1u ||
            (kind == XAIR_SYM_EXPR_XAIR && opcode > XAIR_OP_MEMORY_BARRIER) ||
            (kind != XAIR_SYM_EXPR_XAIR && arg_count != 0u) ||
            (kind == XAIR_SYM_EXPR_SYMBOL && (symbol == NULL || symbol[0] == '\0')) ||
            (kind != XAIR_SYM_EXPR_SYMBOL && symbol != NULL)) {
            free(map); return XAIR_SYM_ERR_BAD_ARG;
        }
        if (!budget_charge(budget, symbol_size)) { free(map); return XAIR_SYM_ERR_RESOURCE_LIMIT; }
        candidate.kind = (xair_sym_expr_kind)kind;
        candidate.opcode = (xair_opcode)opcode;
        candidate.bits = (uint16_t)bits;
        candidate.arg_count = arg_count;
        candidate.symbol = symbol;
        for (arg_i = 0; arg_i < arg_count; ++arg_i) {
            if (args[arg_i] >= i) { free(map); return XAIR_SYM_ERR_BAD_ARG; }
            candidate.args[arg_i] = map[args[arg_i]];
        }
        for (; arg_i < 3u; ++arg_i) {
            if (args[arg_i] != 0u) { free(map); return XAIR_SYM_ERR_BAD_ARG; }
        }
        if (!snapshot_expression_shape_valid(context, &candidate)) {
            free(map); return XAIR_SYM_ERR_BAD_ARG;
        }
        status = xair_sym_intern(context, &candidate, &map[i]);
        if (status != XAIR_SYM_OK) { free(map); return status; }
        context->expressions[map[i]]->flags_pack = flags_pack;
    }
    *out_map = map;
    *out_count = (size_t)count;
    return XAIR_SYM_OK;
}

static xair_sym_status load_taint_dag(snapshot_reader *reader, xair_sym_context *context,
    snapshot_budget *budget, const xair_sym_expr_id *expr_map, size_t expr_count,
    xair_sym_taint_id **out_map, size_t *out_count) {
    xair_sym_taint_id *map = NULL;
    uint64_t count;
    size_t i;
    if (!read_u64(reader, &count) || count >= UINT32_MAX ||
        count > (reader->size - reader->offset) / 70u) return XAIR_SYM_ERR_BAD_ARG;
    if (!budget_charge_array(budget, count + 1u, sizeof(*map) + sizeof(xair_sym_taint_node) +
        sizeof(xair_sym_taint_node *) * 2u)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (count != 0 && !budget_charge_array(budget, 16u, sizeof(xair_sym_taint_node *)))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    map = (xair_sym_taint_id *)calloc((size_t)count + 1u, sizeof(*map));
    if (map == NULL) return XAIR_SYM_ERR_OOM;
    for (i = 0; i < (size_t)count; ++i) {
        xair_sym_taint_details details;
        const char *name;
        size_t name_size, transform_size, sink_size;
        uint32_t kind, lhs, rhs, category, serialized_guard;
        xair_sym_taint_id rebuilt = XAIR_SYM_TAINT_NONE;
        xair_sym_status status;
        xair_sym_taint_node *node;
        memset(&details, 0, sizeof(details));
        if (!read_u32(reader, &kind) || !read_u32(reader, &lhs) || !read_u32(reader, &rhs) ||
            !read_string(reader, &name, &name_size) || !read_u32(reader, &category) ||
            !read_u64(reader, &details.source_address) || !read_u64(reader, &details.call_site) ||
            !read_u64(reader, &details.sink_address) || !read_u64(reader, &details.byte_offset) ||
            !read_u64(reader, &details.byte_length) || !read_u32(reader, &serialized_guard) ||
            !read_u8(reader, &details.confidence) || !read_u8(reader, &details.implicit) ||
            !read_u8(reader, &details.sanitizer_validated) ||
            !read_string(reader, &details.transform, &transform_size) ||
            !read_string(reader, &details.sink, &sink_size) ||
            kind < XAIR_SYM_TAINT_NODE_SOURCE || kind > XAIR_SYM_TAINT_NODE_SINK ||
            category > XAIR_SYM_TAINT_CATEGORY_DRIVER || details.implicit > 1u ||
            details.sanitizer_validated > 1u || lhs > i || rhs > i) {
            free(map); return XAIR_SYM_ERR_BAD_ARG;
        }
        if (!budget_charge(budget, name_size) || !budget_charge(budget, transform_size) ||
            !budget_charge(budget, sink_size)) { free(map); return XAIR_SYM_ERR_RESOURCE_LIMIT; }
        details.category = (xair_sym_taint_category)category;
        if (serialized_guard == XAIR_SYM_INVALID_ID) details.guard = XAIR_SYM_INVALID_ID;
        else if (serialized_guard == 0u && kind != XAIR_SYM_TAINT_NODE_TRANSFORM)
            details.guard = 0u;
        else {
            if (serialized_guard >= expr_count) { free(map); return XAIR_SYM_ERR_BAD_ARG; }
            details.guard = expr_map[serialized_guard];
        }
        if (kind == XAIR_SYM_TAINT_NODE_SOURCE) {
            if (lhs != 0 || rhs != 0 || name == NULL || details.transform != NULL || details.sink != NULL)
                { free(map); return XAIR_SYM_ERR_BAD_ARG; }
            status = xair_sym_taint_source_ex(context, name, &details, &rebuilt);
        } else if (kind == XAIR_SYM_TAINT_NODE_UNION) {
            if (lhs == 0 || rhs == 0 || name != NULL) { free(map); return XAIR_SYM_ERR_BAD_ARG; }
            status = xair_sym_taint_union(context, map[lhs], map[rhs], &rebuilt);
        } else if (kind == XAIR_SYM_TAINT_NODE_SANITIZER) {
            if (lhs == 0 || rhs != 0 || name == NULL) { free(map); return XAIR_SYM_ERR_BAD_ARG; }
            status = xair_sym_taint_sanitize_ex(context, map[lhs], name,
                details.sanitizer_validated != 0, &rebuilt);
        } else if (kind == XAIR_SYM_TAINT_NODE_TRANSFORM) {
            if (lhs == 0 || rhs != 0 || name == NULL) { free(map); return XAIR_SYM_ERR_BAD_ARG; }
            status = xair_sym_taint_transform(context, map[lhs], name, details.guard,
                details.implicit != 0, &rebuilt);
        } else {
            if (lhs == 0 || rhs != 0 || name == NULL) { free(map); return XAIR_SYM_ERR_BAD_ARG; }
            status = xair_sym_taint_sink(context, map[lhs], name, details.sink_address, &rebuilt);
        }
        if (status != XAIR_SYM_OK || rebuilt == XAIR_SYM_TAINT_NONE || rebuilt > context->taint_count) {
            free(map); return status == XAIR_SYM_OK ? XAIR_SYM_ERR_BAD_ARG : status;
        }
        node = context->taints[rebuilt - 1u];
        if (node->kind != (xair_sym_taint_node_kind)kind ||
            node->lhs != (lhs == 0 ? 0 : map[lhs]) || node->rhs != (rhs == 0 ? 0 : map[rhs]) ||
            !nullable_string_equal(node->name, name) ||
            !snapshot_taint_details_equal(&node->details, &details)) {
            free(map); return XAIR_SYM_ERR_BAD_ARG;
        }
        map[i + 1u] = rebuilt;
    }
    *out_map = map;
    *out_count = (size_t)count;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_snapshot_take(const xair_sym_state *state, xair_sym_snapshot **out_snapshot) {
    xair_sym_snapshot *snapshot;
    xair_status fingerprint_status;
    xair_sym_status clone_status;
    if (out_snapshot != NULL) *out_snapshot = NULL;
    if (state == NULL || out_snapshot == NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (state->environment != NULL && state->environment->model_count != 0)
        return XAIR_SYM_ERR_UNSUPPORTED;
    snapshot = (xair_sym_snapshot *)calloc(1, sizeof(*snapshot));
    if (snapshot == NULL) return XAIR_SYM_ERR_OOM;
    fingerprint_status = xair_module_fingerprint(state->module, &snapshot->module_fingerprint);
    if (fingerprint_status != XAIR_OK) { free(snapshot); return XAIR_SYM_ERR_BAD_ARG; }
    clone_status = xair_sym_state_clone(state, &snapshot->state);
    if (clone_status != XAIR_SYM_OK) { free(snapshot); return clone_status; }
    snapshot->state->program = NULL;
    snapshot->metadata.schema_version = SNAPSHOT_SCHEMA;
    snapshot->metadata.symbolic_version = xair_sym_version_u32();
    snapshot->metadata.memory_model_version = XAIR_SYM_MEMORY_MODEL_VERSION;
    snapshot->metadata.abi = state->abi;
    snapshot->metadata.ir_fingerprint = snapshot->module_fingerprint;
    snapshot->metadata.binary_hash = state->binary_hash;
    snapshot->metadata.model_library_version = state->environment != NULL ?
        state->environment->model_version : state->model_library_version;
    snapshot->state->model_library_version = snapshot->metadata.model_library_version;
    snapshot->metadata.options_fingerprint = state->options_fingerprint;
    snapshot->metadata.completeness = state->completeness;
    *out_snapshot = snapshot;
    return XAIR_SYM_OK;
}

void xair_sym_snapshot_destroy(xair_sym_snapshot *snapshot) {
    if (snapshot != NULL) { xair_sym_state_destroy(snapshot->state); free(snapshot); }
}

xair_sym_status xair_sym_snapshot_restore(const xair_sym_snapshot *snapshot, xair_sym_state **out_state) {
    if (out_state != NULL) *out_state = NULL;
    if (snapshot == NULL || out_state == NULL) return XAIR_SYM_ERR_BAD_ARG;
    return xair_sym_state_clone(snapshot->state, out_state);
}

xair_sym_status xair_sym_snapshot_metadata_get(const xair_sym_snapshot *snapshot,
    xair_sym_snapshot_metadata *out_metadata) {
    if (snapshot == NULL || out_metadata == NULL) return XAIR_SYM_ERR_BAD_ARG;
    *out_metadata = snapshot->metadata; return XAIR_SYM_OK;
}

static int serialize_snapshot(const xair_sym_snapshot *snapshot, snapshot_blob *blob) {
    static const uint8_t magic[8] = {'X','A','I','R','S','N','0','3'};
    const xair_sym_state *state = snapshot->state;
    snapshot_constraint_record *constraints = NULL;
    xair_sym_constraint *constraint;
    size_t i;
    int ok;
    if (state->environment != NULL && state->environment->model_count != 0) return 0;
    ok = blob_bytes(blob, magic, sizeof(magic)) && blob_u32(blob, snapshot->metadata.schema_version) &&
        blob_u32(blob, snapshot->metadata.symbolic_version) && blob_u32(blob, snapshot->metadata.memory_model_version) &&
        blob_u32(blob, (uint32_t)snapshot->metadata.abi) && blob_u64(blob, snapshot->metadata.ir_fingerprint) &&
        blob_u64(blob, snapshot->metadata.binary_hash) && blob_u64(blob, snapshot->metadata.model_library_version) &&
        blob_u64(blob, snapshot->metadata.options_fingerprint) && blob_u32(blob, (uint32_t)snapshot->metadata.completeness) &&
        blob_u64(blob, state->context->expression_count);
    for (i = 0; ok && i < state->context->expression_count; ++i) {
        const xair_sym_expr *expr = state->context->expressions[i];
        ok = blob_u8(blob, (uint8_t)expr->kind) && blob_u32(blob, (uint32_t)expr->opcode) &&
            blob_u32(blob, expr->bits) && blob_u8(blob, expr->arg_count) &&
            blob_u8(blob, expr->flags_pack) &&
            blob_u32(blob, expr->args[0]) && blob_u32(blob, expr->args[1]) &&
            blob_u32(blob, expr->args[2]) && blob_u64(blob, expr->immediate) &&
            blob_u64(blob, expr->immediate_hi) && blob_string(blob, expr->symbol);
    }
    if (ok) ok = blob_u64(blob, state->context->taint_count);
    for (i = 0; ok && i < state->context->taint_count; ++i) {
        const xair_sym_taint_node *taint = state->context->taints[i];
        ok = blob_u32(blob, (uint32_t)taint->kind) && blob_u32(blob, taint->lhs) &&
            blob_u32(blob, taint->rhs) && blob_string(blob, taint->name) &&
            blob_u32(blob, (uint32_t)taint->details.category) &&
            blob_u64(blob, taint->details.source_address) && blob_u64(blob, taint->details.call_site) &&
            blob_u64(blob, taint->details.sink_address) && blob_u64(blob, taint->details.byte_offset) &&
            blob_u64(blob, taint->details.byte_length) && blob_u32(blob, taint->details.guard) &&
            blob_u8(blob, taint->details.confidence) && blob_u8(blob, taint->details.implicit) &&
            blob_u8(blob, taint->details.sanitizer_validated) &&
            blob_string(blob, taint->details.transform) && blob_string(blob, taint->details.sink);
    }
    if (ok) ok = blob_u32(blob, state->block) &&
        blob_u64(blob, state->depth) && blob_u32(blob, state->control_taint) &&
        blob_u64(blob, state->unresolved_operations) && blob_u64(blob, state->heap_next) &&
        blob_u64(blob, state->fs_base) && blob_u64(blob, state->gs_base) &&
        blob_u64(blob, state->memory_havoc_version) &&
        blob_u64(blob, state->partition_constraint_identity) &&
        blob_u32(blob, (uint32_t)state->execution_mode) && blob_u8(blob, state->terminate_requested) &&
        blob_u8(blob, state->model_output_confidence) &&
        blob_u8(blob, state->environment != NULL);
    if (ok && state->environment != NULL)
        ok = blob_u32(blob, (uint32_t)state->environment->arch) &&
            blob_u64(blob, state->environment->stack_base) &&
            blob_u64(blob, state->environment->stack_size) &&
            blob_u64(blob, state->environment->heap_next);
    if (ok) ok = blob_u32(blob, (uint32_t)state->control_scope_count);
    for (i = 0; ok && i < state->control_scope_count; ++i)
        ok = blob_u32(blob, state->control_scopes[i].postdominator) && blob_u32(blob, state->control_scopes[i].taint);
    if (ok) ok = blob_u64(blob, state->value_count);
    for (i = 0; ok && i < state->value_count; ++i)
        ok = blob_u8(blob, state->defined[i]) &&
            blob_u32(blob, state->defined[i] ? state->values[i] : XAIR_SYM_INVALID_ID) &&
            blob_u32(blob, state->value_taints[i]);
    if (state->constraints != NULL) {
        constraints = (snapshot_constraint_record *)malloc(state->constraints->count * sizeof(*constraints));
        if (constraints == NULL) ok = 0;
        else {
            size_t index = state->constraints->count;
            for (constraint = state->constraints; constraint != NULL; constraint = constraint->parent) {
                --index;
                constraints[index].expression = constraint->expression;
                constraints[index].identity = constraint->identity;
            }
        }
    }
    if (ok) ok = blob_u64(blob, state->constraints == NULL ? 0 : state->constraints->count);
    for (i = 0; ok && state->constraints != NULL && i < state->constraints->count; ++i)
        ok = blob_u64(blob, constraints[i].identity) && blob_u32(blob, constraints[i].expression);
    if (ok) ok = blob_u64(blob, state->memory->count);
    for (i = 0; ok && i < state->memory->count; ++i) {
        const xair_sym_object *object = &state->memory->objects[i];
        size_t page_i, backing_i, backing_records = 0, page_records = 0;
        for (backing_i = 0; backing_i < object->backing_size; ++backing_i)
            if (object->backing[backing_i] != 0) backing_records++;
        for (page_i = 0; page_i < object->page_count; ++page_i) if (object->pages[page_i] != NULL) page_records++;
        ok = blob_u64(blob, object->base) && blob_u64(blob, object->size) && blob_u32(blob, object->permissions) &&
            blob_u8(blob, object->zero_fill) && blob_u64(blob, object->backing_size) &&
            blob_u64(blob, backing_records);
        for (backing_i = 0; ok && backing_i < object->backing_size; ++backing_i) {
            if (object->backing[backing_i] != 0)
                ok = blob_u64(blob, backing_i) && blob_u8(blob, object->backing[backing_i]);
        }
        if (ok) ok = blob_u64(blob, page_records);
        for (page_i = 0; ok && page_i < object->page_count; ++page_i) {
            const xair_sym_page *page = object->pages[page_i];
            size_t byte_i, entries = 0;
            if (page == NULL) continue;
            for (byte_i = 0; byte_i < XAIR_SYM_PAGE_SIZE; ++byte_i)
                if (page->bytes[byte_i] != XAIR_SYM_INVALID_ID || page->taints[byte_i] != XAIR_SYM_TAINT_NONE) entries++;
            ok = blob_u64(blob, page_i) && blob_u32(blob, (uint32_t)entries);
            for (byte_i = 0; ok && byte_i < XAIR_SYM_PAGE_SIZE; ++byte_i) {
                if (page->bytes[byte_i] == XAIR_SYM_INVALID_ID && page->taints[byte_i] == XAIR_SYM_TAINT_NONE) continue;
                ok = blob_u32(blob, (uint32_t)byte_i) && blob_u32(blob, page->bytes[byte_i]) &&
                    blob_u32(blob, page->taints[byte_i]);
            }
        }
    }
    free(constraints);
    if (ok) ok = blob_u64(blob, snapshot_hash(blob->data, blob->size));
    return ok;
}

xair_sym_status xair_sym_snapshot_fingerprint(const xair_sym_snapshot *snapshot, uint64_t *out_fingerprint) {
    snapshot_blob blob;
    if (snapshot == NULL || out_fingerprint == NULL) return XAIR_SYM_ERR_BAD_ARG;
    memset(&blob, 0, sizeof(blob));
    if (!serialize_snapshot(snapshot, &blob)) { free(blob.data); return XAIR_SYM_ERR_OOM; }
    *out_fingerprint = snapshot_hash(blob.data, blob.size - 8u);
    free(blob.data); return XAIR_SYM_OK;
}

static int atomic_replace(const char *temporary, const char *path) {
#if defined(_WIN32)
    return MoveFileExA(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return rename(temporary, path) == 0;
#endif
}

xair_sym_status xair_sym_snapshot_save(const xair_sym_snapshot *snapshot, const char *path) {
    snapshot_blob blob;
    char *temporary;
    size_t path_size;
    FILE *file;
    int ok;
    if (snapshot == NULL || path == NULL) return XAIR_SYM_ERR_BAD_ARG;
    memset(&blob, 0, sizeof(blob));
    if (!serialize_snapshot(snapshot, &blob)) { free(blob.data); return XAIR_SYM_ERR_OOM; }
    path_size = strlen(path);
    if (path_size > SIZE_MAX - 5u) { free(blob.data); return XAIR_SYM_ERR_RANGE; }
    temporary = (char *)malloc(path_size + 5u);
    if (temporary == NULL) { free(blob.data); return XAIR_SYM_ERR_OOM; }
    memcpy(temporary, path, path_size); memcpy(temporary + path_size, ".tmp", 5u);
    file = fopen(temporary, "wb");
    ok = file != NULL && fwrite(blob.data, 1, blob.size, file) == blob.size && fflush(file) == 0;
    if (file != NULL && fclose(file) != 0) ok = 0;
    if (ok) ok = atomic_replace(temporary, path);
    if (!ok) remove(temporary);
    free(temporary); free(blob.data);
    return ok ? XAIR_SYM_OK : XAIR_SYM_ERR_BAD_ARG;
}

static xair_sym_status load_blob(xair_sym_context *context, const xair_module *module,
    const uint8_t *data, size_t size, const xair_sym_snapshot_metadata *expected,
    uint32_t expectation_flags, size_t input_allocation, xair_sym_snapshot **out_snapshot) {
    static const uint8_t magic[8] = {'X','A','I','R','S','N','0','3'};
    snapshot_reader reader;
    xair_sym_snapshot_metadata metadata;
    xair_sym_snapshot *snapshot = NULL;
    xair_sym_state *state = NULL;
    xair_sym_expr_id *expr_map = NULL;
    xair_sym_taint_id *taint_map = NULL;
    size_t expr_count = 0, taint_count = 0;
    snapshot_budget budget;
    uint8_t actual_magic[8];
    uint32_t u32, block, control_taint, scope_count, environment_arch = 0;
    uint64_t depth, unresolved, heap_next, fs_base, gs_base, memory_havoc, partition_identity;
    uint64_t environment_stack_base = 0, environment_stack_size = 0, environment_heap_next = 0;
    uint64_t count, stored_checksum, current_fp;
    uint32_t execution_mode;
    uint8_t terminate_requested, model_output_confidence, environment_present;
    xair_sym_environment *environment = NULL;
    int partition_found = 0;
    uint64_t previous_constraint_identity = 0;
    size_t i;
    xair_sym_status status = XAIR_SYM_ERR_BAD_ARG;
    if (out_snapshot != NULL) *out_snapshot = NULL;
    if (data == NULL || out_snapshot == NULL || size < 16u || snapshot_hash(data, size - 8u) !=
        ((uint64_t)data[size-8] | (uint64_t)data[size-7] << 8u | (uint64_t)data[size-6] << 16u |
         (uint64_t)data[size-5] << 24u | (uint64_t)data[size-4] << 32u | (uint64_t)data[size-3] << 40u |
         (uint64_t)data[size-2] << 48u | (uint64_t)data[size-1] << 56u)) return XAIR_SYM_ERR_BAD_ARG;
    reader.data = data; reader.size = size; reader.offset = 0;
    if (!budget_init(&budget, context) || !budget_charge(&budget, input_allocation)) {
        status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail;
    }
    memset(&metadata, 0, sizeof(metadata));
    if (!read_bytes(&reader, actual_magic, 8) || memcmp(actual_magic, magic, 8) != 0 ||
        !read_u32(&reader, &metadata.schema_version) || !read_u32(&reader, &metadata.symbolic_version) ||
        !read_u32(&reader, &metadata.memory_model_version) || !read_u32(&reader, &u32)) goto fail;
    metadata.abi = (xair_calling_convention)u32;
    if (!read_u64(&reader, &metadata.ir_fingerprint) || !read_u64(&reader, &metadata.binary_hash) ||
        !read_u64(&reader, &metadata.model_library_version) || !read_u64(&reader, &metadata.options_fingerprint) ||
        !read_u32(&reader, &u32)) goto fail;
    metadata.completeness = (xair_sym_completion_reason)u32;
    if (metadata.schema_version != SNAPSHOT_SCHEMA || metadata.symbolic_version > xair_sym_version_u32() ||
        metadata.memory_model_version != XAIR_SYM_MEMORY_MODEL_VERSION || metadata.completeness > XAIR_SYM_FAILED ||
        xair_module_fingerprint(module, &current_fp) != XAIR_OK || current_fp != metadata.ir_fingerprint) goto fail;
    if (expected != NULL) {
        if (((expectation_flags & XAIR_SYM_SNAPSHOT_EXPECT_BINARY) != 0 &&
             expected->binary_hash != metadata.binary_hash) ||
            ((expectation_flags & XAIR_SYM_SNAPSHOT_EXPECT_ABI) != 0 && expected->abi != metadata.abi) ||
            ((expectation_flags & XAIR_SYM_SNAPSHOT_EXPECT_MODELS) != 0 &&
             expected->model_library_version != metadata.model_library_version) ||
            ((expectation_flags & XAIR_SYM_SNAPSHOT_EXPECT_OPTIONS) != 0 &&
             expected->options_fingerprint != metadata.options_fingerprint)) goto fail;
    }
    status = load_expression_dag(&reader, context, &budget, &expr_map, &expr_count);
    if (status != XAIR_SYM_OK) goto fail;
    status = load_taint_dag(&reader, context, &budget, expr_map, expr_count, &taint_map, &taint_count);
    if (status != XAIR_SYM_OK) goto fail;
    if (!read_u32(&reader, &block) || !read_u64(&reader, &depth) || !read_u32(&reader, &control_taint) ||
        !read_u64(&reader, &unresolved) || !read_u64(&reader, &heap_next) ||
        !read_u64(&reader, &fs_base) || !read_u64(&reader, &gs_base) ||
        !read_u64(&reader, &memory_havoc) || !read_u64(&reader, &partition_identity) ||
        !read_u32(&reader, &execution_mode) ||
        !read_u8(&reader, &terminate_requested) || !read_u8(&reader, &model_output_confidence) ||
        !read_u8(&reader, &environment_present) ||
        block >= xair_module_block_count(module) || control_taint > taint_count ||
        execution_mode > XAIR_SYM_EXEC_HYBRID_CONCRETIZE || terminate_requested > 1u ||
        model_output_confidence > XAIR_CONFIDENCE_EXACT ||
        environment_present > 1u || metadata.abi > XAIR_CC_STDCALL_X86) {
        status = XAIR_SYM_ERR_BAD_ARG; goto fail;
    }
    if (environment_present &&
        (!read_u32(&reader, &environment_arch) || !read_u64(&reader, &environment_stack_base) ||
         !read_u64(&reader, &environment_stack_size) || !read_u64(&reader, &environment_heap_next))) {
        status = XAIR_SYM_ERR_BAD_ARG; goto fail;
    }
    if (!read_u32(&reader, &scope_count) || scope_count > 32u) {
        status = XAIR_SYM_ERR_BAD_ARG; goto fail;
    }
    control_taint = taint_map[control_taint];
    if (!budget_charge(&budget, sizeof(*state) + sizeof(xair_sym_memory)) ||
        !budget_charge_array(&budget, xair_module_value_count(module),
            sizeof(xair_sym_expr_id) + sizeof(uint8_t) + sizeof(xair_sym_taint_id)) ||
        (xair_module_value_count(module) == 0 &&
         !budget_charge(&budget, sizeof(xair_sym_expr_id) + sizeof(uint8_t) + sizeof(xair_sym_taint_id)))) {
        status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail;
    }
    status = xair_sym_state_create(context, module, block, &state);
    if (status != XAIR_SYM_OK) goto fail;
    state->depth = (size_t)depth; state->control_taint = control_taint; state->unresolved_operations = (size_t)unresolved;
    state->heap_next = heap_next; state->fs_base = fs_base; state->gs_base = gs_base;
    state->memory_havoc_version = memory_havoc;
    state->partition_constraint_identity = 0;
    partition_found = partition_identity == 0;
    state->execution_mode = (xair_sym_execution_mode)execution_mode;
    state->terminate_requested = terminate_requested;
    state->model_output_confidence = model_output_confidence;
    state->abi = metadata.abi; state->binary_hash = metadata.binary_hash;
    state->model_library_version = metadata.model_library_version; state->options_fingerprint = metadata.options_fingerprint;
    state->completeness = metadata.completeness;
    if (environment_present) {
        if (environment_stack_size > SIZE_MAX) { status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail; }
        status = xair_sym_environment_create_builtin_snapshot(context,
            (xair_arch)environment_arch, metadata.abi, metadata.model_library_version,
            environment_stack_base, (size_t)environment_stack_size,
            environment_heap_next, &environment);
        if (status != XAIR_SYM_OK) goto fail;
        xair_sym_environment_attach_builtin(state, environment); environment = NULL;
    }
    state->control_scope_count = scope_count;
    for (i = 0; i < scope_count; ++i) {
        if (!read_u32(&reader, &state->control_scopes[i].postdominator) ||
            !read_u32(&reader, &state->control_scopes[i].taint) || state->control_scopes[i].taint > taint_count ||
            (state->control_scopes[i].postdominator != XAIR_INVALID_ID &&
             state->control_scopes[i].postdominator >= xair_module_block_count(module))) goto fail;
        state->control_scopes[i].taint = taint_map[state->control_scopes[i].taint];
    }
    if (!read_u64(&reader, &count) || count != state->value_count) goto fail;
    for (i = 0; i < state->value_count; ++i) {
        uint8_t defined; uint32_t expression, taint;
        if (!read_u8(&reader, &defined) || !read_u32(&reader, &expression) || !read_u32(&reader, &taint) ||
            defined > 1 || (expression != XAIR_SYM_INVALID_ID && expression >= expr_count) ||
            taint > taint_count) goto fail;
        if (defined && xair_value_type(module, (xair_value_id)i).kind == XAIR_TYPE_MEM) {
            if (expression != XAIR_SYM_INVALID_ID) goto fail;
        } else if (defined) {
            if (expression == XAIR_SYM_INVALID_ID ||
                context->expressions[expr_map[expression]]->bits != xair_value_type(module, (xair_value_id)i).bits) goto fail;
        }
        state->defined[i] = defined;
        state->values[i] = expression == XAIR_SYM_INVALID_ID ? XAIR_SYM_INVALID_ID : expr_map[expression];
        state->value_taints[i] = taint_map[taint];
    }
    if (!read_u64(&reader, &count) || count > SNAPSHOT_MAX_CONSTRAINTS) goto fail;
    for (i = 0; i < (size_t)count; ++i) {
        uint32_t expression;
        uint64_t serialized_identity;
        if (!read_u64(&reader, &serialized_identity) || !read_u32(&reader, &expression) ||
            serialized_identity == 0 || serialized_identity <= previous_constraint_identity ||
            expression >= expr_count ||
            context->expressions[expr_map[expression]]->bits != 1u) goto fail;
        previous_constraint_identity = serialized_identity;
        if (!budget_charge(&budget, sizeof(xair_sym_constraint))) {
            status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail;
        }
        status = xair_sym_state_assume(state, expr_map[expression]); if (status != XAIR_SYM_OK) goto fail;
        if (serialized_identity == partition_identity) {
            state->partition_constraint_identity = state->constraints->identity;
            partition_found = 1;
        }
    }
    if (!partition_found) goto fail;
    if (!read_u64(&reader, &count) || count > SNAPSHOT_MAX_OBJECTS) goto fail;
    if (!budget_charge_array(&budget, count, sizeof(xair_sym_object))) {
        status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail;
    }
    if (count != 0 && !budget_charge_array(&budget, 4u, sizeof(xair_sym_object))) {
        status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail;
    }
    for (i = 0; i < (size_t)count; ++i) {
        uint64_t base, object_size, backing_size, backing_records, backing_i, previous_backing = UINT64_MAX;
        uint64_t page_records, page_i, previous_page = UINT64_MAX;
        uint32_t permissions; uint8_t zero_fill; uint8_t *backing = NULL; xair_sym_object_id object_id;
        size_t page_count;
        if (!read_u64(&reader, &base) || !read_u64(&reader, &object_size) || !read_u32(&reader, &permissions) ||
            !read_u8(&reader, &zero_fill) || !read_u64(&reader, &backing_size) ||
            !read_u64(&reader, &backing_records) || object_size == 0 ||
            object_size > SIZE_MAX || backing_size > object_size || backing_size > SIZE_MAX || zero_fill > 1u ||
            backing_records > backing_size || backing_records > (reader.size - reader.offset) / 9u) goto fail;
        page_count = ((size_t)object_size >> XAIR_SYM_PAGE_SHIFT) +
            ((((size_t)object_size & (XAIR_SYM_PAGE_SIZE - 1u)) != 0u) ? 1u : 0u);
        if (!budget_charge_array(&budget, page_count, sizeof(xair_sym_page *)) ||
            !budget_charge(&budget, (size_t)backing_size) ||
            !budget_charge(&budget, sizeof(xair_sym_backing))) {
            status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail;
        }
        if (backing_size != 0) {
            backing = (uint8_t *)calloc((size_t)backing_size, 1);
            if (backing == NULL) { status = XAIR_SYM_ERR_OOM; goto fail; }
        }
        for (backing_i = 0; backing_i < backing_records; ++backing_i) {
            uint64_t offset; uint8_t value;
            if (!read_u64(&reader, &offset) || !read_u8(&reader, &value) || value == 0 ||
                offset >= backing_size || (previous_backing != UINT64_MAX && offset <= previous_backing)) {
                free(backing); goto fail;
            }
            previous_backing = offset; backing[offset] = value;
        }
        status = xair_sym_memory_map_lazy(state, base, (size_t)object_size, permissions,
            backing, (size_t)backing_size, zero_fill, &object_id);
        if (status != XAIR_SYM_OK) { free(backing); goto fail; }
        if (backing != NULL && state->memory->objects[object_id].backing_ref != NULL)
            state->memory->objects[object_id].backing_ref->owned = 1;
        if (!read_u64(&reader, &page_records) || page_records > state->memory->objects[object_id].page_count) goto fail;
        for (page_i = 0; page_i < page_records; ++page_i) {
            uint64_t page_index; uint32_t entries, entry_i, previous_offset = UINT32_MAX;
            if (!read_u64(&reader, &page_index) || !read_u32(&reader, &entries) ||
                page_index >= state->memory->objects[object_id].page_count || entries > XAIR_SYM_PAGE_SIZE ||
                (previous_page != UINT64_MAX && page_index <= previous_page)) goto fail;
            previous_page = page_index;
            if (entries != 0 && !budget_charge(&budget, sizeof(xair_sym_page))) {
                status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail;
            }
            for (entry_i = 0; entry_i < entries; ++entry_i) {
                uint32_t offset, expression, taint;
                uint64_t address;
                if (!read_u32(&reader, &offset) || !read_u32(&reader, &expression) || !read_u32(&reader, &taint) ||
                    offset >= XAIR_SYM_PAGE_SIZE || (expression != XAIR_SYM_INVALID_ID && expression >= expr_count) ||
                    taint > taint_count ||
                    (previous_offset != UINT32_MAX && offset <= previous_offset)) goto fail;
                previous_offset = offset;
                address = base + (page_index << XAIR_SYM_PAGE_SHIFT) + offset;
                if (address - base >= object_size) goto fail;
                if (expression != XAIR_SYM_INVALID_ID) {
                    status = xair_sym_memory_initialize8(state, address, expr_map[expression]); if (status != XAIR_SYM_OK) goto fail;
                }
                if (taint != XAIR_SYM_TAINT_NONE) {
                    status = xair_sym_memory_initialize_taint8(state, address, taint_map[taint]); if (status != XAIR_SYM_OK) goto fail;
                }
            }
        }
    }
    if (!read_u64(&reader, &stored_checksum) || reader.offset != reader.size || stored_checksum != snapshot_hash(data, size - 8u)) goto fail;
    if (!budget_charge(&budget, sizeof(*snapshot))) { status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail; }
    snapshot = (xair_sym_snapshot *)calloc(1, sizeof(*snapshot));
    if (snapshot == NULL) { status = XAIR_SYM_ERR_OOM; goto fail; }
    snapshot->state = state; snapshot->module_fingerprint = metadata.ir_fingerprint; snapshot->metadata = metadata;
    *out_snapshot = snapshot;
    free(taint_map); free(expr_map);
    return XAIR_SYM_OK;
fail:
    free(taint_map); free(expr_map);
    xair_sym_environment_release(environment);
    xair_sym_state_destroy(state); xair_sym_snapshot_destroy(snapshot);
    return status == XAIR_SYM_OK ? XAIR_SYM_ERR_BAD_ARG : status;
}

xair_sym_status xair_sym_snapshot_load(xair_sym_context *context, const xair_module *module,
    const char *path, xair_sym_snapshot **out_snapshot) {
    FILE *file;
    long length;
    uint8_t *data;
    xair_sym_status status;
    if (out_snapshot != NULL) *out_snapshot = NULL;
    if (context == NULL || module == NULL || path == NULL || out_snapshot == NULL) return XAIR_SYM_ERR_BAD_ARG;
    file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        (uint64_t)length > SNAPSHOT_MAX_FILE || fseek(file, 0, SEEK_SET) != 0) {
        if (file != NULL) (void)fclose(file);
        return XAIR_SYM_ERR_BAD_ARG;
    }
    {
        size_t limit = context->analysis.max_memory != 0 ?
            context->analysis.max_memory : SNAPSHOT_DEFAULT_LOAD_BUDGET;
        size_t existing = context->analysis.max_memory != 0 ? context_allocation_estimate(context) : 0;
        if (existing > limit || (size_t)length > limit - existing) {
            (void)fclose(file);
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
        }
    }
    data = (uint8_t *)malloc((size_t)length != 0 ? (size_t)length : 1);
    if (data == NULL) { fclose(file); return XAIR_SYM_ERR_OOM; }
    if (fread(data, 1, (size_t)length, file) != (size_t)length || fclose(file) != 0) {
        free(data); return XAIR_SYM_ERR_BAD_ARG;
    }
    status = load_blob(context, module, data, (size_t)length, NULL, 0, (size_t)length, out_snapshot);
    free(data); return status;
}

xair_sym_status xair_sym_snapshot_load_bytes(xair_sym_context *context, const xair_module *module,
    const uint8_t *bytes, size_t size, xair_sym_snapshot **out_snapshot) {
    if (out_snapshot != NULL) *out_snapshot = NULL;
    if (context == NULL || module == NULL || bytes == NULL || out_snapshot == NULL || size > SNAPSHOT_MAX_FILE)
        return XAIR_SYM_ERR_BAD_ARG;
    return load_blob(context, module, bytes, size, NULL, 0, 0, out_snapshot);
}

xair_sym_status xair_sym_snapshot_load_bytes_checked(xair_sym_context *context,
    const xair_module *module, const uint8_t *bytes, size_t size,
    const xair_sym_snapshot_metadata *expected, uint32_t expectation_flags,
    xair_sym_snapshot **out_snapshot) {
    const uint32_t all_flags = XAIR_SYM_SNAPSHOT_EXPECT_BINARY | XAIR_SYM_SNAPSHOT_EXPECT_ABI |
        XAIR_SYM_SNAPSHOT_EXPECT_MODELS | XAIR_SYM_SNAPSHOT_EXPECT_OPTIONS;
    if (out_snapshot != NULL) *out_snapshot = NULL;
    if (context == NULL || module == NULL || bytes == NULL || expected == NULL ||
        out_snapshot == NULL || size > SNAPSHOT_MAX_FILE || (expectation_flags & ~all_flags) != 0)
        return XAIR_SYM_ERR_BAD_ARG;
    return load_blob(context, module, bytes, size, expected, expectation_flags, 0, out_snapshot);
}

xair_sym_status xair_sym_snapshot_clone_isolated(const xair_sym_snapshot *snapshot,
    xair_sym_context **out_context, xair_sym_state **out_state) {
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_environment *cloned_environment = NULL;
    const xair_sym_context *source_context;
    const xair_sym_state *source_state;
    snapshot_constraint_record *constraints = NULL;
    size_t i;
    xair_sym_status status;
    int partition_found;
    if (out_context != NULL) *out_context = NULL;
    if (out_state != NULL) *out_state = NULL;
    if (snapshot == NULL || out_context == NULL || out_state == NULL) return XAIR_SYM_ERR_BAD_ARG;
    source_state = snapshot->state; source_context = source_state->context;
    status = xair_sym_context_create(&context); if (status != XAIR_SYM_OK) return status;
    xair_sym_context_set_taint_mode(context, source_context->taint_mode);
    xair_sym_context_set_analysis_options(context, &source_context->analysis);
    for (i = 0; i < source_context->expression_count; ++i) {
        const xair_sym_expr *expression = source_context->expressions[i];
        xair_sym_expr_id rebuilt = XAIR_SYM_INVALID_ID;
        if (expression->kind == XAIR_SYM_EXPR_CONST) status = xair_sym_const_wide(context, expression->bits,
            expression->immediate, expression->immediate_hi, &rebuilt);
        else if (expression->kind == XAIR_SYM_EXPR_SYMBOL) status = xair_sym_symbol(context, expression->bits, expression->symbol, &rebuilt);
        else if (expression->arg_count == 1) status = xair_sym_unary(context, expression->opcode, expression->bits,
            expression->args[0], expression->immediate, &rebuilt);
        else if (expression->arg_count == 2) status = xair_sym_binary(context, expression->opcode, expression->bits,
            expression->args[0], expression->args[1], &rebuilt);
        else if (expression->opcode == XAIR_OP_SELECT) status = xair_sym_select(context,
            expression->args[0], expression->args[1], expression->args[2], &rebuilt);
        else status = XAIR_SYM_ERR_UNSUPPORTED;
        if (status != XAIR_SYM_OK || rebuilt != i) { status = XAIR_SYM_ERR_UNSUPPORTED; goto fail; }
        context->expressions[rebuilt]->flags_pack = expression->flags_pack;
    }
    for (i = 0; i < source_context->taint_count; ++i) {
        const xair_sym_taint_node *node = source_context->taints[i];
        xair_sym_taint_id rebuilt;
        if (node->kind == XAIR_SYM_TAINT_NODE_SOURCE) status = xair_sym_taint_source_ex(context, node->name, &node->details, &rebuilt);
        else if (node->kind == XAIR_SYM_TAINT_NODE_UNION) status = xair_sym_taint_union(context, node->lhs, node->rhs, &rebuilt);
        else if (node->kind == XAIR_SYM_TAINT_NODE_SINK) status = xair_sym_taint_sink(context, node->lhs,
            node->name, node->details.sink_address, &rebuilt);
        else if (node->kind == XAIR_SYM_TAINT_NODE_TRANSFORM) status = xair_sym_taint_transform(
            context, node->lhs, node->name, node->details.guard, node->details.implicit, &rebuilt);
        else status = xair_sym_taint_sanitize_ex(context, node->lhs, node->name,
            node->details.sanitizer_validated, &rebuilt);
        if (status != XAIR_SYM_OK || rebuilt != i + 1) { status = XAIR_SYM_ERR_UNSUPPORTED; goto fail; }
    }
    status = xair_sym_state_create(context, source_state->module, source_state->block, &state); if (status != XAIR_SYM_OK) goto fail;
    state->depth = source_state->depth; state->control_taint = source_state->control_taint;
    state->completeness = source_state->completeness; state->unresolved_operations = source_state->unresolved_operations;
    state->abi = source_state->abi; state->binary_hash = source_state->binary_hash;
    state->model_library_version = source_state->model_library_version; state->options_fingerprint = source_state->options_fingerprint;
    state->fs_base = source_state->fs_base; state->gs_base = source_state->gs_base; state->heap_next = source_state->heap_next;
    state->memory_havoc_version = source_state->memory_havoc_version;
    state->partition_constraint_identity = 0;
    partition_found = source_state->partition_constraint_identity == 0;
    state->execution_mode = source_state->execution_mode;
    state->terminate_requested = source_state->terminate_requested;
    state->model_output_confidence = source_state->model_output_confidence;
    state->call_model = NULL; state->call_model_user = NULL; state->environment = NULL;
    if (source_state->environment != NULL) {
        status = xair_sym_environment_clone_builtin(source_state->environment, context,
            &cloned_environment);
        if (status != XAIR_SYM_OK) goto fail;
        xair_sym_environment_attach_builtin(state, cloned_environment);
        cloned_environment = NULL;
    }
    state->control_scope_count = source_state->control_scope_count;
    memcpy(state->control_scopes, source_state->control_scopes, sizeof(state->control_scopes));
    if (source_context->immediate_postdominator_count != 0) {
        context->immediate_postdominators = (xair_block_id *)malloc(
            source_context->immediate_postdominator_count * sizeof(*context->immediate_postdominators));
        if (context->immediate_postdominators == NULL) { status = XAIR_SYM_ERR_OOM; goto fail; }
        memcpy(context->immediate_postdominators, source_context->immediate_postdominators,
            source_context->immediate_postdominator_count * sizeof(*context->immediate_postdominators));
        context->immediate_postdominator_count = source_context->immediate_postdominator_count;
    }
    memcpy(state->defined, source_state->defined, source_state->value_count);
    memcpy(state->values, source_state->values, source_state->value_count * sizeof(*state->values));
    memcpy(state->value_taints, source_state->value_taints, source_state->value_count * sizeof(*state->value_taints));
    if (source_state->constraints != NULL) {
        xair_sym_constraint *constraint;
        size_t index = source_state->constraints->count;
        constraints = (snapshot_constraint_record *)malloc(index * sizeof(*constraints));
        if (constraints == NULL) { status = XAIR_SYM_ERR_OOM; goto fail; }
        for (constraint = source_state->constraints; constraint != NULL; constraint = constraint->parent) {
            --index;
            constraints[index].expression = constraint->expression;
            constraints[index].identity = constraint->identity;
        }
        for (index = 0; index < source_state->constraints->count; ++index) {
            status = xair_sym_state_assume(state, constraints[index].expression); if (status != XAIR_SYM_OK) goto fail;
            if (constraints[index].identity == source_state->partition_constraint_identity) {
                state->partition_constraint_identity = state->constraints->identity;
                partition_found = 1;
            }
        }
    }
    if (!partition_found) { status = XAIR_SYM_ERR_INTERNAL; goto fail; }
    for (i = 0; i < source_state->memory->count; ++i) {
        const xair_sym_object *object = &source_state->memory->objects[i];
        xair_sym_object_id object_id;
        size_t page_i, byte_i;
        status = xair_sym_memory_map_lazy(state, object->base, object->size, object->permissions,
            object->backing, object->backing_size, object->zero_fill, &object_id);
        if (status != XAIR_SYM_OK) goto fail;
        for (page_i = 0; page_i < object->page_count; ++page_i) {
            const xair_sym_page *page = object->pages[page_i];
            if (page == NULL) continue;
            for (byte_i = 0; byte_i < XAIR_SYM_PAGE_SIZE && (page_i << XAIR_SYM_PAGE_SHIFT) + byte_i < object->size; ++byte_i) {
                uint64_t address = object->base + (page_i << XAIR_SYM_PAGE_SHIFT) + byte_i;
                if (page->bytes[byte_i] != XAIR_SYM_INVALID_ID) {
                    status = xair_sym_memory_initialize8(state, address, page->bytes[byte_i]); if (status != XAIR_SYM_OK) goto fail;
                }
                if (page->taints[byte_i] != XAIR_SYM_TAINT_NONE) {
                    status = xair_sym_memory_initialize_taint8(state, address, page->taints[byte_i]); if (status != XAIR_SYM_OK) goto fail;
                }
            }
        }
    }
    free(constraints); *out_context = context; *out_state = state; return XAIR_SYM_OK;
fail:
    xair_sym_environment_release(cloned_environment);
    free(constraints); xair_sym_state_destroy(state); xair_sym_context_destroy(context); return status;
}
