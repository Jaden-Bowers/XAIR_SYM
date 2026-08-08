#include "xair_sym_internal.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void constraint_retain(xair_sym_constraint *constraint) {
    if (constraint != NULL) constraint->refs++;
}

static void constraint_release(xair_sym_constraint *constraint) {
    while (constraint != NULL) {
        xair_sym_constraint *parent;
        if (--constraint->refs != 0) return;
        parent = constraint->parent;
        xair_sym_parallel_memory_release(constraint->context, sizeof(*constraint));
        free(constraint);
        constraint = parent;
    }
}

static int parallel_budget_take(size_t *remaining, xair_sym_parallel_budget *budget) {
    int allowed;
    if (budget == NULL) return 1;
    xair_mutex_lock(&budget->lock);
    allowed = *remaining != 0;
    if (allowed) --*remaining;
    xair_mutex_unlock(&budget->lock);
    return allowed;
}

static int parallel_cover_block(xair_sym_parallel_budget *budget, xair_block_id block) {
    int first = 1;
    if (budget == NULL || block >= budget->block_count) return 1;
    xair_mutex_lock(&budget->lock);
    first = budget->covered_blocks[block] == 0;
    budget->covered_blocks[block] = 1;
    xair_mutex_unlock(&budget->lock);
    return first;
}

xair_sym_status xair_sym_state_create(xair_sym_context *context, const xair_module *module,
    xair_block_id entry, xair_sym_state **out_state) {
    xair_sym_state *state;
    size_t values, allocation;
    if (context == NULL || module == NULL || out_state == NULL || entry >= xair_module_block_count(module)) return XAIR_SYM_ERR_BAD_ARG;
    values = xair_module_value_count(module) != 0 ? xair_module_value_count(module) : 1u;
    if (values > (SIZE_MAX - sizeof(*state)) / (sizeof(xair_sym_expr_id) + sizeof(uint8_t) + sizeof(xair_sym_taint_id)))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    allocation = sizeof(*state) + values * (sizeof(xair_sym_expr_id) + sizeof(uint8_t) + sizeof(xair_sym_taint_id));
    if (!xair_sym_parallel_memory_reserve(context, allocation)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    state = (xair_sym_state *)calloc(1, sizeof(*state));
    if (state == NULL) { xair_sym_parallel_memory_release(context, allocation); return XAIR_SYM_ERR_OOM; }
    state->context = context; state->module = module; state->block = entry; state->value_count = xair_module_value_count(module);
    state->parallel_memory_reserved = allocation;
    state->values = (xair_sym_expr_id *)malloc((state->value_count != 0 ? state->value_count : 1) * sizeof(*state->values));
    state->defined = (uint8_t *)calloc(state->value_count != 0 ? state->value_count : 1, 1);
    state->value_taints = (xair_sym_taint_id *)calloc(state->value_count != 0 ? state->value_count : 1, sizeof(*state->value_taints));
    state->memory = xair_sym_memory_create();
    if (state->values == NULL || state->defined == NULL || state->value_taints == NULL || state->memory == NULL) { xair_sym_state_destroy(state); return XAIR_SYM_ERR_OOM; }
    context->stats.states_created++; *out_state = state; return XAIR_SYM_OK;
}

xair_sym_status xair_sym_state_clone(const xair_sym_state *source, xair_sym_state **out_state) {
    xair_sym_state *state;
    size_t values, allocation;
    if (source == NULL || out_state == NULL) return XAIR_SYM_ERR_BAD_ARG;
    values = source->value_count != 0 ? source->value_count : 1u;
    if (values > (SIZE_MAX - sizeof(*state)) / (sizeof(xair_sym_expr_id) + sizeof(uint8_t) + sizeof(xair_sym_taint_id)))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    allocation = sizeof(*state) + values * (sizeof(xair_sym_expr_id) + sizeof(uint8_t) + sizeof(xair_sym_taint_id));
    if (!xair_sym_parallel_memory_reserve(source->context, allocation)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    state = (xair_sym_state *)calloc(1, sizeof(*state));
    if (state == NULL) { xair_sym_parallel_memory_release(source->context, allocation); return XAIR_SYM_ERR_OOM; }
    *state = *source; state->values = NULL; state->defined = NULL; state->value_taints = NULL; state->constraints = NULL; state->memory = NULL;
    state->parallel_memory_reserved = allocation;
    state->values = (xair_sym_expr_id *)malloc((state->value_count != 0 ? state->value_count : 1) * sizeof(*state->values));
    state->defined = (uint8_t *)malloc(state->value_count != 0 ? state->value_count : 1);
    state->value_taints = (xair_sym_taint_id *)malloc((state->value_count != 0 ? state->value_count : 1) * sizeof(*state->value_taints));
    if (state->values == NULL || state->defined == NULL || state->value_taints == NULL) { xair_sym_state_destroy(state); return XAIR_SYM_ERR_OOM; }
    memcpy(state->values, source->values, state->value_count * sizeof(*state->values));
    memcpy(state->defined, source->defined, state->value_count);
    memcpy(state->value_taints, source->value_taints, state->value_count * sizeof(*state->value_taints));
    state->constraints = source->constraints; constraint_retain(state->constraints);
    state->memory = source->memory; xair_sym_memory_retain(state->memory);
    xair_sym_environment_retain(state->environment);
    state->context->stats.states_created++; *out_state = state; return XAIR_SYM_OK;
}

void xair_sym_state_destroy(xair_sym_state *state) {
    if (state == NULL) return;
    xair_sym_environment_release(state->environment);
    xair_sym_memory_release(state->memory); constraint_release(state->constraints); free(state->value_taints); free(state->defined); free(state->values);
    xair_sym_parallel_memory_release(state->context, state->parallel_memory_reserved); free(state);
}

xair_sym_status xair_sym_state_set_value(xair_sym_state *state, xair_value_id value, xair_sym_expr_id expr) {
    xair_type type;
    if (state == NULL || value >= state->value_count || expr >= state->context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    type = xair_value_type(state->module, value);
    if (type.kind == XAIR_TYPE_MEM ||
        (type.kind != XAIR_TYPE_FLAGS && type.kind != XAIR_TYPE_ADDR && type.kind != XAIR_TYPE_INT) ||
        type.bits == 0 || type.bits != state->context->expressions[expr]->bits) return XAIR_SYM_ERR_BAD_ARG;
    if (type.kind == XAIR_TYPE_FLAGS) state->context->expressions[expr]->flags_pack = 1u;
    state->values[value] = expr; state->defined[value] = 1; return XAIR_SYM_OK;
}

xair_sym_status xair_sym_state_get_value(const xair_sym_state *state, xair_value_id value, xair_sym_expr_id *out_expr) {
    if (state == NULL || out_expr == NULL || value >= state->value_count || !state->defined[value]) return XAIR_SYM_ERR_BAD_ARG;
    *out_expr = state->values[value]; return XAIR_SYM_OK;
}

void xair_sym_state_set_call_model(
    xair_sym_state *state, xair_sym_call_model_cb callback, void *user) {
    if (state == NULL) return;
    state->call_model = callback;
    state->call_model_user = user;
}

xair_sym_status xair_sym_state_assume(xair_sym_state *state, xair_sym_expr_id condition) {
    xair_sym_constraint *constraint;
    if (state == NULL || condition >= state->context->expression_count || state->context->expressions[condition]->bits != 1) return XAIR_SYM_ERR_BAD_ARG;
    if (state->context->next_constraint_identity == UINT64_MAX) return XAIR_SYM_ERR_RANGE;
    if (!xair_sym_parallel_memory_reserve(state->context, sizeof(*constraint))) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    constraint = (xair_sym_constraint *)malloc(sizeof(*constraint));
    if (constraint == NULL) { xair_sym_parallel_memory_release(state->context, sizeof(*constraint)); return XAIR_SYM_ERR_OOM; }
    constraint->context = state->context;
    constraint->refs = 1;
    constraint->count = state->constraints == NULL ? 1 : state->constraints->count + 1;
    constraint->identity = ++state->context->next_constraint_identity;
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

static xair_sym_status offset_symbolic_address(
    xair_sym_state *state,
    xair_sym_expr_id address_expr,
    size_t offset,
    xair_sym_expr_id *out_address) {
    uint16_t bits;
    xair_sym_expr_id delta;
    xair_sym_status status;

    if (state == NULL || out_address == NULL || address_expr >= state->context->expression_count) {
        return XAIR_SYM_ERR_BAD_ARG;
    }
    if (offset == 0u) {
        *out_address = address_expr;
        return XAIR_SYM_OK;
    }
    bits = state->context->expressions[address_expr]->bits;
    status = xair_sym_const(state->context, bits, (uint64_t)offset, &delta);
    if (status != XAIR_SYM_OK) {
        return status;
    }
    return xair_sym_binary(state->context, XAIR_OP_ADD, bits, address_expr, delta, out_address);
}

static xair_sym_status concretize_memory_address(
    xair_sym_state *state,
    xair_sym_expr_id address_expr,
    uint64_t *out_address) {
    xair_sym_expr_id concrete_expr;
    xair_sym_expr_id assumed;
    xair_sym_status status;

    if (state == NULL || out_address == NULL) {
        return XAIR_SYM_ERR_BAD_ARG;
    }
    status = xair_sym_state_concretize(state, address_expr, &concrete_expr);
    if (status != XAIR_SYM_OK) {
        return status;
    }
    status = xair_sym_binary(state->context, XAIR_OP_EQ, 1, address_expr, concrete_expr, &assumed);
    if (status != XAIR_SYM_OK) {
        return status;
    }
    status = xair_sym_state_assume(state, assumed);
    if (status != XAIR_SYM_OK) {
        return status;
    }
    status = expression_constant(state, concrete_expr, out_address);
    if (status != XAIR_SYM_OK) {
        return status;
    }
    state->context->stats.concretizations++;
    return XAIR_SYM_OK;
}

static xair_sym_status execute_memory(xair_sym_state *state, xair_op_id op_id,
    const xair_op_view *op, xair_type out_type) {
    xair_sym_expr_id address_expr; uint64_t address; size_t bytes; size_t i; int address_is_concrete;
    xair_sym_taint_id memory_taint = XAIR_SYM_TAINT_NONE; xair_sym_status status;
    xair_op_attributes attributes;
    xair_endian endian = XAIR_ENDIAN_LE;
    if (xair_op_attributes_get(state->module, op_id, &attributes) == XAIR_OK)
        endian = attributes.endian;
    if (endian != XAIR_ENDIAN_LE && endian != XAIR_ENDIAN_BE) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_state_get_value(state, op->src[1], &address_expr); if (status != XAIR_SYM_OK) return status;
    status = expression_constant(state, address_expr, &address);
    address_is_concrete = status == XAIR_SYM_OK;
    if (op->opcode == XAIR_OP_LOAD) {
        xair_sym_expr_id result = XAIR_SYM_INVALID_ID;
        bytes = out_type.bits / 8u; if (out_type.bits == 0 || out_type.bits > 128 || out_type.bits % 8u != 0) return XAIR_SYM_ERR_UNSUPPORTED;
        if (!address_is_concrete && bytes > 1u && state->execution_mode == XAIR_SYM_EXEC_HYBRID_CONCRETIZE) {
            status = concretize_memory_address(state, address_expr, &address);
            if (status != XAIR_SYM_OK) return status;
            address_is_concrete = 1;
        }
        if (address_is_concrete) {
            status = xair_sym_memory_validate_range(state, address, bytes, 1u);
            if (status != XAIR_SYM_OK) return status;
        }
        for (i = 0; i < bytes; ++i) {
            xair_sym_expr_id byte = XAIR_SYM_INVALID_ID;
            if (address_is_concrete) {
                xair_sym_taint_id byte_taint = XAIR_SYM_TAINT_NONE;
                status = xair_sym_memory_load8(state, address + i, &byte);
                if (status == XAIR_SYM_OK) status = xair_sym_memory_load_taint8(state, address + i, &byte_taint);
                if (status == XAIR_SYM_OK) status = xair_sym_taint_union(state->context, memory_taint, byte_taint, &memory_taint);
            } else {
                xair_sym_expr_id byte_address;
                status = offset_symbolic_address(state, address_expr, i, &byte_address);
                {
                    xair_sym_taint_id byte_taint = XAIR_SYM_TAINT_NONE;
                    if (status == XAIR_SYM_OK) status = xair_sym_memory_load_symbolic8(
                        state, byte_address, &byte, &byte_taint);
                    if (status == XAIR_SYM_OK) status = xair_sym_taint_union(
                        state->context, memory_taint, byte_taint, &memory_taint);
                }
            }
            if (status != XAIR_SYM_OK) return status;
            if (result == XAIR_SYM_INVALID_ID) result = byte;
            else { xair_sym_expr_id joined; status = xair_sym_binary(state->context, XAIR_OP_CONCAT,
                (uint16_t)((i + 1) * 8u), endian == XAIR_ENDIAN_LE ? byte : result,
                endian == XAIR_ENDIAN_LE ? result : byte, &joined);
                if (status != XAIR_SYM_OK) return status;
                result = joined;
            }
        }
        status = xair_sym_state_set_value(state, op->dst, result);
        if (status != XAIR_SYM_OK) return status;
        return xair_sym_state_set_taint(state, op->dst, memory_taint);
    }
    if (op->opcode == XAIR_OP_STORE) {
        xair_sym_expr_id data; xair_type type = xair_value_type(state->module, op->src[2]);
        xair_sym_expr_id store_bytes[16];
        xair_sym_memory *saved_memory;
        xair_sym_constraint *saved_constraints;
        xair_sym_taint_id data_taint = state->value_taints[op->src[2]];
        if (state->context->taint_mode == XAIR_SYM_TAINT_STRICT_IMPLICIT) {
            status = xair_sym_taint_union(state->context, data_taint, state->control_taint, &data_taint);
            if (status != XAIR_SYM_OK) return status;
        }
        status = xair_sym_state_get_value(state, op->src[2], &data); if (status != XAIR_SYM_OK) return status;
        bytes = type.bits / 8u; if (type.bits == 0 || type.bits > 128 || type.bits % 8u != 0) return XAIR_SYM_ERR_UNSUPPORTED;
        if (!address_is_concrete && bytes > 1u && state->execution_mode == XAIR_SYM_EXEC_HYBRID_CONCRETIZE) {
            status = concretize_memory_address(state, address_expr, &address);
            if (status != XAIR_SYM_OK) return status;
            address_is_concrete = 1;
        }
        if (address_is_concrete) {
            status = xair_sym_memory_validate_range(state, address, bytes, 2u);
            if (status != XAIR_SYM_OK) return status;
        }
        for (i = 0; i < bytes; ++i) {
            uint64_t bit_offset = endian == XAIR_ENDIAN_LE ? i * 8u : (bytes - i - 1u) * 8u;
            status = xair_sym_unary(state->context, XAIR_OP_EXTRACT, 8, data, bit_offset, &store_bytes[i]);
            if (status != XAIR_SYM_OK) return status;
        }
        saved_memory = state->memory; xair_sym_memory_retain(saved_memory);
        saved_constraints = state->constraints; constraint_retain(saved_constraints);
        for (i = 0; i < bytes; ++i) {
            if (address_is_concrete) {
                status = xair_sym_memory_store8(state, address + i, store_bytes[i]);
                if (status == XAIR_SYM_OK) status = xair_sym_memory_store_taint8(state, address + i, data_taint);
            } else {
                xair_sym_expr_id byte_address;
                status = offset_symbolic_address(state, address_expr, i, &byte_address);
                if (status == XAIR_SYM_OK) status = xair_sym_memory_store_symbolic8(
                    state, byte_address, store_bytes[i], data_taint);
            }
            if (status != XAIR_SYM_OK) {
                xair_sym_memory_release(state->memory); state->memory = saved_memory;
                constraint_release(state->constraints); state->constraints = saved_constraints;
                return status;
            }
        }
        xair_sym_memory_release(saved_memory); constraint_release(saved_constraints);
        state->defined[op->dst] = 1;
        state->values[op->dst] = XAIR_SYM_INVALID_ID;
        return xair_sym_state_set_taint(state, op->dst, data_taint);
    }
    return XAIR_SYM_ERR_UNSUPPORTED;
}

static xair_sym_status execute_op_view(xair_sym_state *state, xair_op_id op_id,
    const xair_op_view *op_view) {
    xair_op_view op = *op_view; xair_type out; xair_sym_expr_id args[3];
    xair_sym_expr_id result = XAIR_SYM_INVALID_ID;
    xair_sym_taint_id result_taint = XAIR_SYM_TAINT_NONE; xair_sym_status status; size_t i;
    out = xair_value_type(state->module, op.dst);
    if (op.opcode == XAIR_OP_CONST_U64) {
        uint64_t canonical = out.bits >= 64u ? op.immediate :
            op.immediate & ((UINT64_C(1) << out.bits) - 1u);
        status = xair_sym_const(state->context, out.bits, canonical, &result);
    }
    else if (op.opcode == XAIR_OP_LOAD || op.opcode == XAIR_OP_STORE) return execute_memory(state, op_id, &op, out);
    else {
        for (i = 0; i < op.src_count; ++i) { status = xair_sym_state_get_value(state, op.src[i], &args[i]); if (status != XAIR_SYM_OK) return status; }
        if (op.src_count == 1) status = xair_sym_unary(state->context, op.opcode, out.bits, args[0], op.immediate, &result);
        else if (op.opcode == XAIR_OP_FLAGS_SHL && op.src_count == 3) {
            xair_sym_expr_id zero = XAIR_SYM_INVALID_ID;
            xair_sym_expr_id count_is_zero = XAIR_SYM_INVALID_ID;
            xair_sym_expr_id shifted = XAIR_SYM_INVALID_ID;
            status = xair_sym_binary(state->context, XAIR_OP_FLAGS_SHL, out.bits,
                args[0], args[1], &shifted);
            if (status == XAIR_SYM_OK)
                status = xair_sym_const(state->context,
                    state->context->expressions[args[1]]->bits, 0, &zero);
            if (status == XAIR_SYM_OK)
                status = xair_sym_binary(state->context, XAIR_OP_EQ, 1,
                    args[1], zero, &count_is_zero);
            if (status == XAIR_SYM_OK)
                status = xair_sym_select(state->context, count_is_zero,
                    args[2], shifted, &result);
        }
        else if (op.src_count == 2) status = xair_sym_binary(state->context, op.opcode, out.bits, args[0], args[1], &result);
        else if (op.opcode == XAIR_OP_SELECT) status = xair_sym_select(state->context, args[0], args[1], args[2], &result);
        else return XAIR_SYM_ERR_UNSUPPORTED;
    }
    if (status != XAIR_SYM_OK) return status;
    status = xair_sym_state_set_value(state, op.dst, result);
    if (status != XAIR_SYM_OK) return status;
    if (op.opcode != XAIR_OP_CONST_U64) {
        status = xair_sym_taint_operands(state, &op, &result_taint);
        if (status != XAIR_SYM_OK) return status;
    }
    if (state->context->taint_mode == XAIR_SYM_TAINT_STRICT_IMPLICIT) {
        status = xair_sym_taint_union(state->context, result_taint, state->control_taint, &result_taint);
        if (status != XAIR_SYM_OK) return status;
    }
    return xair_sym_state_set_taint(state, op.dst, result_taint);
}

static xair_sym_status execute_x86_div_intrinsic(xair_sym_state *state, xair_op_id id,
    const xair_op_attributes *attributes) {
    const xair_value_id *inputs, *results;
    size_t input_count, result_count;
    xair_sym_expr_id dividend, divisor, wide_divisor, quotient, remainder, narrowed;
    xair_sym_status status;
    uint16_t bits = attributes->width_bits;
    int is_signed = strcmp(attributes->semantic_id, "x86.idiv") == 0;
    if (bits == 0 || bits > 64 || xair_op_inputs(state->module, id, &inputs, &input_count) != XAIR_OK ||
        xair_op_results(state->module, id, &results, &result_count) != XAIR_OK ||
        input_count != 2 || result_count != 2) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_state_get_value(state, inputs[0], &dividend); if (status != XAIR_SYM_OK) return status;
    status = xair_sym_state_get_value(state, inputs[1], &divisor); if (status != XAIR_SYM_OK) return status;
    status = xair_sym_unary(state->context, is_signed ? XAIR_OP_SEXT : XAIR_OP_ZEXT,
        (uint16_t)(bits * 2u), divisor, 0, &wide_divisor); if (status != XAIR_SYM_OK) return status;
    status = xair_sym_binary(state->context, is_signed ? XAIR_OP_SDIV : XAIR_OP_UDIV,
        (uint16_t)(bits * 2u), dividend, wide_divisor, &quotient); if (status != XAIR_SYM_OK) return status;
    status = xair_sym_binary(state->context, is_signed ? XAIR_OP_SREM : XAIR_OP_UREM,
        (uint16_t)(bits * 2u), dividend, wide_divisor, &remainder); if (status != XAIR_SYM_OK) return status;
    status = xair_sym_unary(state->context, XAIR_OP_TRUNC, bits, quotient, 0, &narrowed);
    if (status == XAIR_SYM_OK) status = xair_sym_state_set_value(state, results[0], narrowed);
    if (status != XAIR_SYM_OK) return status;
    status = xair_sym_unary(state->context, XAIR_OP_TRUNC, bits, remainder, 0, &narrowed);
    if (status == XAIR_SYM_OK) status = xair_sym_state_set_value(state, results[1], narrowed);
    return status;
}

static xair_sym_status execute_op(xair_sym_state *state, xair_op_id id) {
    xair_op_view op;
    xair_op_view_v3 op_v3;
    const xair_value_id *results;
    size_t result_count;
    const xair_value_id *inputs = NULL;
    size_t input_count = 0;
    size_t i;
    if (xair_module_get_op_v3(state->module, id, &op_v3) != XAIR_OK ||
        xair_op_results(state->module, id, &results, &result_count) != XAIR_OK)
        return XAIR_SYM_ERR_BAD_ARG;
    if (op_v3.opcode == XAIR_OP_CONST_WIDE) {
        uint64_t lo, hi; xair_sym_expr_id constant; xair_type type;
        if (result_count != 1 || xair_op_immediate_wide(state->module, id, &lo, &hi) != XAIR_OK)
            return XAIR_SYM_ERR_BAD_ARG;
        type = xair_value_type(state->module, results[0]);
        if (xair_sym_const_wide(state->context, type.bits, lo, hi, &constant) != XAIR_SYM_OK)
            return XAIR_SYM_ERR_BAD_ARG;
        return xair_sym_state_set_value(state, results[0], constant);
    }
    if (op_v3.opcode == XAIR_OP_CALL && state->call_model != NULL) {
        state->model_output_confidence = XAIR_CONFIDENCE_UNKNOWN;
        return state->call_model(state, id, state->call_model_user);
    }
    if (op_v3.opcode == XAIR_OP_INTRINSIC) {
        xair_op_attributes attributes;
        if (xair_op_attributes_get(state->module, id, &attributes) == XAIR_OK &&
            attributes.semantic_id != NULL &&
            (strcmp(attributes.semantic_id, "x86.div") == 0 || strcmp(attributes.semantic_id, "x86.idiv") == 0))
            return execute_x86_div_intrinsic(state, id, &attributes);
    }
    if (op_v3.opcode == XAIR_OP_UNKNOWN || op_v3.opcode == XAIR_OP_UNDEF ||
        op_v3.opcode == XAIR_OP_OPAQUE_PURE || op_v3.opcode == XAIR_OP_OPAQUE_EFFECT ||
        op_v3.opcode == XAIR_OP_CALL || op_v3.opcode == XAIR_OP_INTRINSIC) {
        xair_op_attributes attributes;
        xair_sym_taint_id input_taint = XAIR_SYM_TAINT_NONE;
        uint64_t opaque_hash = UINT64_C(1469598103934665603);
        int have_attributes = xair_op_attributes_get(state->module, id, &attributes) == XAIR_OK;
        if (xair_op_inputs(state->module, id, &inputs, &input_count) != XAIR_OK) return XAIR_SYM_ERR_BAD_ARG;
        for (i = 0; i < input_count; ++i) {
            xair_sym_status taint_status = xair_sym_taint_union(state->context, input_taint,
                state->value_taints[inputs[i]], &input_taint);
            if (taint_status != XAIR_SYM_OK) return taint_status;
            if (state->defined[inputs[i]] && state->values[inputs[i]] != XAIR_SYM_INVALID_ID)
                opaque_hash = (opaque_hash ^ state->context->expressions[state->values[inputs[i]]]->hash) *
                    UINT64_C(1099511628211);
        }
        if (have_attributes && attributes.semantic_id != NULL) {
            const unsigned char *cursor = (const unsigned char *)attributes.semantic_id;
            while (*cursor != 0) opaque_hash = (opaque_hash ^ *cursor++) * UINT64_C(1099511628211);
        }
        for (i = 0; i < result_count; ++i) {
            char name[64];
            xair_type type = xair_value_type(state->module, results[i]);
            xair_sym_expr_id expr;
            xair_sym_status status;
            if (type.kind == XAIR_TYPE_MEM) {
                state->defined[results[i]] = 1;
                state->values[results[i]] = XAIR_SYM_INVALID_ID;
                continue;
            }
            if (op_v3.opcode == XAIR_OP_OPAQUE_PURE)
                (void)snprintf(name, sizeof(name), "opaque_pure_%016llx_%u",
                    (unsigned long long)opaque_hash, (unsigned)i);
            else
                (void)snprintf(name, sizeof(name), "%s_%u_%u", xair_opcode_name(op_v3.opcode),
                    (unsigned)id, (unsigned)i);
            status = xair_sym_symbol(state->context, type.bits == 0 ? 1u : type.bits, name, &expr);
            if (status != XAIR_SYM_OK) return status;
            status = xair_sym_state_set_value(state, results[i], expr);
            if (status != XAIR_SYM_OK) return status;
            if (input_taint != XAIR_SYM_TAINT_NONE) {
                xair_sym_taint_id transformed;
                status = xair_sym_taint_transform(state->context, input_taint,
                    have_attributes && attributes.semantic_id != NULL ? attributes.semantic_id :
                    xair_opcode_name(op_v3.opcode), XAIR_SYM_INVALID_ID, 0, &transformed);
                if (status == XAIR_SYM_OK) status = xair_sym_state_set_taint(state, results[i], transformed);
                if (status != XAIR_SYM_OK) return status;
            }
        }
        if (op_v3.opcode == XAIR_OP_OPAQUE_PURE || op_v3.opcode == XAIR_OP_OPAQUE_EFFECT ||
            op_v3.opcode == XAIR_OP_CALL || op_v3.opcode == XAIR_OP_INTRINSIC) {
            state->completeness = XAIR_SYM_INCOMPLETE;
            state->unresolved_operations++;
        }
        if (op_v3.opcode == XAIR_OP_OPAQUE_EFFECT || op_v3.opcode == XAIR_OP_CALL ||
            op_v3.opcode == XAIR_OP_INTRINSIC ||
            (have_attributes && (attributes.effects & XAIR_EFFECT_WRITE_MEMORY) != 0))
            xair_sym_memory_havoc(state);
        return XAIR_SYM_OK;
    }
    if (op_v3.opcode == XAIR_OP_MEMORY_BARRIER) return XAIR_SYM_OK;
    if (xair_module_get_op(state->module, id, &op) != XAIR_OK) return XAIR_SYM_ERR_BAD_ARG;
    return execute_op_view(state, id, &op);
}

static xair_sym_status transfer(xair_sym_state *state, xair_block_id target, const xair_value_id *args, size_t count) {
    xair_sym_expr_id *copies; xair_sym_taint_id *taints; size_t i; xair_value_id parameter; xair_sym_status status;
    if (xair_block_param_count(state->module, target) != count) return XAIR_SYM_ERR_BAD_ARG;
    copies = (xair_sym_expr_id *)malloc((count != 0 ? count : 1) * sizeof(*copies)); if (copies == NULL) return XAIR_SYM_ERR_OOM;
    taints = (xair_sym_taint_id *)malloc((count != 0 ? count : 1) * sizeof(*taints));
    if (taints == NULL) { free(copies); return XAIR_SYM_ERR_OOM; }
    for (i = 0; i < count; ++i) {
        if (xair_value_type(state->module, args[i]).kind == XAIR_TYPE_MEM) {
            copies[i] = XAIR_SYM_INVALID_ID; status = XAIR_SYM_OK;
        } else status = xair_sym_state_get_value(state, args[i], &copies[i]);
        taints[i] = state->value_taints[args[i]];
        if (status != XAIR_SYM_OK) { free(taints); free(copies); return status; } }
    for (i = 0; i < count; ++i) { if (xair_block_param_value(state->module, target, i, &parameter) != XAIR_OK) { free(taints); free(copies); return XAIR_SYM_ERR_BAD_ARG; }
        if (xair_value_type(state->module, parameter).kind == XAIR_TYPE_MEM) {
            state->defined[parameter] = 1; state->values[parameter] = XAIR_SYM_INVALID_ID; status = XAIR_SYM_OK;
        } else status = xair_sym_state_set_value(state, parameter, copies[i]);
        if (status == XAIR_SYM_OK) status = xair_sym_state_set_taint(state, parameter, taints[i]);
        if (status != XAIR_SYM_OK) { free(taints); free(copies); return status; } }
    free(taints); free(copies); state->block = target; state->depth++; return XAIR_SYM_OK;
}

static xair_sym_status refresh_control_taint(xair_sym_state *state) {
    xair_sym_taint_id combined = XAIR_SYM_TAINT_NONE;
    size_t read_i, write_i = 0;
    xair_sym_status status;
    if (state->control_scope_count == 0) return XAIR_SYM_OK;
    for (read_i = 0; read_i < state->control_scope_count; ++read_i) {
        if (state->control_scopes[read_i].postdominator == state->block) continue;
        state->control_scopes[write_i++] = state->control_scopes[read_i];
    }
    state->control_scope_count = write_i;
    for (read_i = 0; read_i < write_i; ++read_i) {
        status = xair_sym_taint_union(state->context, combined,
            state->control_scopes[read_i].taint, &combined);
        if (status != XAIR_SYM_OK) return status;
    }
    state->control_taint = combined;
    return XAIR_SYM_OK;
}

static xair_sym_status push_control_scope(xair_sym_state *state, xair_sym_taint_id taint) {
    xair_block_id postdominator = XAIR_INVALID_ID;
    xair_sym_taint_id implicit_taint;
    xair_sym_status transform_status;
    if (taint == XAIR_SYM_TAINT_NONE) return XAIR_SYM_OK;
    transform_status = xair_sym_taint_transform(state->context, taint,
        "control_dependency", XAIR_SYM_INVALID_ID, 1, &implicit_taint);
    if (transform_status != XAIR_SYM_OK) return transform_status;
    taint = implicit_taint;
    if (state->context->immediate_postdominators != NULL &&
        state->block < state->context->immediate_postdominator_count)
        postdominator = state->context->immediate_postdominators[state->block];
    if (postdominator == XAIR_INVALID_ID) return xair_sym_taint_union(
        state->context, state->control_taint, taint, &state->control_taint);
    if (state->control_scope_count == sizeof(state->control_scopes) / sizeof(state->control_scopes[0]))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    state->control_scopes[state->control_scope_count].postdominator = postdominator;
    state->control_scopes[state->control_scope_count].taint = taint;
    state->control_scope_count++;
    return xair_sym_taint_union(state->context, state->control_taint, taint, &state->control_taint);
}

static xair_sym_status enqueue(xair_sym_state ***queue, size_t *count, size_t *capacity, xair_sym_state *state) {
    xair_sym_state **next; size_t cap;
    if (*count == *capacity) {
        size_t additional;
        cap = *capacity == 0 ? 16 : *capacity * 2;
        if (cap < *capacity || cap > SIZE_MAX / sizeof(*next)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        additional = (cap - *capacity) * sizeof(*next);
        if (!xair_sym_parallel_memory_reserve(state->context, additional)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        next = (xair_sym_state **)realloc(*queue, cap * sizeof(*next));
        if (next == NULL) { xair_sym_parallel_memory_release(state->context, additional); return XAIR_SYM_ERR_OOM; }
        *queue = next;
        *capacity = cap;
    }
    (*queue)[(*count)++] = state;
    state->context->stats.states_queued++;
    return XAIR_SYM_OK;
}

static xair_sym_state *dequeue(
    xair_sym_state **queue,
    size_t queued,
    size_t *bfs_cursor,
    xair_sym_search_policy policy,
    const size_t *visits) {
    size_t index;
    if (policy == XAIR_SYM_SEARCH_DFS) {
        for (index = queued; index != 0; --index) {
            if (queue[index - 1] != NULL) {
                xair_sym_state *state = queue[index - 1]; queue[index - 1] = NULL; return state;
            }
        }
        return NULL;
    }
    if (policy == XAIR_SYM_SEARCH_COVERAGE) {
        for (index = *bfs_cursor; index < queued; ++index) {
            if (queue[index] != NULL && visits[queue[index]->block] == 0) {
                xair_sym_state *state = queue[index]; queue[index] = NULL; return state;
            }
        }
    }
    while (*bfs_cursor < queued) {
        index = (*bfs_cursor)++;
        if (queue[index] != NULL) { xair_sym_state *state = queue[index]; queue[index] = NULL; return state; }
    }
    return NULL;
}

typedef struct {
    xair_block_id block;
    uint64_t constraint_hash;
    uint64_t memory_hash;
    size_t value_count;
    xair_sym_expr_id *values;
    uint8_t *defined;
    xair_sym_taint_id *taints;
    xair_sym_taint_id control_taint;
    uint64_t memory_havoc_version;
    uint64_t unresolved_operations;
    xair_sym_completion_reason completeness;
    size_t control_scope_count;
    xair_block_id scope_postdominators[32];
    xair_sym_taint_id scope_taints[32];
    uint8_t terminate_requested;
    uint8_t model_output_confidence;
    size_t parallel_memory_reserved;
    xair_sym_state *exact_state;
} xair_sym_seen_state;

static int exact_constraints_equal(const xair_sym_constraint *lhs,
    const xair_sym_constraint *rhs) {
    while (lhs != NULL && rhs != NULL) {
        if (lhs->expression != rhs->expression) return 0;
        lhs = lhs->parent; rhs = rhs->parent;
    }
    return lhs == NULL && rhs == NULL;
}

static int exact_memory_equal(const xair_sym_memory *lhs, const xair_sym_memory *rhs) {
    size_t i, page_i;
    if (lhs->count != rhs->count) return 0;
    for (i = 0; i < lhs->count; ++i) {
        const xair_sym_object *lo = &lhs->objects[i], *ro = &rhs->objects[i];
        if (lo->base != ro->base || lo->size != ro->size || lo->permissions != ro->permissions ||
            lo->zero_fill != ro->zero_fill || lo->backing_size != ro->backing_size ||
            lo->page_count != ro->page_count ||
            (lo->backing_size != 0 && memcmp(lo->backing, ro->backing, lo->backing_size) != 0)) return 0;
        for (page_i = 0; page_i < lo->page_count; ++page_i) {
            const xair_sym_page *lp = lo->pages[page_i], *rp = ro->pages[page_i];
            if (lp == NULL || rp == NULL) { if (lp != rp) return 0; continue; }
            if (memcmp(lp->bytes, rp->bytes, sizeof(lp->bytes)) != 0 ||
                memcmp(lp->taints, rp->taints, sizeof(lp->taints)) != 0) return 0;
        }
    }
    return 1;
}

static uint64_t state_constraint_hash(const xair_sym_state *state) {
    const xair_sym_constraint *constraint;
    uint64_t hash = UINT64_C(1469598103934665603);
    for (constraint = state->constraints; constraint != NULL; constraint = constraint->parent)
        hash = (hash ^ state->context->expressions[constraint->expression]->hash) * UINT64_C(1099511628211);
    return hash;
}

static int state_matches_seen(const xair_sym_state *state, const xair_sym_seen_state *seen) {
    size_t i;
    if (state->block != seen->block || state_constraint_hash(state) != seen->constraint_hash ||
        xair_sym_memory_fingerprint(state->memory) != seen->memory_hash ||
        state->value_count != seen->value_count || state->control_taint != seen->control_taint ||
        state->memory_havoc_version != seen->memory_havoc_version ||
        state->unresolved_operations != seen->unresolved_operations ||
        state->completeness != seen->completeness || state->terminate_requested != seen->terminate_requested ||
        state->model_output_confidence != seen->model_output_confidence ||
        state->control_scope_count != seen->control_scope_count ||
        memcmp(state->defined, seen->defined, state->value_count) != 0 ||
        memcmp(state->value_taints, seen->taints, state->value_count * sizeof(*state->value_taints)) != 0) return 0;
    for (i = 0; i < state->value_count; ++i) {
        if (state->defined[i] && state->values[i] != seen->values[i]) return 0;
    }
    for (i = 0; i < state->control_scope_count; ++i)
        if (state->control_scopes[i].postdominator != seen->scope_postdominators[i] ||
            state->control_scopes[i].taint != seen->scope_taints[i]) return 0;
    return seen->exact_state != NULL &&
        exact_constraints_equal(state->constraints, seen->exact_state->constraints) &&
        exact_memory_equal(state->memory, seen->exact_state->memory);
}

static xair_sym_status remember_state(
    const xair_sym_state *state,
    xair_sym_seen_state **seen_states,
    size_t *seen_count,
    size_t *seen_capacity,
    int *out_duplicate) {
    size_t i;
    xair_sym_seen_state *seen;
    if (out_duplicate == NULL) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < *seen_count; ++i) {
        if (state_matches_seen(state, &(*seen_states)[i])) { *out_duplicate = 1; return XAIR_SYM_OK; }
    }
    *out_duplicate = 0;
    if (*seen_count == *seen_capacity) {
        size_t capacity = *seen_capacity == 0 ? 16 : *seen_capacity * 2;
        size_t additional;
        if (capacity < *seen_capacity || capacity > SIZE_MAX / sizeof(**seen_states))
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
        additional = (capacity - *seen_capacity) * sizeof(**seen_states);
        if (!xair_sym_parallel_memory_reserve(state->context, additional)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        xair_sym_seen_state *next = (xair_sym_seen_state *)realloc(*seen_states, capacity * sizeof(*next));
        if (next == NULL) {
            xair_sym_parallel_memory_release(state->context, additional); return XAIR_SYM_ERR_OOM;
        }
        *seen_states = next; *seen_capacity = capacity;
    }
    seen = &(*seen_states)[*seen_count]; memset(seen, 0, sizeof(*seen));
    seen->block = state->block;
    seen->constraint_hash = state_constraint_hash(state);
    seen->memory_hash = xair_sym_memory_fingerprint(state->memory);
    seen->value_count = state->value_count;
    seen->control_taint = state->control_taint;
    seen->memory_havoc_version = state->memory_havoc_version;
    seen->unresolved_operations = state->unresolved_operations;
    seen->completeness = state->completeness;
    seen->terminate_requested = state->terminate_requested;
    seen->model_output_confidence = state->model_output_confidence;
    seen->control_scope_count = state->control_scope_count;
    for (i = 0; i < state->control_scope_count; ++i) {
        seen->scope_postdominators[i] = state->control_scopes[i].postdominator;
        seen->scope_taints[i] = state->control_scopes[i].taint;
    }
    {
        size_t values = state->value_count != 0 ? state->value_count : 1u;
        size_t allocation;
        if (values > SIZE_MAX / (sizeof(*seen->values) + sizeof(*seen->defined) + sizeof(*seen->taints)))
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
        allocation = values * (sizeof(*seen->values) + sizeof(*seen->defined) + sizeof(*seen->taints));
        if (!xair_sym_parallel_memory_reserve(state->context, allocation)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        seen->values = (xair_sym_expr_id *)malloc(values * sizeof(*seen->values));
        seen->defined = (uint8_t *)malloc(values);
        seen->taints = (xair_sym_taint_id *)malloc(values * sizeof(*seen->taints));
        if (seen->values == NULL || seen->defined == NULL || seen->taints == NULL) {
            free(seen->taints); free(seen->defined); free(seen->values);
            xair_sym_parallel_memory_release(state->context, allocation); return XAIR_SYM_ERR_OOM;
        }
        seen->parallel_memory_reserved = allocation;
    }
    memcpy(seen->values, state->values, state->value_count * sizeof(*seen->values));
    memcpy(seen->defined, state->defined, state->value_count);
    memcpy(seen->taints, state->value_taints, state->value_count * sizeof(*seen->taints));
    {
        xair_sym_status clone_status = xair_sym_state_clone(state, &seen->exact_state);
        if (clone_status != XAIR_SYM_OK) {
            free(seen->taints); free(seen->defined); free(seen->values);
            xair_sym_parallel_memory_release(state->context, seen->parallel_memory_reserved);
            memset(seen, 0, sizeof(*seen)); return clone_status;
        }
    }
    (*seen_count)++;
    return XAIR_SYM_OK;
}

static void destroy_seen_states(xair_sym_context *context, xair_sym_seen_state *seen_states,
    size_t count, size_t capacity) {
    size_t i;
    for (i = 0; i < count; ++i) {
        xair_sym_state_destroy(seen_states[i].exact_state);
        free(seen_states[i].taints); free(seen_states[i].defined); free(seen_states[i].values);
        xair_sym_parallel_memory_release(context, seen_states[i].parallel_memory_reserved);
    }
    free(seen_states);
    xair_sym_parallel_memory_release(context, capacity * sizeof(*seen_states));
}

void xair_sym_explore_options_init(xair_sym_explore_options *options) {
    if (options == NULL) return;
    memset(options, 0, sizeof(*options));
    xair_analysis_options_init(&options->analysis);
    options->max_states = 100000;
    options->max_block_steps = 1000000;
    options->max_visits_per_block = 1024;
    options->max_symbolic_forks = SIZE_MAX;
    options->search = XAIR_SYM_SEARCH_COVERAGE;
    options->execution_mode = XAIR_SYM_EXEC_SYMBOLIC;
    options->cancel_token = NULL;
}

xair_sym_status xair_sym_explore_with_options_ex(xair_sym_state *initial, const xair_sym_explore_options *options,
    xair_sym_terminal_cb callback, void *user, xair_analysis_result *result, xair_diagnostic *diagnostic) {
    xair_sym_state **queue = NULL;
    size_t queued = 0, capacity = 0, cursor = 0, steps = 0, processed = 0, symbolic_forks = 0;
    size_t *visits = NULL;
    xair_sym_seen_state *seen_states = NULL;
    size_t seen_count = 0, seen_capacity = 0;
    size_t block_count;
    size_t visits_bytes;
    xair_sym_state *state = NULL;
    xair_sym_status status;
    xair_block_id trace_block = XAIR_INVALID_ID;
    size_t trace_op_index = SIZE_MAX;
    xair_opcode trace_opcode = XAIR_OP_ADD;
    int trace_opcode_valid = 0;
    uint8_t trace_in_terminator = 0u;
    uint64_t started = xair_monotonic_milliseconds();
    const xair_cancel_token *cancel_token;
    xair_analysis_options solver_analysis;
    int stopped_by_limit = 0;
    int stopped_by_cancel = 0;
    if (result != NULL) { memset(result, 0, sizeof(*result)); result->state = XAIR_ANALYSIS_FAILED; }
    xair_diagnostic_init(diagnostic);
    if (initial == NULL || options == NULL || options->max_states == 0 || options->max_block_steps == 0 ||
        options->max_visits_per_block == 0 || options->search > XAIR_SYM_SEARCH_COVERAGE ||
        options->execution_mode > XAIR_SYM_EXEC_HYBRID_CONCRETIZE) {
        xair_diagnostic_set(diagnostic, XAIR_ERR_BAD_ARG, XAIR_STAGE_SYMBOLIC, 0, 0,
            XAIR_INVALID_ID, XAIR_INVALID_ID, "invalid symbolic exploration options");
        return XAIR_SYM_ERR_BAD_ARG;
    }
    cancel_token = options->analysis.cancel_token != NULL ? options->analysis.cancel_token : options->cancel_token;
    solver_analysis = options->analysis;
    solver_analysis.cancel_token = cancel_token;
    xair_sym_context_set_analysis_options(initial->context, &solver_analysis);
    block_count = xair_module_block_count(initial->module);
    if ((block_count != 0 ? block_count : 1u) > SIZE_MAX / sizeof(*visits))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    visits_bytes = (block_count != 0 ? block_count : 1u) * sizeof(*visits);
    if (options->analysis.max_ir_values != 0 &&
        xair_module_value_count(initial->module) > options->analysis.max_ir_values) {
        if (result != NULL) { result->state = XAIR_ANALYSIS_LIMITED; result->reason = XAIR_ERR_RESOURCE_LIMIT; }
        xair_diagnostic_set(diagnostic, XAIR_ERR_RESOURCE_LIMIT, XAIR_STAGE_SYMBOLIC, 0, 0,
            initial->block, XAIR_INVALID_ID, "symbolic IR value budget exceeded");
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    if (!xair_sym_parallel_memory_reserve(initial->context, visits_bytes)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    visits = (size_t *)calloc(block_count != 0 ? block_count : 1, sizeof(*visits));
    if (visits == NULL) { xair_sym_parallel_memory_release(initial->context, visits_bytes); return XAIR_SYM_ERR_OOM; }
    status = xair_sym_state_clone(initial, &state);
    if (status != XAIR_SYM_OK) { free(visits); xair_sym_parallel_memory_release(initial->context, visits_bytes); return status; }
    state->execution_mode = options->execution_mode;
    status = enqueue(&queue, &queued, &capacity, state);
    if (status != XAIR_SYM_OK) {
        xair_sym_state_destroy(state); free(visits);
        xair_sym_parallel_memory_release(initial->context, visits_bytes); return status;
    }
    state = NULL;
    while (processed < options->max_states && steps < options->max_block_steps) {
        const xair_op_id *ops = NULL; size_t op_count, i; xair_term_view term;
        if (xair_cancel_token_requested(cancel_token)) { stopped_by_cancel = 1; break; }
        if (options->analysis.max_wall_time != 0 &&
            xair_monotonic_milliseconds() - started >= options->analysis.max_wall_time) {
            stopped_by_limit = 1; break;
        }
        if (options->analysis.max_memory != 0 &&
            (queued * sizeof(*queue) + seen_count * sizeof(*seen_states)) > options->analysis.max_memory) {
            stopped_by_limit = 1; break;
        }
        state = dequeue(queue, queued, &cursor, options->search, visits);
        if (state == NULL) break;
        if (state->context->parallel_budget != NULL && !parallel_budget_take(
            &state->context->parallel_budget->remaining_states, state->context->parallel_budget)) {
            stopped_by_limit = 1; xair_sym_state_destroy(state); state = NULL; break;
        }
        if (state->context->taint_mode == XAIR_SYM_TAINT_STRICT_IMPLICIT) {
            status = refresh_control_taint(state);
            if (status != XAIR_SYM_OK) goto fail;
        }
        processed++;
        if (options->analysis.progress_callback != NULL) {
            options->analysis.progress_callback(XAIR_STAGE_SYMBOLIC, processed,
                options->max_states, options->analysis.progress_user);
        }
        {
            int duplicate;
            status = remember_state(state, &seen_states, &seen_count, &seen_capacity, &duplicate);
            if (status != XAIR_SYM_OK) goto fail;
            if (duplicate) {
                state->context->stats.scheduler_pruned++;
                xair_sym_state_destroy(state); state = NULL; continue;
            }
        }
        if (visits[state->block] == 0 && parallel_cover_block(
            state->context->parallel_budget, state->block)) state->context->stats.coverage_blocks++;
        if (++visits[state->block] > options->max_visits_per_block) {
            state->context->stats.scheduler_pruned++;
            stopped_by_limit = 1;
            xair_sym_state_destroy(state);
            state = NULL;
            continue;
        }
        if (state->context->parallel_budget != NULL && !parallel_budget_take(
            &state->context->parallel_budget->remaining_steps, state->context->parallel_budget)) {
            stopped_by_limit = 1; xair_sym_state_destroy(state); state = NULL; break;
        }
        steps++;
        trace_block = state->block;
        trace_op_index = SIZE_MAX;
        trace_opcode_valid = 0;
        trace_in_terminator = 0u;
        if (state->program != NULL) {
            const xair_sym_compiled_block *compiled;
            if (state->block >= state->program->block_count) { status = XAIR_SYM_ERR_BAD_ARG; goto fail; }
            compiled = &state->program->blocks[state->block];
            op_count = compiled->op_count;
            for (i = 0; i < op_count; ++i) {
                trace_op_index = i;
                trace_opcode = compiled->ops[i].opcode;
                trace_opcode_valid = 1;
                status = execute_op(state, compiled->op_ids[i]);
                if (status != XAIR_SYM_OK) goto fail;
                if (state->terminate_requested) break;
            }
            trace_in_terminator = 1u;
            term = compiled->terminator;
            state->context->stats.compiled_dispatches++;
        } else {
            if (xair_block_ops(state->module, state->block, &ops, &op_count) != XAIR_OK) { status = XAIR_SYM_ERR_BAD_ARG; goto fail; }
            for (i = 0; i < op_count; ++i) {
                xair_op_view op_view;
                trace_op_index = i;
                if (xair_module_get_op(state->module, ops[i], &op_view) == XAIR_OK) {
                    trace_opcode = op_view.opcode;
                    trace_opcode_valid = 1;
                } else {
                    trace_opcode_valid = 0;
                }
                status = execute_op(state, ops[i]);
                if (status != XAIR_SYM_OK) goto fail;
                if (state->terminate_requested) break;
            }
            trace_in_terminator = 1u;
            if (xair_block_terminator(state->module, state->block, &term) != XAIR_OK) { status = XAIR_SYM_ERR_BAD_ARG; goto fail; }
        }
        if (state->completeness == XAIR_SYM_INCOMPLETE)
            initial->completeness = XAIR_SYM_INCOMPLETE;
        if (state->unresolved_operations > initial->unresolved_operations)
            initial->unresolved_operations = state->unresolved_operations;
        if (state->terminate_requested) {
            state->context->stats.states_completed++;
            if (callback != NULL) { status = callback(state, user); if (status != XAIR_SYM_OK) goto fail; }
            xair_sym_state_destroy(state); state = NULL; continue;
        }
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
            if (options->execution_mode == XAIR_SYM_EXEC_HYBRID_CONCRETIZE && symbolic_forks >= options->max_symbolic_forks) {
                uint64_t concrete;
                int take_true;
                xair_sym_expr_id chosen;
                status = xair_sym_model_u64(state, condition, &concrete);
                if (status != XAIR_SYM_OK) goto fail;
                take_true = (concrete & 1u) != 0;
                chosen = take_true ? condition : negated;
                status = xair_sym_state_assume(state, chosen);
                if (status == XAIR_SYM_OK) status = transfer(state,
                    take_true ? term.true_target : term.false_target,
                    take_true ? term.true_args : term.false_args,
                    take_true ? term.true_arg_count : term.false_arg_count);
                if (status == XAIR_SYM_OK) status = enqueue(&queue, &queued, &capacity, state);
                if (status != XAIR_SYM_OK) goto fail;
                state->context->stats.concretizations++;
                state = NULL;
                continue;
            }
            if (state->context->parallel_budget != NULL && !parallel_budget_take(
                &state->context->parallel_budget->remaining_forks, state->context->parallel_budget)) {
                stopped_by_limit = 1; xair_sym_state_destroy(state); state = NULL; break;
            }
            status = xair_sym_state_clone(state, &false_state); if (status != XAIR_SYM_OK) goto fail; state->context->stats.forks++;
            symbolic_forks++;
            if (state->context->taint_mode == XAIR_SYM_TAINT_STRICT_IMPLICIT) {
                xair_sym_taint_id branch_taint = state->value_taints[term.condition];
                status = push_control_scope(state, branch_taint);
                if (status == XAIR_SYM_OK) status = push_control_scope(false_state, branch_taint);
                if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); goto fail; }
            }
            status = xair_sym_check(state, condition, &sat);
            if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); goto fail; }
            if (sat == XAIR_SYM_SAT) {
                status = xair_sym_state_assume(state, condition);
                if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); goto fail; }
                status = transfer(state, term.true_target, term.true_args, term.true_arg_count);
                if (status == XAIR_SYM_OK) status = enqueue(&queue, &queued, &capacity, state);
                if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); goto fail; }
                state = NULL;
            } else {
                state->context->stats.states_pruned++;
                xair_sym_state_destroy(state);
                state = NULL;
            }
            status = xair_sym_check(false_state, negated, &sat);
            if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); false_state = NULL; goto fail; }
            if (sat == XAIR_SYM_SAT) {
                status = xair_sym_state_assume(false_state, negated);
                if (status != XAIR_SYM_OK) { xair_sym_state_destroy(false_state); goto fail; }
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
        if (state->completeness == XAIR_SYM_INCOMPLETE) initial->completeness = XAIR_SYM_INCOMPLETE;
        if (state->unresolved_operations > initial->unresolved_operations)
            initial->unresolved_operations = state->unresolved_operations;
        state->context->stats.states_completed++; if (callback != NULL) { status = callback(state, user); if (status != XAIR_SYM_OK) goto fail; }
        xair_sym_state_destroy(state);
        state = NULL;
    }
    if (!stopped_by_cancel && !stopped_by_limit &&
        (processed >= options->max_states || steps >= options->max_block_steps)) stopped_by_limit = 1;
    for (cursor = 0; cursor < queued; ++cursor) xair_sym_state_destroy(queue[cursor]);
    free(visits);
    xair_sym_parallel_memory_release(initial->context, visits_bytes);
    destroy_seen_states(initial->context, seen_states, seen_count, seen_capacity);
    free(queue);
    xair_sym_parallel_memory_release(initial->context, capacity * sizeof(*queue));
    if (result != NULL) {
        result->completed = processed;
        result->total = options->max_states;
        result->elapsed_ms = xair_monotonic_milliseconds() - started;
        result->state = stopped_by_cancel ? XAIR_ANALYSIS_CANCELED :
            stopped_by_limit ? XAIR_ANALYSIS_LIMITED : XAIR_ANALYSIS_COMPLETE;
        result->reason = stopped_by_cancel ? XAIR_ERR_CANCELED :
            stopped_by_limit ? XAIR_ERR_RESOURCE_LIMIT : XAIR_OK;
    }
    if (stopped_by_cancel) {
        xair_diagnostic_set(diagnostic, XAIR_ERR_CANCELED, XAIR_STAGE_SYMBOLIC, 0, 0,
            trace_block, XAIR_INVALID_ID, "symbolic exploration canceled");
        return XAIR_SYM_ERR_CANCELED;
    }
    if (stopped_by_limit) {
        xair_diagnostic_set(diagnostic, XAIR_ERR_RESOURCE_LIMIT, XAIR_STAGE_SYMBOLIC, 0, 0,
            trace_block, XAIR_INVALID_ID, "symbolic exploration limit reached");
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    return XAIR_SYM_OK;
fail:
    (void)trace_in_terminator;
    (void)trace_opcode_valid;
    (void)trace_opcode;
    xair_diagnostic_set(diagnostic,
        status == XAIR_SYM_ERR_CANCELED ? XAIR_ERR_CANCELED :
        status == XAIR_SYM_ERR_RESOURCE_LIMIT ? XAIR_ERR_RESOURCE_LIMIT : XAIR_ERR_INCOMPLETE,
        XAIR_STAGE_SYMBOLIC, 0, (uint32_t)(trace_op_index == SIZE_MAX ? 0 : trace_op_index),
        state != NULL ? state->block : trace_block, XAIR_INVALID_ID, xair_sym_status_name(status));
    if (state != NULL) {
        if (state->completeness == XAIR_SYM_INCOMPLETE)
            initial->completeness = XAIR_SYM_INCOMPLETE;
        if (state->unresolved_operations > initial->unresolved_operations)
            initial->unresolved_operations = state->unresolved_operations;
    }
    xair_sym_state_destroy(state);
    for (cursor = 0; cursor < queued; ++cursor) xair_sym_state_destroy(queue[cursor]);
    free(visits);
    xair_sym_parallel_memory_release(initial->context, visits_bytes);
    destroy_seen_states(initial->context, seen_states, seen_count, seen_capacity);
    free(queue);
    xair_sym_parallel_memory_release(initial->context, capacity * sizeof(*queue));
    if (result != NULL) {
        result->state = status == XAIR_SYM_ERR_CANCELED ? XAIR_ANALYSIS_CANCELED :
            status == XAIR_SYM_ERR_RESOURCE_LIMIT ? XAIR_ANALYSIS_LIMITED : XAIR_ANALYSIS_FAILED;
        result->reason = diagnostic != NULL ? diagnostic->status : XAIR_ERR_INCOMPLETE;
        result->elapsed_ms = xair_monotonic_milliseconds() - started;
        result->completed = processed;
        result->total = options->max_states;
    }
    return status;
}

xair_sym_status xair_sym_explore_with_options(xair_sym_state *initial, const xair_sym_explore_options *options,
    xair_sym_terminal_cb callback, void *user) {
    return xair_sym_explore_with_options_ex(initial, options, callback, user, NULL, NULL);
}

xair_sym_status xair_sym_explore_detailed(xair_sym_state *initial,
    const xair_sym_explore_options *options, xair_sym_terminal_cb callback, void *user,
    xair_sym_explore_result *result, xair_diagnostic *diagnostic) {
    xair_sym_stats before, after;
    xair_analysis_result analysis;
    xair_sym_status status;
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (diagnostic != NULL) xair_diagnostic_init(diagnostic);
    if (initial == NULL || options == NULL || result == NULL) return XAIR_SYM_ERR_BAD_ARG;
    xair_sym_context_stats(initial->context, &before);
    status = xair_sym_explore_with_options_ex(initial, options, callback, user, &analysis, diagnostic);
    xair_sym_context_stats(initial->context, &after);
    result->completion_reason = status == XAIR_SYM_ERR_RESOURCE_LIMIT ? XAIR_SYM_LIMIT_REACHED :
        status == XAIR_SYM_ERR_CANCELED ? XAIR_SYM_CANCELED :
        status != XAIR_SYM_OK ? XAIR_SYM_FAILED :
        initial->completeness == XAIR_SYM_INCOMPLETE ? XAIR_SYM_INCOMPLETE : XAIR_SYM_COMPLETED;
    result->states_processed = (size_t)analysis.completed;
    result->states_queued = after.states_queued - before.states_queued;
    result->states_pruned = (after.states_pruned - before.states_pruned) +
        (after.scheduler_pruned - before.scheduler_pruned);
    result->forks = after.forks - before.forks;
    result->solver_queries = after.solver_queries - before.solver_queries;
    result->coverage_blocks = after.coverage_blocks - before.coverage_blocks;
    result->unresolved_operations = initial->unresolved_operations;
    result->limits_reached = status == XAIR_SYM_ERR_RESOURCE_LIMIT ? 1 : 0;
    result->terminal_states = after.states_completed - before.states_completed;
    result->duplicate_terminal_states = after.terminal_duplicates - before.terminal_duplicates;
    return status;
}

xair_sym_status xair_sym_explore(xair_sym_state *initial, size_t max_states, size_t max_steps,
    xair_sym_terminal_cb callback, void *user) {
    xair_sym_explore_options options;
    xair_sym_explore_options_init(&options);
    options.max_states = max_states;
    options.max_block_steps = max_steps;
    return xair_sym_explore_with_options(initial, &options, callback, user);
}
