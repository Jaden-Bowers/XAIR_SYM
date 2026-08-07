#include "xair_sym_internal.h"

#include <stdlib.h>
#include <string.h>
#include <z3.h>

typedef struct {
    xair_sym_context *source;
    Z3_context context;
    Z3_ast *cache;
    uint8_t *defined;
} z3_translation;

typedef struct {
    Z3_context context;
    const xair_cancel_token *token;
    xair_atomic_bool finished;
} z3_cancel_monitor;

static int monitor_solver_cancellation(void *opaque) {
    z3_cancel_monitor *monitor = (z3_cancel_monitor *)opaque;
    while (!xair_atomic_bool_load(&monitor->finished)) {
        if (xair_cancel_token_requested(monitor->token)) {
            Z3_interrupt(monitor->context);
            break;
        }
        xair_sleep_milliseconds(1);
    }
    return 0;
}

static uint64_t query_mix(uint64_t hash, uint64_t value) {
    return hash ^ (value + UINT64_C(0x9e3779b97f4a7c15) + (hash << 6u) + (hash >> 2u));
}

static uint64_t query_dependencies(xair_sym_state *state, xair_sym_expr_id extra) {
    uint64_t dependencies = extra == XAIR_SYM_INVALID_ID ? UINT64_MAX : state->context->expressions[extra]->dependencies;
    uint64_t previous;
    do {
        xair_sym_constraint *constraint;
        previous = dependencies;
        for (constraint = state->constraints; constraint != NULL; constraint = constraint->parent) {
            uint64_t current = state->context->expressions[constraint->expression]->dependencies;
            if (current == 0 || (current & dependencies) != 0) dependencies |= current;
        }
    } while (dependencies != previous);
    return dependencies;
}

static int constraint_selected(xair_sym_state *state, xair_sym_constraint *constraint, uint64_t dependencies) {
    uint64_t current = state->context->expressions[constraint->expression]->dependencies;
    return dependencies == UINT64_MAX || current == 0 || (current & dependencies) != 0;
}

static uint64_t query_key(xair_sym_state *state, xair_sym_expr_id extra, uint64_t dependencies) {
    xair_sym_constraint *constraint;
    uint64_t key = UINT64_C(0x5841495251554552);
    key = query_mix(key, extra == XAIR_SYM_INVALID_ID ? UINT64_MAX : state->context->expressions[extra]->hash);
    for (constraint = state->constraints; constraint != NULL; constraint = constraint->parent) {
        if (constraint_selected(state, constraint, dependencies)) {
            key = query_mix(key, state->context->expressions[constraint->expression]->hash);
        }
    }
    return key == 0 ? 1 : key;
}

static int query_cache_lookup(xair_sym_context *context, uint64_t key, uint64_t identity,
    xair_sym_expr_id extra, xair_sym_sat *out_result) {
    size_t slot;
    if (context->query_cache_capacity == 0) return 0;
    slot = (size_t)(key & (context->query_cache_capacity - 1));
    while (context->query_cache[slot].used) {
        if (context->query_cache[slot].key == key && context->query_cache[slot].constraint_identity == identity &&
            context->query_cache[slot].extra == extra) { *out_result = context->query_cache[slot].result; return 1; }
        slot = (slot + 1) & (context->query_cache_capacity - 1);
    }
    return 0;
}

static xair_sym_status query_cache_rebuild(xair_sym_context *context, size_t capacity) {
    xair_sym_query_cache_entry *entries = (xair_sym_query_cache_entry *)calloc(capacity, sizeof(*entries));
    size_t i;
    if (entries == NULL) return XAIR_SYM_ERR_OOM;
    for (i = 0; i < context->query_cache_capacity; ++i) {
        if (context->query_cache[i].used) {
            size_t slot = (size_t)(context->query_cache[i].key & (capacity - 1));
            while (entries[slot].used) slot = (slot + 1) & (capacity - 1);
            entries[slot] = context->query_cache[i];
        }
    }
    free(context->query_cache); context->query_cache = entries; context->query_cache_capacity = capacity;
    return XAIR_SYM_OK;
}

static xair_sym_status query_cache_insert(xair_sym_context *context, uint64_t key, uint64_t identity,
    xair_sym_expr_id extra, xair_sym_sat result) {
    size_t slot;
    xair_sym_status status;
    if (result == XAIR_SYM_UNKNOWN) return XAIR_SYM_OK;
    if (context->query_cache_capacity == 0 || (context->query_cache_count + 1) * 10 >= context->query_cache_capacity * 7) {
        status = query_cache_rebuild(context, context->query_cache_capacity == 0 ? 64 : context->query_cache_capacity * 2);
        if (status != XAIR_SYM_OK) return status;
    }
    slot = (size_t)(key & (context->query_cache_capacity - 1));
    while (context->query_cache[slot].used && (context->query_cache[slot].key != key ||
        context->query_cache[slot].constraint_identity != identity || context->query_cache[slot].extra != extra)) {
        slot = (slot + 1) & (context->query_cache_capacity - 1);
    }
    if (!context->query_cache[slot].used) context->query_cache_count++;
    context->query_cache[slot].used = 1; context->query_cache[slot].key = key;
    context->query_cache[slot].constraint_identity = identity; context->query_cache[slot].extra = extra;
    context->query_cache[slot].result = result;
    return XAIR_SYM_OK;
}

static Z3_ast translate(z3_translation *translation, xair_sym_expr_id id);

static Z3_ast bv1_from_bool(Z3_context context, Z3_ast condition) {
    Z3_sort sort = Z3_mk_bv_sort(context, 1);
    Z3_ast one = Z3_mk_unsigned_int64(context, 1, sort);
    Z3_ast zero = Z3_mk_unsigned_int64(context, 0, sort);
    return Z3_mk_ite(context, condition, one, zero);
}

static Z3_ast as_bool(Z3_context context, Z3_ast value) {
    Z3_sort sort = Z3_mk_bv_sort(context, 1);
    return Z3_mk_eq(context, value, Z3_mk_unsigned_int64(context, 1, sort));
}

static Z3_ast translate_flag_zf(z3_translation *translation, const xair_sym_expr *extract) {
    const xair_sym_expr *flags = translation->source->expressions[extract->args[0]];
    Z3_ast result;
    Z3_ast zero;
    Z3_sort sort;

    if (flags->kind != XAIR_SYM_EXPR_XAIR || flags->arg_count == 0) return NULL;
    if (flags->opcode == XAIR_OP_FLAGS_LOGIC) {
        result = translate(translation, flags->args[0]);
    } else if (flags->opcode == XAIR_OP_FLAGS_ADD || flags->opcode == XAIR_OP_FLAGS_SUB) {
        Z3_ast args[2]; args[0] = translate(translation, flags->args[0]); args[1] = translate(translation, flags->args[1]);
        if (args[0] == NULL || args[1] == NULL) return NULL;
        result = flags->opcode == XAIR_OP_FLAGS_ADD ? Z3_mk_bvadd(translation->context, args[0], args[1]) :
            Z3_mk_bvsub(translation->context, args[0], args[1]);
    } else {
        return NULL;
    }
    if (result == NULL) return NULL;
    sort = Z3_get_sort(translation->context, result);
    zero = Z3_mk_unsigned_int64(translation->context, 0, sort);
    return bv1_from_bool(translation->context, Z3_mk_eq(translation->context, result, zero));
}

static Z3_ast translate_xair(z3_translation *t, const xair_sym_expr *expr) {
    Z3_ast a = expr->arg_count > 0 ? translate(t, expr->args[0]) : NULL;
    Z3_ast b = expr->arg_count > 1 ? translate(t, expr->args[1]) : NULL;
    Z3_ast c = expr->arg_count > 2 ? translate(t, expr->args[2]) : NULL;
    uint16_t src_bits = expr->arg_count > 0 ? t->source->expressions[expr->args[0]]->bits : 0;
    switch (expr->opcode) {
    case XAIR_OP_ADD: return Z3_mk_bvadd(t->context, a, b);
    case XAIR_OP_SUB: return Z3_mk_bvsub(t->context, a, b);
    case XAIR_OP_MUL: return Z3_mk_bvmul(t->context, a, b);
    case XAIR_OP_UDIV: return Z3_mk_bvudiv(t->context, a, b);
    case XAIR_OP_SDIV: return Z3_mk_bvsdiv(t->context, a, b);
    case XAIR_OP_UREM: return Z3_mk_bvurem(t->context, a, b);
    case XAIR_OP_SREM: return Z3_mk_bvsrem(t->context, a, b);
    case XAIR_OP_AND: return Z3_mk_bvand(t->context, a, b);
    case XAIR_OP_OR: return Z3_mk_bvor(t->context, a, b);
    case XAIR_OP_XOR: return Z3_mk_bvxor(t->context, a, b);
    case XAIR_OP_SHL: return Z3_mk_bvshl(t->context, a, b);
    case XAIR_OP_LSHR: return Z3_mk_bvlshr(t->context, a, b);
    case XAIR_OP_ASHR: return Z3_mk_bvashr(t->context, a, b);
    case XAIR_OP_ROL: return Z3_mk_ext_rotate_left(t->context, a, b);
    case XAIR_OP_ROR: return Z3_mk_ext_rotate_right(t->context, a, b);
    case XAIR_OP_EQ: return bv1_from_bool(t->context, Z3_mk_eq(t->context, a, b));
    case XAIR_OP_NE: return bv1_from_bool(t->context, Z3_mk_not(t->context, Z3_mk_eq(t->context, a, b)));
    case XAIR_OP_ULT: return bv1_from_bool(t->context, Z3_mk_bvult(t->context, a, b));
    case XAIR_OP_ULE: return bv1_from_bool(t->context, Z3_mk_bvule(t->context, a, b));
    case XAIR_OP_SLT: return bv1_from_bool(t->context, Z3_mk_bvslt(t->context, a, b));
    case XAIR_OP_SLE: return bv1_from_bool(t->context, Z3_mk_bvsle(t->context, a, b));
    case XAIR_OP_ZEXT: return Z3_mk_zero_ext(t->context, expr->bits - src_bits, a);
    case XAIR_OP_SEXT: return Z3_mk_sign_ext(t->context, expr->bits - src_bits, a);
    case XAIR_OP_TRUNC: return Z3_mk_extract(t->context, expr->bits - 1, 0, a);
    case XAIR_OP_EXTRACT: return Z3_mk_extract(t->context,
        (unsigned)(expr->immediate + expr->bits - 1), (unsigned)expr->immediate, a);
    case XAIR_OP_CONCAT: return Z3_mk_concat(t->context, a, b);
    case XAIR_OP_SELECT: return Z3_mk_ite(t->context, as_bool(t->context, a), b, c);
    case XAIR_OP_ADDR_ADD:
    case XAIR_OP_ADDR_SUB:
        return expr->opcode == XAIR_OP_ADDR_ADD ? Z3_mk_bvadd(t->context, a, b) : Z3_mk_bvsub(t->context, a, b);
    case XAIR_OP_INT_TO_ADDR:
    case XAIR_OP_ADDR_TO_INT: return a;
    case XAIR_OP_FLAG_ZF: return translate_flag_zf(t, expr);
    default: return NULL;
    }
}

static Z3_ast translate_constant(z3_translation *translation, const xair_sym_expr *expr, Z3_sort sort) {
    if (expr->bits <= 64) return Z3_mk_unsigned_int64(translation->context, expr->immediate, sort);
    {
        Z3_sort high_sort = Z3_mk_bv_sort(translation->context, expr->bits - 64u);
        Z3_sort low_sort = Z3_mk_bv_sort(translation->context, 64u);
        Z3_ast high = Z3_mk_unsigned_int64(translation->context, expr->immediate_hi, high_sort);
        Z3_ast low = Z3_mk_unsigned_int64(translation->context, expr->immediate, low_sort);
        return Z3_mk_concat(translation->context, high, low);
    }
}

static Z3_ast translate(z3_translation *t, xair_sym_expr_id id) {
    const xair_sym_expr *expr;
    Z3_sort sort;
    Z3_ast ast;
    if (id >= t->source->expression_count) return NULL;
    if (t->defined[id]) return t->cache[id];
    expr = t->source->expressions[id]; sort = Z3_mk_bv_sort(t->context, expr->bits);
    if (expr->kind == XAIR_SYM_EXPR_CONST) ast = translate_constant(t, expr, sort);
    else if (expr->kind == XAIR_SYM_EXPR_SYMBOL) ast = Z3_mk_const(t->context,
        Z3_mk_string_symbol(t->context, expr->symbol), sort);
    else ast = translate_xair(t, expr);
    if (ast != NULL) { t->cache[id] = ast; t->defined[id] = 1; }
    return ast;
}

xair_sym_status xair_sym_solver_check(xair_sym_state *state, xair_sym_expr_id extra,
    xair_sym_sat *out_sat, xair_sym_expr_id model_symbol, uint64_t *out_model) {
    Z3_config config; Z3_context context; Z3_solver solver; Z3_lbool checked;
    z3_translation translation; xair_sym_constraint *constraint_node; xair_sym_status status = XAIR_SYM_OK;
    z3_cancel_monitor monitor;
    xair_thread monitor_thread;
    int monitor_started = 0;
    uint64_t dependencies;
    uint64_t cache_key;
    if (state == NULL || out_sat == NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (xair_cancel_token_requested(state->context->analysis.cancel_token)) return XAIR_SYM_ERR_CANCELED;
    if (extra != XAIR_SYM_INVALID_ID && extra >= state->context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    dependencies = query_dependencies(state, extra);
    cache_key = query_key(state, extra, dependencies);
    if (out_model == NULL && query_cache_lookup(state->context, cache_key,
        state->constraints == NULL ? 0 : state->constraints->identity, extra, out_sat)) {
        state->context->stats.solver_cache_hits++;
        return XAIR_SYM_OK;
    }
    config = Z3_mk_config(); context = Z3_mk_context(config); Z3_del_config(config);
    if (context == NULL) return XAIR_SYM_ERR_SOLVER;
    memset(&translation, 0, sizeof(translation)); translation.source = state->context; translation.context = context;
    translation.cache = (Z3_ast *)calloc(state->context->expression_count, sizeof(*translation.cache));
    translation.defined = (uint8_t *)calloc(state->context->expression_count, 1);
    if (translation.cache == NULL || translation.defined == NULL) { status = XAIR_SYM_ERR_OOM; goto done; }
    solver = Z3_mk_solver(context); Z3_solver_inc_ref(context, solver);
    if (state->context->analysis.max_wall_time != 0) {
        Z3_params params = Z3_mk_params(context);
        unsigned timeout = state->context->analysis.max_wall_time > UINT32_MAX ?
            UINT32_MAX : (unsigned)state->context->analysis.max_wall_time;
        Z3_params_inc_ref(context, params);
        Z3_params_set_uint(context, params, Z3_mk_string_symbol(context, "timeout"), timeout);
        Z3_solver_set_params(context, solver, params);
        Z3_params_dec_ref(context, params);
    }
    for (constraint_node = state->constraints; constraint_node != NULL; constraint_node = constraint_node->parent) {
        if (!constraint_selected(state, constraint_node, dependencies)) {
            state->context->stats.constraints_sliced++;
            continue;
        }
        Z3_ast constraint = translate(&translation, constraint_node->expression);
        if (constraint == NULL) { status = XAIR_SYM_ERR_UNSUPPORTED; goto solver_done; }
        Z3_solver_assert(context, solver, as_bool(context, constraint));
        state->context->stats.constraints_submitted++;
    }
    if (extra != XAIR_SYM_INVALID_ID) {
        Z3_ast condition = translate(&translation, extra);
        if (condition == NULL) { status = XAIR_SYM_ERR_UNSUPPORTED; goto solver_done; }
        Z3_solver_assert(context, solver, as_bool(context, condition));
    }
    if (state->context->analysis.cancel_token != NULL) {
        monitor.context = context;
        monitor.token = state->context->analysis.cancel_token;
        xair_atomic_bool_init(&monitor.finished, 0);
        if (!xair_thread_create(&monitor_thread, monitor_solver_cancellation, &monitor)) {
            status = XAIR_SYM_ERR_INTERNAL;
            goto solver_done;
        }
        monitor_started = 1;
    }
    state->context->stats.solver_queries++;
    checked = Z3_solver_check(context, solver);
    if (monitor_started) {
        int ignored;
        xair_atomic_bool_store(&monitor.finished, 1);
        (void)xair_thread_join(&monitor_thread, &ignored);
        monitor_started = 0;
    }
    if (xair_cancel_token_requested(state->context->analysis.cancel_token)) {
        status = XAIR_SYM_ERR_CANCELED;
        goto solver_done;
    }
    if (checked == Z3_L_TRUE) { *out_sat = XAIR_SYM_SAT; state->context->stats.solver_sat++; }
    else if (checked == Z3_L_FALSE) { *out_sat = XAIR_SYM_UNSAT; state->context->stats.solver_unsat++; }
    else {
        const char *reason = Z3_solver_get_reason_unknown(context, solver);
        *out_sat = XAIR_SYM_UNKNOWN;
        status = reason != NULL && strstr(reason, "timeout") != NULL ?
            XAIR_SYM_ERR_SOLVER_TIMEOUT : XAIR_SYM_ERR_SOLVER_UNKNOWN;
        goto solver_done;
    }
    if (xair_cancel_token_requested(state->context->analysis.cancel_token)) {
        status = XAIR_SYM_ERR_CANCELED;
        goto solver_done;
    }
    if (out_model == NULL) {
        status = query_cache_insert(state->context, cache_key,
            state->constraints == NULL ? 0 : state->constraints->identity, extra, *out_sat);
        if (status != XAIR_SYM_OK) goto solver_done;
    }
    if (out_model != NULL && model_symbol != XAIR_SYM_INVALID_ID && checked == Z3_L_TRUE) {
        Z3_model model = Z3_solver_get_model(context, solver); Z3_ast symbol = translate(&translation, model_symbol); Z3_ast value;
        Z3_model_inc_ref(context, model);
        if (symbol == NULL || !Z3_model_eval(context, model, symbol, true, &value) ||
            !Z3_get_numeral_uint64(context, value, out_model)) status = XAIR_SYM_ERR_SOLVER;
        Z3_model_dec_ref(context, model);
    }
solver_done:
    if (monitor_started) {
        int ignored;
        xair_atomic_bool_store(&monitor.finished, 1);
        (void)xair_thread_join(&monitor_thread, &ignored);
    }
    Z3_solver_dec_ref(context, solver);
done:
    free(translation.defined); free(translation.cache); Z3_del_context(context); return status;
}

xair_sym_status xair_sym_check(xair_sym_state *state, xair_sym_expr_id extra, xair_sym_sat *out_sat) {
    return xair_sym_solver_check(state, extra, out_sat, XAIR_SYM_INVALID_ID, NULL);
}

xair_sym_status xair_sym_check_ex(
    xair_sym_state *state,
    xair_sym_expr_id extra,
    xair_sym_sat *out_sat,
    xair_diagnostic *diagnostic) {
    xair_sym_status status;
    xair_diagnostic_init(diagnostic);
    status = xair_sym_solver_check(state, extra, out_sat, XAIR_SYM_INVALID_ID, NULL);
    if (status != XAIR_SYM_OK) {
        xair_status reason = status == XAIR_SYM_ERR_CANCELED ? XAIR_ERR_CANCELED :
            status == XAIR_SYM_ERR_SOLVER_TIMEOUT ? XAIR_ERR_SOLVER_TIMEOUT :
            status == XAIR_SYM_ERR_SOLVER_UNKNOWN ? XAIR_ERR_SOLVER_UNKNOWN : XAIR_ERR_INCOMPLETE;
        xair_diagnostic_set(diagnostic, reason, XAIR_STAGE_SOLVER, 0, 0,
            state == NULL ? XAIR_INVALID_ID : state->block, XAIR_INVALID_ID,
            xair_sym_status_name(status));
    }
    return status;
}

xair_sym_status xair_sym_model_u64(xair_sym_state *state, xair_sym_expr_id symbol, uint64_t *out_value) {
    xair_sym_sat sat;
    xair_sym_status status;
    uint64_t identity;
    size_t i;
    if (state == NULL || out_value == NULL || symbol >= state->context->expression_count) return XAIR_SYM_ERR_BAD_ARG;
    identity = state->constraints == NULL ? 0 : state->constraints->identity;
    for (i = 0; i < state->context->model_cache_count; ++i) {
        xair_sym_model_cache_entry *entry = &state->context->model_cache[i];
        if (entry->constraint_identity == identity && entry->symbol == symbol) {
            *out_value = entry->value;
            state->context->stats.model_cache_hits++;
            return XAIR_SYM_OK;
        }
    }
    status = xair_sym_solver_check(state, XAIR_SYM_INVALID_ID, &sat, symbol, out_value);
    if (status != XAIR_SYM_OK) return status;
    if (sat != XAIR_SYM_SAT) return XAIR_SYM_ERR_INFEASIBLE;
    if (state->context->model_cache_count == state->context->model_cache_capacity) {
        size_t capacity = state->context->model_cache_capacity == 0 ? 16 : state->context->model_cache_capacity * 2;
        xair_sym_model_cache_entry *entries = (xair_sym_model_cache_entry *)realloc(
            state->context->model_cache, capacity * sizeof(*entries));
        if (entries == NULL) return XAIR_SYM_ERR_OOM;
        state->context->model_cache = entries;
        state->context->model_cache_capacity = capacity;
    }
    state->context->model_cache[state->context->model_cache_count].constraint_identity = identity;
    state->context->model_cache[state->context->model_cache_count].symbol = symbol;
    state->context->model_cache[state->context->model_cache_count].value = *out_value;
    state->context->model_cache_count++;
    return XAIR_SYM_OK;
}
