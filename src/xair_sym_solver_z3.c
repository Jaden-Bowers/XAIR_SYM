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

static Z3_ast translate(z3_translation *t, xair_sym_expr_id id) {
    const xair_sym_expr *expr;
    Z3_sort sort;
    Z3_ast ast;
    if (id >= t->source->expression_count) return NULL;
    if (t->defined[id]) return t->cache[id];
    expr = t->source->expressions[id]; sort = Z3_mk_bv_sort(t->context, expr->bits);
    if (expr->kind == XAIR_SYM_EXPR_CONST) ast = Z3_mk_unsigned_int64(t->context, expr->immediate, sort);
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
    if (state == NULL || out_sat == NULL) return XAIR_SYM_ERR_BAD_ARG;
    config = Z3_mk_config(); context = Z3_mk_context(config); Z3_del_config(config);
    if (context == NULL) return XAIR_SYM_ERR_SOLVER;
    memset(&translation, 0, sizeof(translation)); translation.source = state->context; translation.context = context;
    translation.cache = (Z3_ast *)calloc(state->context->expression_count, sizeof(*translation.cache));
    translation.defined = (uint8_t *)calloc(state->context->expression_count, 1);
    if (translation.cache == NULL || translation.defined == NULL) { status = XAIR_SYM_ERR_OOM; goto done; }
    solver = Z3_mk_solver(context); Z3_solver_inc_ref(context, solver);
    for (constraint_node = state->constraints; constraint_node != NULL; constraint_node = constraint_node->parent) {
        Z3_ast constraint = translate(&translation, constraint_node->expression);
        if (constraint == NULL) { status = XAIR_SYM_ERR_UNSUPPORTED; goto solver_done; }
        Z3_solver_assert(context, solver, as_bool(context, constraint));
    }
    if (extra != XAIR_SYM_INVALID_ID) {
        Z3_ast condition = translate(&translation, extra);
        if (condition == NULL) { status = XAIR_SYM_ERR_UNSUPPORTED; goto solver_done; }
        Z3_solver_assert(context, solver, as_bool(context, condition));
    }
    state->context->stats.solver_queries++; checked = Z3_solver_check(context, solver);
    if (checked == Z3_L_TRUE) { *out_sat = XAIR_SYM_SAT; state->context->stats.solver_sat++; }
    else if (checked == Z3_L_FALSE) { *out_sat = XAIR_SYM_UNSAT; state->context->stats.solver_unsat++; }
    else *out_sat = XAIR_SYM_UNKNOWN;
    if (out_model != NULL && model_symbol != XAIR_SYM_INVALID_ID && checked == Z3_L_TRUE) {
        Z3_model model = Z3_solver_get_model(context, solver); Z3_ast symbol = translate(&translation, model_symbol); Z3_ast value;
        Z3_model_inc_ref(context, model);
        if (symbol == NULL || !Z3_model_eval(context, model, symbol, true, &value) ||
            !Z3_get_numeral_uint64(context, value, out_model)) status = XAIR_SYM_ERR_SOLVER;
        Z3_model_dec_ref(context, model);
    }
solver_done:
    Z3_solver_dec_ref(context, solver);
done:
    free(translation.defined); free(translation.cache); Z3_del_context(context); return status;
}

xair_sym_status xair_sym_check(xair_sym_state *state, xair_sym_expr_id extra, xair_sym_sat *out_sat) {
    return xair_sym_solver_check(state, extra, out_sat, XAIR_SYM_INVALID_ID, NULL);
}

xair_sym_status xair_sym_model_u64(xair_sym_state *state, xair_sym_expr_id symbol, uint64_t *out_value) {
    xair_sym_sat sat;
    xair_sym_status status;
    if (out_value == NULL) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_solver_check(state, XAIR_SYM_INVALID_ID, &sat, symbol, out_value);
    if (status != XAIR_SYM_OK) return status;
    return sat == XAIR_SYM_SAT ? XAIR_SYM_OK : XAIR_SYM_ERR_INFEASIBLE;
}
