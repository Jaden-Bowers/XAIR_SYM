#include "xair_sym/xair_sym.h"

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

int main(void) {
    xair_module *module = NULL;
    xair_block_id entry = XAIR_INVALID_ID;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_expr_id symbol = XAIR_SYM_INVALID_ID;
    xair_sym_expr_id constant = XAIR_SYM_INVALID_ID;
    xair_sym_expr_id condition = XAIR_SYM_INVALID_ID;
    xair_sym_sat sat = XAIR_SYM_UNKNOWN;

    CHECK(xair_sym_context_solver_initialized(NULL) == 0);
    CHECK(xair_module_create(&module) == XAIR_OK);
    CHECK(xair_block_create(module, "entry", &entry) == XAIR_OK);
    CHECK(xair_set_return(module, entry, NULL, 0) == XAIR_OK);
    CHECK(xair_sym_context_create(&context) == XAIR_SYM_OK);
    CHECK(xair_sym_context_solver_initialized(context) == 0);
    CHECK(xair_sym_state_create(context, module, entry, &state) == XAIR_SYM_OK);
    CHECK(xair_sym_symbol(context, 8, "input", &symbol) == XAIR_SYM_OK);
    CHECK(xair_sym_const(context, 8, 7, &constant) == XAIR_SYM_OK);
    CHECK(xair_sym_binary(
              context, XAIR_OP_EQ, 1, symbol, constant, &condition) ==
          XAIR_SYM_OK);
    CHECK(xair_sym_state_assume(state, condition) == XAIR_SYM_OK);
    CHECK(xair_sym_context_solver_initialized(context) == 0);

    CHECK(xair_sym_check(state, XAIR_SYM_INVALID_ID, &sat) == XAIR_SYM_OK);
    CHECK(sat == XAIR_SYM_SAT);
    CHECK(xair_sym_context_solver_initialized(context) != 0);

    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
    return 0;
}
