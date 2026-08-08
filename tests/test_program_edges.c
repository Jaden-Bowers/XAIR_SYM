#include "xair_sym/xair_sym.h"

#include <assert.h>

int main(void) {
    xair_module *empty = NULL, *other = NULL;
    xair_block_id block;
    xair_sym_program *program = NULL;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_opcode_capability capability;
    assert(xair_sym_program_compile(NULL, &program) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_module_create(&empty) == XAIR_OK);
    assert(xair_sym_program_compile(empty, &program) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_module_freeze(empty) == XAIR_OK);
    assert(xair_sym_program_compile(empty, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_program_compile(empty, &program) == XAIR_SYM_OK);
    xair_sym_program_destroy(NULL);
    assert(xair_sym_state_attach_program(NULL, program) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_module_create(&other) == XAIR_OK);
    assert(xair_block_create(other, "other", &block) == XAIR_OK);
    assert(xair_set_return(other, block, NULL, 0) == XAIR_OK);
    assert(xair_module_freeze(other) == XAIR_OK);
    assert(xair_sym_context_create(&context) == XAIR_SYM_OK);
    assert(xair_sym_state_create(context, other, block, &state) == XAIR_SYM_OK);
    assert(xair_sym_state_attach_program(state, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_state_attach_program(state, program) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_opcode_capability_get(0, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_opcode_capability_get(xair_sym_opcode_capability_count(), &capability) == XAIR_SYM_ERR_BAD_ARG);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context);
    xair_module_destroy(other); xair_sym_program_destroy(program); xair_module_destroy(empty);
    return 0;
}
