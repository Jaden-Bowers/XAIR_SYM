#include "xair_sym_internal.h"

#include <stdlib.h>

xair_sym_status xair_sym_program_compile(const xair_module *module, xair_sym_program **out_program) {
    xair_sym_program *program;
    size_t block_i;
    if (module == NULL || out_program == NULL || !xair_module_is_frozen(module)) return XAIR_SYM_ERR_BAD_ARG;
    program = (xair_sym_program *)calloc(1, sizeof(*program));
    if (program == NULL) return XAIR_SYM_ERR_OOM;
    program->module = module;
    program->block_count = xair_module_block_count(module);
    program->blocks = (xair_sym_compiled_block *)calloc(
        program->block_count != 0 ? program->block_count : 1, sizeof(*program->blocks));
    if (program->blocks == NULL) { free(program); return XAIR_SYM_ERR_OOM; }
    for (block_i = 0; block_i < program->block_count; ++block_i) {
        const xair_op_id *ops;
        size_t op_count;
        size_t op_i;
        if (xair_block_ops(module, (xair_block_id)block_i, &ops, &op_count) != XAIR_OK ||
            xair_block_terminator(module, (xair_block_id)block_i, &program->blocks[block_i].terminator) != XAIR_OK) {
            xair_sym_program_destroy(program); return XAIR_SYM_ERR_BAD_ARG;
        }
        program->blocks[block_i].op_count = op_count;
        if (op_count == 0) continue;
        program->blocks[block_i].ops = (xair_op_view *)malloc(op_count * sizeof(*program->blocks[block_i].ops));
        if (program->blocks[block_i].ops == NULL) { xair_sym_program_destroy(program); return XAIR_SYM_ERR_OOM; }
        for (op_i = 0; op_i < op_count; ++op_i) {
            if (xair_module_get_op(module, ops[op_i], &program->blocks[block_i].ops[op_i]) != XAIR_OK) {
                xair_sym_program_destroy(program); return XAIR_SYM_ERR_BAD_ARG;
            }
        }
    }
    *out_program = program;
    return XAIR_SYM_OK;
}

void xair_sym_program_destroy(xair_sym_program *program) {
    size_t i;
    if (program == NULL) return;
    for (i = 0; i < program->block_count; ++i) free(program->blocks[i].ops);
    free(program->blocks); free(program);
}

xair_sym_status xair_sym_state_attach_program(xair_sym_state *state, const xair_sym_program *program) {
    if (state == NULL || program == NULL || state->module != program->module) return XAIR_SYM_ERR_BAD_ARG;
    state->program = program;
    return XAIR_SYM_OK;
}
