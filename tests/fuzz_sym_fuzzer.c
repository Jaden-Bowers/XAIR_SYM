#include "xair_sym/xair_sym.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const xair_opcode operations[] = {
        XAIR_OP_ADD, XAIR_OP_SUB, XAIR_OP_MUL, XAIR_OP_AND,
        XAIR_OP_OR, XAIR_OP_XOR, XAIR_OP_SHL, XAIR_OP_LSHR
    };
    xair_module *module = NULL;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_expr_id values[64], symbols[8];
    xair_analysis_options limits;
    xair_block_id block;
    uint64_t sample = UINT64_C(1469598103934665603);
    size_t value_count = 0, symbol_count = 0, cursor = 0, i;
    uint8_t modeled[8];
    if (size > 4096) return 0;
    for (i = 0; i < size; ++i) sample = (sample ^ data[i]) * UINT64_C(1099511628211);
    if (xair_module_create(&module) != XAIR_OK ||
        xair_block_create(module, "fuzz", &block) != XAIR_OK ||
        xair_set_return(module, block, NULL, 0) != XAIR_OK ||
        xair_sym_context_create(&context) != XAIR_SYM_OK ||
        xair_sym_state_create(context, module, block, &state) != XAIR_SYM_OK)
        goto done;
    xair_analysis_options_init(&limits);
    limits.max_memory = 64u * 1024u * 1024u;
    limits.max_wall_time = 10;
    xair_sym_context_set_analysis_options(context, &limits);
    while (cursor < size && symbol_count < sizeof(symbols) / sizeof(symbols[0])) {
        char name[2] = {(char)('a' + symbol_count), '\0'};
        if (xair_sym_symbol(context, 8, name, &symbols[symbol_count]) != XAIR_SYM_OK) goto done;
        values[value_count++] = symbols[symbol_count++];
        cursor++;
    }
    while (cursor + 2 < size && value_count < sizeof(values) / sizeof(values[0])) {
        xair_sym_expr_id result;
        xair_opcode opcode = operations[data[cursor] % (sizeof(operations) / sizeof(operations[0]))];
        xair_sym_expr_id lhs = values[data[cursor + 1] % value_count];
        xair_sym_expr_id rhs = values[data[cursor + 2] % value_count];
        if (xair_sym_binary(context, opcode, 8, lhs, rhs, &result) == XAIR_SYM_OK)
            values[value_count++] = result;
        cursor += 3;
    }
    /* Solver checks are intentionally sampled: libFuzzer must still sustain a
     * useful execution rate while exercising translation and model extraction. */
    if (symbol_count != 0 && (sample & 127u) == 0)
        (void)xair_sym_model_bytes(state, symbols, symbol_count, modeled);
done:
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
    return 0;
}
