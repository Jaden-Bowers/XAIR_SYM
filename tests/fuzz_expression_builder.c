#include "xair_sym/xair_sym.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const xair_opcode binary_ops[] = {
        XAIR_OP_ADD, XAIR_OP_SUB, XAIR_OP_MUL, XAIR_OP_AND, XAIR_OP_OR, XAIR_OP_XOR,
        XAIR_OP_SHL, XAIR_OP_LSHR, XAIR_OP_ASHR, XAIR_OP_EQ, XAIR_OP_ULT, XAIR_OP_SLT
    };
    xair_sym_context *context = NULL;
    xair_sym_expr_id values[256];
    size_t count = 0, cursor = 0;
    if (size > 4096 || xair_sym_context_create(&context) != XAIR_SYM_OK) return 0;
    while (cursor + 3 <= size && count < sizeof(values) / sizeof(values[0])) {
        uint16_t bits = (uint16_t)(1u << (data[cursor] % 7u));
        xair_sym_expr_id lhs, rhs, result;
        if (bits > 128) bits = 128;
        if (xair_sym_const(context, bits, data[cursor + 1], &lhs) != XAIR_SYM_OK ||
            xair_sym_const(context, bits, data[cursor + 2], &rhs) != XAIR_SYM_OK) break;
        if (xair_sym_binary(context, binary_ops[data[cursor] % (sizeof(binary_ops) / sizeof(binary_ops[0]))],
            (data[cursor] % 4u) == 3u ? 1u : bits, lhs, rhs, &result) == XAIR_SYM_OK) values[count++] = result;
        cursor += 3;
    }
    (void)values;
    xair_sym_context_destroy(context);
    return 0;
}
