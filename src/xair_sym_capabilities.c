#include "xair_sym_internal.h"

#define CAP_SCALAR (XAIR_SYM_CAP_VERIFY | XAIR_SYM_CAP_FORMAT | XAIR_SYM_CAP_CONCRETE | \
    XAIR_SYM_CAP_EXPRESSION | XAIR_SYM_CAP_Z3 | XAIR_SYM_CAP_FOLD | \
    XAIR_SYM_CAP_TAINT | XAIR_SYM_CAP_SERIALIZE)
#define CAP_MEMORY (XAIR_SYM_CAP_VERIFY | XAIR_SYM_CAP_FORMAT | XAIR_SYM_CAP_CONCRETE | \
    XAIR_SYM_CAP_EXPRESSION | XAIR_SYM_CAP_TAINT | XAIR_SYM_CAP_SERIALIZE)
#define CAP_INCOMPLETE (CAP_MEMORY | XAIR_SYM_CAP_EXPLICIT_INCOMPLETE)
#define CAP_SYMBOLIC (CAP_MEMORY | XAIR_SYM_CAP_Z3)
#define CAP_OPAQUE_PURE (CAP_SYMBOLIC | XAIR_SYM_CAP_EXPLICIT_INCOMPLETE)

static const xair_sym_opcode_capability capabilities[] = {
#define XAIR_SYM_OPCODE(name, caps) { name, caps },
#include "xair_sym_opcode_capabilities.inc"
#undef XAIR_SYM_OPCODE
};

size_t xair_sym_opcode_capability_count(void) {
    return sizeof(capabilities) / sizeof(capabilities[0]);
}

xair_sym_status xair_sym_opcode_capability_get(size_t index,
    xair_sym_opcode_capability *out_capability) {
    if (out_capability == NULL || index >= xair_sym_opcode_capability_count()) return XAIR_SYM_ERR_BAD_ARG;
    *out_capability = capabilities[index];
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_opcode_capabilities_validate(void) {
    size_t i, j;
    for (i = 0; i < xair_sym_opcode_capability_count(); ++i) {
        uint32_t caps = capabilities[i].capabilities;
        const uint32_t common = XAIR_SYM_CAP_VERIFY | XAIR_SYM_CAP_FORMAT |
            XAIR_SYM_CAP_CONCRETE | XAIR_SYM_CAP_EXPRESSION | XAIR_SYM_CAP_TAINT |
            XAIR_SYM_CAP_SERIALIZE;
        if (xair_opcode_name(capabilities[i].opcode) == NULL || (caps & common) != common)
            return XAIR_SYM_ERR_INTERNAL;
        if ((caps & XAIR_SYM_CAP_EXPLICIT_INCOMPLETE) == 0 &&
            capabilities[i].opcode != XAIR_OP_LOAD && capabilities[i].opcode != XAIR_OP_STORE &&
            capabilities[i].opcode != XAIR_OP_MEMORY_BARRIER &&
            capabilities[i].opcode != XAIR_OP_UNKNOWN && capabilities[i].opcode != XAIR_OP_UNDEF &&
            ((caps & (XAIR_SYM_CAP_Z3 | XAIR_SYM_CAP_FOLD)) !=
             (XAIR_SYM_CAP_Z3 | XAIR_SYM_CAP_FOLD))) return XAIR_SYM_ERR_INTERNAL;
        for (j = i + 1; j < xair_sym_opcode_capability_count(); ++j)
            if (capabilities[i].opcode == capabilities[j].opcode) return XAIR_SYM_ERR_INTERNAL;
    }
    return XAIR_SYM_OK;
}
