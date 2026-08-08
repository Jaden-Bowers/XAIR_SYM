#include "xair_sym/xair_sym.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    xair_module *module = NULL;
    xair_sym_context *context = NULL;
    xair_sym_snapshot *snapshot = NULL;
    xair_block_id block;
    if (size > 16u * 1024u * 1024u) return 0;
    if (xair_module_create(&module) != XAIR_OK || xair_block_create(module, "fuzz", &block) != XAIR_OK ||
        xair_set_return(module, block, NULL, 0) != XAIR_OK || xair_module_freeze(module) != XAIR_OK ||
        xair_sym_context_create(&context) != XAIR_SYM_OK) goto done;
    (void)xair_sym_snapshot_load_bytes(context, module, data, size, &snapshot);
done:
    xair_sym_snapshot_destroy(snapshot);
    xair_sym_context_destroy(context);
    xair_module_destroy(module);
    return 0;
}
