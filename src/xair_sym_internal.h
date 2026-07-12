#ifndef XAIR_SYM_INTERNAL_H
#define XAIR_SYM_INTERNAL_H

#include "xair_sym/xair_sym.h"

typedef struct {
    xair_sym_expr_kind kind;
    xair_opcode opcode;
    uint16_t bits;
    uint8_t arg_count;
    xair_sym_expr_id args[3];
    uint64_t immediate;
    uint64_t hash;
    char symbol[48];
} xair_sym_expr;

typedef struct {
    uint64_t hash;
    xair_sym_expr_id expr;
    uint8_t used;
} xair_sym_hash_entry;

typedef struct xair_sym_arena_chunk {
    struct xair_sym_arena_chunk *next;
    size_t used;
    size_t capacity;
    unsigned char data[];
} xair_sym_arena_chunk;

typedef struct {
    uint64_t base;
    size_t size;
    uint32_t permissions;
    xair_sym_expr_id *bytes;
} xair_sym_object;

typedef struct xair_sym_memory {
    size_t refs;
    xair_sym_object *objects;
    size_t count;
    size_t capacity;
} xair_sym_memory;

typedef struct xair_sym_constraint {
    size_t refs;
    size_t count;
    xair_sym_expr_id expression;
    struct xair_sym_constraint *parent;
} xair_sym_constraint;

struct xair_sym_context {
    xair_sym_expr **expressions;
    size_t expression_count;
    size_t expression_capacity;
    xair_sym_hash_entry *hash;
    size_t hash_count;
    size_t hash_capacity;
    xair_sym_arena_chunk *arena;
    xair_sym_stats stats;
};

struct xair_sym_state {
    xair_sym_context *context;
    const xair_module *module;
    xair_block_id block;
    xair_sym_expr_id *values;
    uint8_t *defined;
    size_t value_count;
    xair_sym_constraint *constraints;
    xair_sym_memory *memory;
};

xair_sym_status xair_sym_intern(xair_sym_context *context, const xair_sym_expr *key, xair_sym_expr_id *out_expr);
xair_sym_memory *xair_sym_memory_create(void);
void xair_sym_memory_retain(xair_sym_memory *memory);
void xair_sym_memory_release(xair_sym_memory *memory);
xair_sym_status xair_sym_memory_make_unique(xair_sym_state *state);
xair_sym_status xair_sym_memory_load_symbolic8(
    xair_sym_state *state, xair_sym_expr_id address, xair_sym_expr_id *out_value);
xair_sym_status xair_sym_memory_store_symbolic8(
    xair_sym_state *state, xair_sym_expr_id address, xair_sym_expr_id value);
xair_sym_status xair_sym_solver_check(
    xair_sym_state *state, xair_sym_expr_id extra, xair_sym_sat *out_sat,
    xair_sym_expr_id model_symbol, uint64_t *out_model);

#endif
