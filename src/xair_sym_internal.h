#ifndef XAIR_SYM_INTERNAL_H
#define XAIR_SYM_INTERNAL_H

#include "xair_sym/xair_sym.h"

#include <stdatomic.h>

typedef struct {
    xair_sym_expr_kind kind;
    xair_opcode opcode;
    uint16_t bits;
    uint8_t arg_count;
    xair_sym_expr_id args[3];
    uint64_t immediate;
    uint64_t hash;
    uint64_t dependencies;
    char symbol[48];
} xair_sym_expr;

typedef struct {
    uint64_t hash;
    xair_sym_expr_id expr;
    uint8_t used;
} xair_sym_hash_entry;

typedef struct {
    xair_sym_taint_node_kind kind;
    xair_sym_taint_id lhs;
    xair_sym_taint_id rhs;
    uint64_t hash;
    char name[48];
} xair_sym_taint_node;

typedef struct {
    uint64_t key;
    uint64_t constraint_identity;
    xair_sym_expr_id extra;
    xair_sym_sat result;
    uint8_t used;
} xair_sym_query_cache_entry;

typedef struct {
    uint64_t constraint_identity;
    xair_sym_expr_id symbol;
    uint64_t value;
} xair_sym_model_cache_entry;

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
    xair_sym_taint_id *taints;
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
    uint64_t identity;
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
    xair_sym_taint_node **taints;
    size_t taint_count;
    size_t taint_capacity;
    xair_sym_taint_mode taint_mode;
    xair_sym_query_cache_entry *query_cache;
    size_t query_cache_count;
    size_t query_cache_capacity;
    uint64_t next_constraint_identity;
    xair_sym_model_cache_entry *model_cache;
    size_t model_cache_count;
    size_t model_cache_capacity;
};

struct xair_sym_state {
    xair_sym_context *context;
    const xair_module *module;
    xair_block_id block;
    xair_sym_expr_id *values;
    uint8_t *defined;
    xair_sym_taint_id *value_taints;
    size_t value_count;
    xair_sym_constraint *constraints;
    xair_sym_memory *memory;
    size_t depth;
    xair_sym_taint_id control_taint;
    const xair_sym_program *program;
};

typedef struct {
    xair_op_view *ops;
    size_t op_count;
    xair_term_view terminator;
} xair_sym_compiled_block;

struct xair_sym_program {
    const xair_module *module;
    xair_sym_compiled_block *blocks;
    size_t block_count;
};

struct xair_sym_snapshot {
    xair_sym_state *state;
    uint64_t module_fingerprint;
};

struct xair_sym_cancel_token {
    atomic_bool requested;
};

struct xair_sym_trace {
    xair_sym_trace_branch *branches;
    size_t count;
    size_t capacity;
};

struct xair_sym_environment {
    xair_sym_context *context;
    xair_arch arch;
    uint64_t heap_next;
    uint64_t stack_base;
    size_t stack_size;
};

xair_sym_status xair_sym_intern(xair_sym_context *context, const xair_sym_expr *key, xair_sym_expr_id *out_expr);
xair_sym_memory *xair_sym_memory_create(void);
void xair_sym_memory_retain(xair_sym_memory *memory);
void xair_sym_memory_release(xair_sym_memory *memory);
xair_sym_status xair_sym_memory_make_unique(xair_sym_state *state);
xair_sym_status xair_sym_memory_initialize8(
    xair_sym_state *state, uint64_t address, xair_sym_expr_id value);
xair_sym_status xair_sym_memory_initialize_taint8(
    xair_sym_state *state, uint64_t address, xair_sym_taint_id taint);
xair_sym_status xair_sym_memory_load_symbolic8(
    xair_sym_state *state, xair_sym_expr_id address, xair_sym_expr_id *out_value);
xair_sym_status xair_sym_memory_store_symbolic8(
    xair_sym_state *state, xair_sym_expr_id address, xair_sym_expr_id value);
xair_sym_status xair_sym_memory_union_taint(
    xair_sym_state *state, uint32_t permission, xair_sym_taint_id taint,
    int update, xair_sym_taint_id *out_taint);
xair_sym_status xair_sym_solver_check(
    xair_sym_state *state, xair_sym_expr_id extra, xair_sym_sat *out_sat,
    xair_sym_expr_id model_symbol, uint64_t *out_model);
xair_sym_status xair_sym_taint_operands(
    xair_sym_state *state, const xair_op_view *op, xair_sym_taint_id *out_taint);
xair_sym_status xair_sym_snapshot_clone_isolated(
    const xair_sym_snapshot *snapshot, xair_sym_context **out_context,
    xair_sym_state **out_state);

#endif
