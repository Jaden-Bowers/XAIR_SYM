#ifndef XAIR_SYM_INTERNAL_H
#define XAIR_SYM_INTERNAL_H

#include "xair_sym/xair_sym.h"

#include "xair/xair_platform.h"

typedef struct {
    xair_sym_expr_kind kind;
    xair_opcode opcode;
    uint16_t bits;
    uint8_t arg_count;
    xair_sym_expr_id args[3];
    uint64_t immediate;
    uint64_t immediate_hi;
    uint64_t hash;
    uint64_t dependencies;
    const char *symbol;
    uint8_t flags_pack;
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
    char *name;
    xair_sym_taint_details details;
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
    unsigned char data[1];
} xair_sym_arena_chunk;

#define XAIR_SYM_PAGE_SHIFT 12u
#define XAIR_SYM_PAGE_SIZE ((size_t)1u << XAIR_SYM_PAGE_SHIFT)
#define XAIR_SYM_SYMBOLIC_ADDRESS_LIMIT 4096u
#define XAIR_SYM_MEMORY_MODEL_VERSION 2u

typedef struct xair_sym_page {
    size_t refs;
    xair_sym_expr_id bytes[XAIR_SYM_PAGE_SIZE];
    xair_sym_taint_id taints[XAIR_SYM_PAGE_SIZE];
} xair_sym_page;

typedef struct xair_sym_backing {
    size_t refs;
    const uint8_t *bytes;
    size_t size;
    uint8_t owned;
    uint64_t hash;
} xair_sym_backing;

typedef struct {
    xair_mutex lock;
    size_t remaining_states;
    size_t remaining_steps;
    size_t remaining_forks;
    size_t max_memory;
    size_t remaining_memory;
    size_t peak_memory;
    uint8_t *covered_blocks;
    size_t block_count;
} xair_sym_parallel_budget;

typedef struct {
    uint64_t base;
    size_t size;
    uint32_t permissions;
    const uint8_t *backing;
    size_t backing_size;
    xair_sym_backing *backing_ref;
    uint8_t zero_fill;
    xair_sym_page **pages;
    size_t page_count;
    uint64_t version;
} xair_sym_object;

typedef struct xair_sym_memory {
    size_t refs;
    xair_sym_object *objects;
    size_t count;
    size_t capacity;
    uint64_t version;
} xair_sym_memory;

typedef struct xair_sym_constraint {
    xair_sym_context *context;
    size_t refs;
    size_t count;
    uint64_t identity;
    xair_sym_expr_id expression;
    struct xair_sym_constraint *parent;
} xair_sym_constraint;

struct xair_sym_context {
    xair_analysis_options analysis;
    uint64_t analysis_started_ms;
    xair_sym_expr **expressions;
    size_t expression_count;
    size_t expression_capacity;
    xair_sym_hash_entry *hash;
    size_t hash_count;
    size_t hash_capacity;
    xair_sym_arena_chunk *arena;
    size_t arena_bytes;
    size_t arena_capacity_bytes;
    xair_sym_parallel_budget *parallel_budget;
    size_t parallel_memory_reserved;
    size_t object_bytes;
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
    void *solver_runtime;
    xair_block_id *immediate_postdominators;
    size_t immediate_postdominator_count;
};

int xair_sym_parallel_memory_reserve(xair_sym_context *context, size_t bytes);
void xair_sym_parallel_memory_release(xair_sym_context *context, size_t bytes);

struct xair_sym_state {
    xair_sym_context *context;
    const xair_module *module;
    xair_block_id block;
    xair_sym_expr_id *values;
    uint8_t *defined;
    xair_sym_taint_id *value_taints;
    size_t value_count;
    size_t parallel_memory_reserved;
    xair_sym_constraint *constraints;
    xair_sym_memory *memory;
    size_t depth;
    xair_sym_taint_id control_taint;
    const xair_sym_program *program;
    xair_sym_execution_mode execution_mode;
    xair_sym_call_model_cb call_model;
    void *call_model_user;
    xair_sym_environment *environment;
    xair_sym_completion_reason completeness;
    size_t unresolved_operations;
    xair_calling_convention abi;
    uint64_t binary_hash;
    uint64_t model_library_version;
    uint64_t options_fingerprint;
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t heap_next;
    uint64_t memory_havoc_version;
    uint64_t partition_constraint_identity;
    uint8_t terminate_requested;
    uint8_t model_output_confidence;
    struct {
        xair_block_id postdominator;
        xair_sym_taint_id taint;
    } control_scopes[32];
    size_t control_scope_count;
};

typedef struct {
    xair_op_view *ops;
    xair_op_id *op_ids;
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
    xair_sym_snapshot_metadata metadata;
};

struct xair_sym_trace {
    xair_sym_trace_branch *branches;
    size_t count;
    size_t capacity;
};

struct xair_sym_environment {
    size_t refs;
    xair_sym_context *context;
    xair_arch arch;
    uint64_t heap_next;
    uint64_t stack_base;
    size_t stack_size;
    xair_calling_convention abi;
    uint64_t model_version;
    struct xair_sym_registered_model *models;
    size_t model_count;
    size_t model_capacity;
};

typedef struct xair_sym_registered_model {
    char *module;
    char *name;
    char *user_identity;
    uint32_t ordinal;
    uint64_t address;
    xair_sym_model_info info;
    xair_sym_call_model_cb callback;
    void *user;
} xair_sym_registered_model;

xair_sym_status xair_sym_intern(xair_sym_context *context, const xair_sym_expr *key, xair_sym_expr_id *out_expr);
xair_sym_memory *xair_sym_memory_create(void);
void xair_sym_memory_retain(xair_sym_memory *memory);
void xair_sym_memory_release(xair_sym_memory *memory);
xair_sym_status xair_sym_memory_make_unique(xair_sym_state *state);
xair_sym_status xair_sym_memory_map_lazy(
    xair_sym_state *state, uint64_t base, size_t size, uint32_t permissions,
    const uint8_t *backing, size_t backing_size, int zero_fill,
    xair_sym_object_id *out_object);
xair_sym_status xair_sym_object_remove_containing(xair_sym_state *state, uint64_t address);
xair_sym_status xair_sym_memory_initialize8(
    xair_sym_state *state, uint64_t address, xair_sym_expr_id value);
xair_sym_status xair_sym_memory_initialize_taint8(
    xair_sym_state *state, uint64_t address, xair_sym_taint_id taint);
xair_sym_status xair_sym_memory_validate_range(
    const xair_sym_state *state, uint64_t address, size_t size, uint32_t permission);
xair_sym_status xair_sym_memory_load_symbolic8(
    xair_sym_state *state, xair_sym_expr_id address, xair_sym_expr_id *out_value,
    xair_sym_taint_id *out_taint);
xair_sym_status xair_sym_memory_store_symbolic8(
    xair_sym_state *state, xair_sym_expr_id address, xair_sym_expr_id value,
    xair_sym_taint_id taint);
xair_sym_status xair_sym_memory_union_taint(
    xair_sym_state *state, uint32_t permission, xair_sym_taint_id taint,
    int update, xair_sym_taint_id *out_taint);
uint64_t xair_sym_memory_fingerprint(const xair_sym_memory *memory);
void xair_sym_memory_havoc(xair_sym_state *state);
xair_sym_status xair_sym_solver_check(
    xair_sym_state *state, xair_sym_expr_id extra, xair_sym_sat *out_sat,
    xair_sym_expr_id model_symbol, uint64_t *out_model);
void xair_sym_solver_runtime_destroy(xair_sym_context *context);
xair_sym_status xair_sym_solver_model_wide(
    xair_sym_state *state, xair_sym_expr_id symbol,
    uint64_t *out_lo, uint64_t *out_hi);
xair_sym_status xair_sym_taint_operands(
    xair_sym_state *state, const xair_op_view *op, xair_sym_taint_id *out_taint);
xair_sym_status xair_sym_snapshot_clone_isolated(
    const xair_sym_snapshot *snapshot, xair_sym_context **out_context,
    xair_sym_state **out_state);
void xair_sym_environment_retain(xair_sym_environment *environment);
void xair_sym_environment_release(xair_sym_environment *environment);
xair_sym_status xair_sym_environment_clone_builtin(
    const xair_sym_environment *source, xair_sym_context *context,
    xair_sym_environment **out_environment);
xair_sym_status xair_sym_environment_create_builtin_snapshot(
    xair_sym_context *context, xair_arch arch, xair_calling_convention abi,
    uint64_t model_version, uint64_t stack_base, size_t stack_size,
    uint64_t heap_next, xair_sym_environment **out_environment);
void xair_sym_environment_attach_builtin(
    xair_sym_state *state, xair_sym_environment *environment);

#endif
