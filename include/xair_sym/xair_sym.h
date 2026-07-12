#ifndef XAIR_SYM_XAIR_SYM_H
#define XAIR_SYM_XAIR_SYM_H

#include "xair_cfg/xair_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XAIR_SYM_INVALID_ID UINT32_MAX
#define XAIR_SYM_VERSION_MAJOR 0u
#define XAIR_SYM_VERSION_MINOR 2u
#define XAIR_SYM_VERSION_PATCH 0u

typedef uint32_t xair_sym_expr_id;
typedef uint32_t xair_sym_object_id;
typedef uint32_t xair_sym_taint_id;

#define XAIR_SYM_TAINT_NONE 0u

typedef enum {
    XAIR_SYM_OK = 0,
    XAIR_SYM_ERR_OOM,
    XAIR_SYM_ERR_BAD_ARG,
    XAIR_SYM_ERR_RANGE,
    XAIR_SYM_ERR_UNSUPPORTED,
    XAIR_SYM_ERR_SOLVER,
    XAIR_SYM_ERR_INFEASIBLE
} xair_sym_status;

typedef enum {
    XAIR_SYM_UNSAT = 0,
    XAIR_SYM_SAT,
    XAIR_SYM_UNKNOWN
} xair_sym_sat;

typedef enum {
    XAIR_SYM_EXPR_CONST = 0,
    XAIR_SYM_EXPR_SYMBOL,
    XAIR_SYM_EXPR_XAIR
} xair_sym_expr_kind;

typedef struct {
    xair_sym_expr_kind kind;
    xair_opcode opcode;
    uint16_t bits;
    uint8_t arg_count;
    xair_sym_expr_id args[3];
    uint64_t immediate;
    const char *symbol;
} xair_sym_expr_view;

typedef struct {
    size_t expressions;
    size_t expressions_reused;
    size_t hash_collisions;
    size_t solver_queries;
    size_t solver_sat;
    size_t solver_unsat;
    size_t states_created;
    size_t states_completed;
    size_t states_pruned;
    size_t forks;
    size_t memory_objects;
    size_t memory_cow_copies;
    size_t taint_nodes;
    size_t taint_nodes_reused;
    size_t solver_cache_hits;
    size_t model_cache_hits;
    size_t constraints_submitted;
    size_t constraints_sliced;
    size_t scheduler_pruned;
} xair_sym_stats;

typedef enum {
    XAIR_SYM_TAINT_EXPLICIT = 0,
    XAIR_SYM_TAINT_TARGETED_IMPLICIT,
    XAIR_SYM_TAINT_STRICT_IMPLICIT
} xair_sym_taint_mode;

typedef enum {
    XAIR_SYM_TAINT_NODE_SOURCE = 1,
    XAIR_SYM_TAINT_NODE_UNION,
    XAIR_SYM_TAINT_NODE_SANITIZER
} xair_sym_taint_node_kind;

typedef struct {
    xair_sym_taint_node_kind kind;
    xair_sym_taint_id lhs;
    xair_sym_taint_id rhs;
    const char *name;
} xair_sym_taint_view;

typedef enum {
    XAIR_SYM_SEARCH_BFS = 0,
    XAIR_SYM_SEARCH_DFS,
    XAIR_SYM_SEARCH_COVERAGE
} xair_sym_search_policy;

typedef struct {
    size_t max_states;
    size_t max_block_steps;
    size_t max_visits_per_block;
    xair_sym_search_policy search;
} xair_sym_explore_options;

typedef struct xair_sym_context xair_sym_context;
typedef struct xair_sym_state xair_sym_state;

xair_sym_status xair_sym_context_create(xair_sym_context **out_context);
void xair_sym_context_destroy(xair_sym_context *context);
void xair_sym_context_stats(const xair_sym_context *context, xair_sym_stats *out_stats);
void xair_sym_context_set_taint_mode(xair_sym_context *context, xair_sym_taint_mode mode);

xair_sym_status xair_sym_taint_source(
    xair_sym_context *context, const char *name, xair_sym_taint_id *out_taint);
xair_sym_status xair_sym_taint_union(
    xair_sym_context *context, xair_sym_taint_id lhs, xair_sym_taint_id rhs,
    xair_sym_taint_id *out_taint);
xair_sym_status xair_sym_taint_sanitize(
    xair_sym_context *context, xair_sym_taint_id input, const char *sanitizer,
    xair_sym_taint_id *out_taint);
xair_sym_status xair_sym_taint_get(
    const xair_sym_context *context, xair_sym_taint_id taint,
    xair_sym_taint_view *out_view);

xair_sym_status xair_sym_const(
    xair_sym_context *context, uint16_t bits, uint64_t value, xair_sym_expr_id *out_expr);
xair_sym_status xair_sym_symbol(
    xair_sym_context *context, uint16_t bits, const char *name, xair_sym_expr_id *out_expr);
xair_sym_status xair_sym_unary(
    xair_sym_context *context, xair_opcode opcode, uint16_t bits,
    xair_sym_expr_id src, uint64_t immediate, xair_sym_expr_id *out_expr);
xair_sym_status xair_sym_binary(
    xair_sym_context *context, xair_opcode opcode, uint16_t bits,
    xair_sym_expr_id lhs, xair_sym_expr_id rhs, xair_sym_expr_id *out_expr);
xair_sym_status xair_sym_select(
    xair_sym_context *context, xair_sym_expr_id condition,
    xair_sym_expr_id true_value, xair_sym_expr_id false_value, xair_sym_expr_id *out_expr);
xair_sym_status xair_sym_expr_get(
    const xair_sym_context *context, xair_sym_expr_id expr, xair_sym_expr_view *out_view);

xair_sym_status xair_sym_state_create(
    xair_sym_context *context, const xair_module *module, xair_block_id entry,
    xair_sym_state **out_state);
xair_sym_status xair_sym_state_clone(const xair_sym_state *state, xair_sym_state **out_state);
void xair_sym_state_destroy(xair_sym_state *state);
xair_sym_status xair_sym_state_set_value(
    xair_sym_state *state, xair_value_id value, xair_sym_expr_id expr);
xair_sym_status xair_sym_state_get_value(
    const xair_sym_state *state, xair_value_id value, xair_sym_expr_id *out_expr);
xair_sym_status xair_sym_state_assume(xair_sym_state *state, xair_sym_expr_id condition);
xair_sym_status xair_sym_state_set_taint(
    xair_sym_state *state, xair_value_id value, xair_sym_taint_id taint);
xair_sym_status xair_sym_state_get_taint(
    const xair_sym_state *state, xair_value_id value, xair_sym_taint_id *out_taint);

xair_sym_status xair_sym_object_add(
    xair_sym_state *state, uint64_t base, size_t size, uint32_t permissions,
    xair_sym_object_id *out_object);
xair_sym_status xair_sym_memory_store8(
    xair_sym_state *state, uint64_t address, xair_sym_expr_id value);
xair_sym_status xair_sym_memory_load8(
    const xair_sym_state *state, uint64_t address, xair_sym_expr_id *out_value);
xair_sym_status xair_sym_memory_store_taint8(
    xair_sym_state *state, uint64_t address, xair_sym_taint_id taint);
xair_sym_status xair_sym_memory_load_taint8(
    const xair_sym_state *state, uint64_t address, xair_sym_taint_id *out_taint);

xair_sym_status xair_sym_check(
    xair_sym_state *state, xair_sym_expr_id extra_condition, xair_sym_sat *out_sat);
xair_sym_status xair_sym_model_u64(
    xair_sym_state *state, xair_sym_expr_id symbol, uint64_t *out_value);

typedef xair_sym_status (*xair_sym_terminal_cb)(xair_sym_state *state, void *user);
xair_sym_status xair_sym_explore(
    xair_sym_state *initial, size_t max_states, size_t max_block_steps,
    xair_sym_terminal_cb callback, void *user);
void xair_sym_explore_options_init(xair_sym_explore_options *options);
xair_sym_status xair_sym_explore_with_options(
    xair_sym_state *initial, const xair_sym_explore_options *options,
    xair_sym_terminal_cb callback, void *user);

xair_block_id xair_sym_state_block(const xair_sym_state *state);
const char *xair_sym_status_name(xair_sym_status status);

#ifdef __cplusplus
}
#endif
#endif
