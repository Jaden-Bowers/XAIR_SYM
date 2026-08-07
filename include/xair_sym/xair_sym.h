#ifndef XAIR_SYM_XAIR_SYM_H
#define XAIR_SYM_XAIR_SYM_H

#include "xair_cfg/xair_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XAIR_SYM_INVALID_ID UINT32_MAX
#define XAIR_SYM_VERSION_MAJOR 0u
#define XAIR_SYM_VERSION_MINOR 5u
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
    XAIR_SYM_ERR_INFEASIBLE,
    XAIR_SYM_ERR_RESOURCE_LIMIT,
    XAIR_SYM_ERR_CANCELED,
    XAIR_SYM_ERR_SOLVER_TIMEOUT,
    XAIR_SYM_ERR_SOLVER_UNKNOWN,
    XAIR_SYM_ERR_INTERNAL
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
    uint64_t immediate_hi;
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
    size_t concretizations;
    size_t compiled_dispatches;
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

typedef enum {
    XAIR_SYM_EXEC_SYMBOLIC = 0,
    XAIR_SYM_EXEC_HYBRID_CONCRETIZE
} xair_sym_execution_mode;

typedef xair_cancel_token xair_sym_cancel_token;

typedef struct {
    xair_analysis_options analysis;
    size_t max_states;
    size_t max_block_steps;
    size_t max_visits_per_block;
    size_t max_symbolic_forks;
    xair_sym_search_policy search;
    xair_sym_execution_mode execution_mode;
    const xair_sym_cancel_token *cancel_token;
} xair_sym_explore_options;

typedef struct xair_sym_context xair_sym_context;
typedef struct xair_sym_state xair_sym_state;
typedef struct xair_sym_trace xair_sym_trace;
typedef struct xair_sym_environment xair_sym_environment;
typedef struct xair_sym_program xair_sym_program;
typedef struct xair_sym_snapshot xair_sym_snapshot;
typedef xair_sym_status (*xair_sym_terminal_cb)(xair_sym_state *state, void *user);
typedef xair_sym_status (*xair_sym_call_model_cb)(
    xair_sym_state *state, xair_op_id call_op, void *user);

const char *xair_sym_version_string(void);
uint32_t xair_sym_version_u32(void);
xair_sym_status xair_sym_cancel_token_create(xair_sym_cancel_token **out_token);
void xair_sym_cancel_token_destroy(xair_sym_cancel_token *token);
void xair_sym_cancel_token_request(xair_sym_cancel_token *token);
void xair_sym_cancel_token_reset(xair_sym_cancel_token *token);
int xair_sym_cancel_token_requested(const xair_sym_cancel_token *token);

typedef struct {
    xair_block_id block;
    xair_sym_expr_id condition;
    uint8_t taken;
} xair_sym_trace_branch;

typedef struct {
    xair_analysis_options analysis;
    uint64_t stack_base;
    size_t stack_size;
    size_t max_segment_size;
} xair_sym_process_options;

typedef enum {
    XAIR_SYM_MODEL_UNKNOWN = 0,
    XAIR_SYM_MODEL_ALLOC,
    XAIR_SYM_MODEL_FREE,
    XAIR_SYM_MODEL_COPY,
    XAIR_SYM_MODEL_FILL,
    XAIR_SYM_MODEL_INPUT,
    XAIR_SYM_MODEL_LENGTH,
    XAIR_SYM_MODEL_NO_RETURN,
    XAIR_SYM_MODEL_DRIVER_INPUT,
    XAIR_SYM_MODEL_DRIVER_COMPLETE
} xair_sym_model_kind;

typedef struct {
    xair_sym_model_kind kind;
    uint16_t version_major;
    uint16_t version_minor;
} xair_sym_model_info;

xair_sym_status xair_sym_context_create(xair_sym_context **out_context);
void xair_sym_context_destroy(xair_sym_context *context);
void xair_sym_context_stats(const xair_sym_context *context, xair_sym_stats *out_stats);
void xair_sym_context_set_analysis_options(
    xair_sym_context *context, const xair_analysis_options *options);
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
xair_sym_status xair_sym_const_wide(
    xair_sym_context *context, uint16_t bits, uint64_t lo, uint64_t hi,
    xair_sym_expr_id *out_expr);
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
void xair_sym_state_set_call_model(
    xair_sym_state *state, xair_sym_call_model_cb callback, void *user);
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
xair_sym_status xair_sym_check_ex(
    xair_sym_state *state, xair_sym_expr_id extra_condition, xair_sym_sat *out_sat,
    xair_diagnostic *diagnostic);
xair_sym_status xair_sym_model_u64(
    xair_sym_state *state, xair_sym_expr_id symbol, uint64_t *out_value);
xair_sym_status xair_sym_model_bytes(
    xair_sym_state *state, const xair_sym_expr_id *symbols, size_t count,
    uint8_t *out_bytes);
xair_sym_status xair_sym_state_concretize(
    xair_sym_state *state, xair_sym_expr_id expression,
    xair_sym_expr_id *out_constant);

xair_sym_status xair_sym_program_compile(
    const xair_module *module, xair_sym_program **out_program);
void xair_sym_program_destroy(xair_sym_program *program);
xair_sym_status xair_sym_state_attach_program(
    xair_sym_state *state, const xair_sym_program *program);

xair_sym_status xair_sym_snapshot_take(
    const xair_sym_state *state, xair_sym_snapshot **out_snapshot);
void xair_sym_snapshot_destroy(xair_sym_snapshot *snapshot);
xair_sym_status xair_sym_snapshot_restore(
    const xair_sym_snapshot *snapshot, xair_sym_state **out_state);
xair_sym_status xair_sym_snapshot_save(
    const xair_sym_snapshot *snapshot, const char *path);
xair_sym_status xair_sym_snapshot_load(
    xair_sym_context *context, const xair_module *module, const char *path,
    xair_sym_snapshot **out_snapshot);

typedef struct {
    size_t workers;
    xair_sym_explore_options explore;
} xair_sym_parallel_options;

void xair_sym_parallel_options_init(xair_sym_parallel_options *options);
xair_sym_status xair_sym_parallel_explore(
    const xair_sym_snapshot *snapshot, const xair_sym_parallel_options *options,
    xair_sym_terminal_cb callback, void *user);

xair_sym_status xair_sym_trace_create(xair_sym_trace **out_trace);
void xair_sym_trace_destroy(xair_sym_trace *trace);
xair_sym_status xair_sym_trace_add_branch(
    xair_sym_trace *trace, xair_block_id block,
    xair_sym_expr_id condition, int taken);
size_t xair_sym_trace_count(const xair_sym_trace *trace);
xair_sym_status xair_sym_trace_get(
    const xair_sym_trace *trace, size_t index,
    xair_sym_trace_branch *out_branch);
xair_sym_status xair_sym_concolic_invert(
    const xair_sym_state *base, const xair_sym_trace *trace,
    size_t branch_index, xair_sym_state **out_state);
xair_sym_status xair_sym_testcase_write(
    const char *path, const uint8_t *bytes, size_t size);
xair_sym_status xair_sym_testcase_read(
    const char *path, uint8_t *bytes, size_t capacity, size_t *out_size);

void xair_sym_process_options_init(xair_sym_process_options *options, xair_arch arch);
xair_sym_status xair_sym_process_create(
    xair_sym_context *context, const xair_cfg *cfg,
    const xair_binary_view *binary, const xair_sym_process_options *options,
    xair_sym_environment **out_environment, xair_sym_state **out_state);
void xair_sym_environment_destroy(xair_sym_environment *environment);
xair_sym_status xair_sym_environment_model(
    const xair_sym_environment *environment, const char *name,
    xair_sym_model_kind *out_kind);
xair_sym_status xair_sym_environment_model_info(
    const xair_sym_environment *environment, const char *name,
    xair_sym_model_info *out_info);
xair_sym_status xair_sym_environment_allocate(
    xair_sym_environment *environment, xair_sym_state *state,
    size_t size, uint64_t *out_address);
xair_sym_status xair_sym_environment_input(
    xair_sym_environment *environment, xair_sym_state *state,
    uint64_t address, size_t size, const char *source_name,
    xair_sym_expr_id *out_symbols);
xair_sym_status xair_sym_environment_copy(
    xair_sym_environment *environment, xair_sym_state *state,
    uint64_t destination, uint64_t source, size_t size);

xair_sym_status xair_sym_explore(
    xair_sym_state *initial, size_t max_states, size_t max_block_steps,
    xair_sym_terminal_cb callback, void *user);
void xair_sym_explore_options_init(xair_sym_explore_options *options);
xair_sym_status xair_sym_explore_with_options(
    xair_sym_state *initial, const xair_sym_explore_options *options,
    xair_sym_terminal_cb callback, void *user);
xair_sym_status xair_sym_explore_with_options_ex(
    xair_sym_state *initial, const xair_sym_explore_options *options,
    xair_sym_terminal_cb callback, void *user,
    xair_analysis_result *result, xair_diagnostic *diagnostic);

xair_block_id xair_sym_state_block(const xair_sym_state *state);
const char *xair_sym_status_name(xair_sym_status status);

#ifdef __cplusplus
}
#endif
#endif
