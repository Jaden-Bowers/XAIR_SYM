#include "xair_sym_internal.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    xair_mutex lock;
    xair_sym_terminal_cb callback;
    void *user;
    xair_sym_context **terminal_contexts;
    xair_sym_state **terminal_states;
    size_t terminal_count;
    size_t terminal_capacity;
    size_t duplicates;
    xair_sym_parallel_budget budget;
    xair_sym_program *program;
} parallel_shared;

typedef struct {
    const xair_sym_snapshot *snapshot;
    xair_sym_explore_options options;
    parallel_shared *shared;
    size_t partition;
    size_t partition_count;
    xair_sym_explore_result result;
    xair_diagnostic diagnostic;
    xair_sym_status status;
} parallel_worker;

static int budget_memory_reserve(xair_sym_parallel_budget *budget, size_t bytes) {
    size_t used;
    if (bytes == 0 || budget->max_memory == 0) return 1;
    xair_mutex_lock(&budget->lock);
    if (bytes > budget->remaining_memory) { xair_mutex_unlock(&budget->lock); return 0; }
    budget->remaining_memory -= bytes;
    used = budget->max_memory - budget->remaining_memory;
    if (used > budget->peak_memory) budget->peak_memory = used;
    xair_mutex_unlock(&budget->lock);
    return 1;
}

static void budget_memory_release(xair_sym_parallel_budget *budget, size_t bytes) {
    if (bytes == 0 || budget->max_memory == 0) return;
    xair_mutex_lock(&budget->lock);
    if (bytes <= budget->max_memory - budget->remaining_memory) budget->remaining_memory += bytes;
    xair_mutex_unlock(&budget->lock);
}

static int add_allocation(size_t *total, size_t count, size_t element) {
    if (element != 0 && count > (SIZE_MAX - *total) / element) return 0;
    *total += count * element;
    return 1;
}

static int isolated_allocation_estimate(const xair_sym_context *context,
    const xair_sym_state *state, size_t *out_bytes) {
    size_t total = context->arena_capacity_bytes;
    const xair_sym_constraint *constraint;
    size_t i;
    if (context->object_bytes > SIZE_MAX - total) return 0;
    total += context->object_bytes;
    if (!add_allocation(&total, context->expression_capacity, sizeof(*context->expressions)) ||
        !add_allocation(&total, context->hash_capacity, sizeof(*context->hash)) ||
        !add_allocation(&total, context->taint_capacity, sizeof(*context->taints)) ||
        !add_allocation(&total, context->query_cache_capacity, sizeof(*context->query_cache)) ||
        !add_allocation(&total, context->model_cache_capacity, sizeof(*context->model_cache)) ||
        !add_allocation(&total, context->immediate_postdominator_count,
            sizeof(*context->immediate_postdominators)) ||
        !add_allocation(&total, 1, state->parallel_memory_reserved) ||
        !add_allocation(&total, 1, sizeof(*state->memory)) ||
        !add_allocation(&total, state->memory->capacity, sizeof(*state->memory->objects))) return 0;
    for (constraint = state->constraints; constraint != NULL; constraint = constraint->parent)
        if (!add_allocation(&total, 1, sizeof(*constraint))) return 0;
    for (i = 0; i < state->memory->count; ++i) {
        const xair_sym_object *object = &state->memory->objects[i];
        if (object->backing_ref != NULL &&
            (!add_allocation(&total, 1, sizeof(*object->backing_ref)) ||
             (object->backing_ref->owned && !add_allocation(&total, object->backing_ref->size, 1)))) return 0;
    }
    for (i = 0; i < context->taint_count; ++i) {
        const xair_sym_taint_node *node = context->taints[i];
        if (!add_allocation(&total, 1, sizeof(*node)) ||
            (node->name != NULL && !add_allocation(&total, strlen(node->name) + 1u, 1))) return 0;
    }
    *out_bytes = total;
    return 1;
}

static int program_allocation_estimate(const xair_module *module, size_t *out_bytes) {
    size_t total = sizeof(xair_sym_program);
    size_t block_count = xair_module_block_count(module), block_i;
    if (!add_allocation(&total, block_count, sizeof(xair_sym_compiled_block))) return 0;
    for (block_i = 0; block_i < block_count; ++block_i) {
        const xair_op_id *ops;
        size_t op_count;
        if (xair_block_ops(module, (xair_block_id)block_i, &ops, &op_count) != XAIR_OK ||
            !add_allocation(&total, op_count, sizeof(xair_op_view) + sizeof(xair_op_id))) return 0;
    }
    *out_bytes = total;
    return 1;
}

static int nullable_string_equal(const char *lhs, const char *rhs) {
    return lhs == rhs || (lhs != NULL && rhs != NULL && strcmp(lhs, rhs) == 0);
}

static int expression_equal(const xair_sym_context *lc, xair_sym_expr_id lhs,
    const xair_sym_context *rc, xair_sym_expr_id rhs) {
    const xair_sym_expr *le, *re;
    size_t i;
    if (lhs == XAIR_SYM_INVALID_ID || rhs == XAIR_SYM_INVALID_ID) return lhs == rhs;
    if (lhs >= lc->expression_count || rhs >= rc->expression_count) return 0;
    le = lc->expressions[lhs]; re = rc->expressions[rhs];
    if (le->kind != re->kind || le->opcode != re->opcode || le->bits != re->bits ||
        le->arg_count != re->arg_count || le->immediate != re->immediate ||
        le->immediate_hi != re->immediate_hi || !nullable_string_equal(le->symbol, re->symbol)) return 0;
    for (i = 0; i < le->arg_count; ++i)
        if (!expression_equal(lc, le->args[i], rc, re->args[i])) return 0;
    return 1;
}

static int taint_equal(const xair_sym_context *lc, xair_sym_taint_id lhs,
    const xair_sym_context *rc, xair_sym_taint_id rhs) {
    const xair_sym_taint_node *ln, *rn;
    if (lhs == XAIR_SYM_TAINT_NONE || rhs == XAIR_SYM_TAINT_NONE) return lhs == rhs;
    if (lhs > lc->taint_count || rhs > rc->taint_count) return 0;
    ln = lc->taints[lhs - 1u]; rn = rc->taints[rhs - 1u];
    if (ln->kind != rn->kind || !nullable_string_equal(ln->name, rn->name) ||
        ln->details.category != rn->details.category ||
        ln->details.source_address != rn->details.source_address ||
        ln->details.call_site != rn->details.call_site ||
        ln->details.sink_address != rn->details.sink_address ||
        ln->details.byte_offset != rn->details.byte_offset ||
        ln->details.byte_length != rn->details.byte_length || ln->details.confidence != rn->details.confidence ||
        ln->details.implicit != rn->details.implicit ||
        ln->details.sanitizer_validated != rn->details.sanitizer_validated ||
        !nullable_string_equal(ln->details.transform, rn->details.transform) ||
        !nullable_string_equal(ln->details.sink, rn->details.sink)) return 0;
    if (!expression_equal(lc, ln->details.guard, rc, rn->details.guard)) return 0;
    return taint_equal(lc, ln->lhs, rc, rn->lhs) && taint_equal(lc, ln->rhs, rc, rn->rhs);
}

static int memory_equal(const xair_sym_state *lhs, const xair_sym_state *rhs) {
    size_t i, p, b;
    if (lhs->memory->count != rhs->memory->count ||
        lhs->memory_havoc_version != rhs->memory_havoc_version) return 0;
    for (i = 0; i < lhs->memory->count; ++i) {
        const xair_sym_object *lo = &lhs->memory->objects[i], *ro = &rhs->memory->objects[i];
        if (lo->base != ro->base || lo->size != ro->size || lo->permissions != ro->permissions ||
            lo->zero_fill != ro->zero_fill || lo->backing_size != ro->backing_size ||
            (lo->backing_size != 0 && memcmp(lo->backing, ro->backing, lo->backing_size) != 0) ||
            lo->page_count != ro->page_count) return 0;
        for (p = 0; p < lo->page_count; ++p) {
            const xair_sym_page *lp = lo->pages[p], *rp = ro->pages[p];
            if (lp == NULL || rp == NULL) { if (lp != rp) return 0; continue; }
            for (b = 0; b < XAIR_SYM_PAGE_SIZE; ++b) {
                if (!expression_equal(lhs->context, lp->bytes[b], rhs->context, rp->bytes[b]) ||
                    !taint_equal(lhs->context, lp->taints[b], rhs->context, rp->taints[b])) return 0;
            }
        }
    }
    return 1;
}

static int terminal_equal(const xair_sym_state *lhs, const xair_sym_state *rhs) {
    size_t i;
    if (lhs->block != rhs->block || lhs->value_count != rhs->value_count ||
        lhs->completeness != rhs->completeness || lhs->unresolved_operations != rhs->unresolved_operations ||
        lhs->terminate_requested != rhs->terminate_requested ||
        lhs->model_output_confidence != rhs->model_output_confidence || lhs->fs_base != rhs->fs_base ||
        lhs->gs_base != rhs->gs_base || lhs->heap_next != rhs->heap_next ||
        lhs->control_scope_count != rhs->control_scope_count ||
        !taint_equal(lhs->context, lhs->control_taint, rhs->context, rhs->control_taint)) return 0;
    for (i = 0; i < lhs->control_scope_count; ++i)
        if (lhs->control_scopes[i].postdominator != rhs->control_scopes[i].postdominator ||
            !taint_equal(lhs->context, lhs->control_scopes[i].taint,
                rhs->context, rhs->control_scopes[i].taint)) return 0;
    {
        const xair_sym_constraint *lc = lhs->constraints, *rc = rhs->constraints;
        while (lc != NULL || rc != NULL) {
            while (lc != NULL && lc->identity == lhs->partition_constraint_identity) lc = lc->parent;
            while (rc != NULL && rc->identity == rhs->partition_constraint_identity) rc = rc->parent;
            if (lc == NULL || rc == NULL) break;
            if (!expression_equal(lhs->context, lc->expression, rhs->context, rc->expression)) return 0;
            lc = lc->parent; rc = rc->parent;
        }
        while (lc != NULL && lc->identity == lhs->partition_constraint_identity) lc = lc->parent;
        while (rc != NULL && rc->identity == rhs->partition_constraint_identity) rc = rc->parent;
        if (lc != NULL || rc != NULL) return 0;
    }
    for (i = 0; i < lhs->value_count; ++i) {
        if (lhs->defined[i] != rhs->defined[i] ||
            (lhs->defined[i] && !expression_equal(lhs->context, lhs->values[i], rhs->context, rhs->values[i])) ||
            !taint_equal(lhs->context, lhs->value_taints[i], rhs->context, rhs->value_taints[i])) return 0;
    }
    return memory_equal(lhs, rhs);
}

static xair_sym_status invoke_unique_terminal(xair_sym_state *state, void *opaque) {
    parallel_shared *shared = (parallel_shared *)opaque;
    xair_sym_context *isolated_context = NULL;
    xair_sym_state *isolated_state = NULL;
    xair_sym_snapshot *snapshot = NULL;
    size_t i;
    xair_sym_status status = XAIR_SYM_OK;
    xair_mutex_lock(&shared->lock);
    for (i = 0; i < shared->terminal_count; ++i) {
        if (terminal_equal(shared->terminal_states[i], state)) {
            shared->duplicates++;
            xair_mutex_unlock(&shared->lock);
            return XAIR_SYM_OK;
        }
    }
    if (shared->terminal_count == shared->terminal_capacity) {
        size_t capacity = shared->terminal_capacity == 0 ? 16 : shared->terminal_capacity * 2;
        size_t allocation;
        xair_sym_context **contexts;
        xair_sym_state **states;
        if (capacity < shared->terminal_capacity ||
            capacity > SIZE_MAX / (sizeof(*contexts) + sizeof(*states))) {
            xair_mutex_unlock(&shared->lock); return XAIR_SYM_ERR_RESOURCE_LIMIT;
        }
        allocation = capacity * (sizeof(*contexts) + sizeof(*states));
        if (!budget_memory_reserve(&shared->budget, allocation)) {
            xair_mutex_unlock(&shared->lock); return XAIR_SYM_ERR_RESOURCE_LIMIT;
        }
        contexts = (xair_sym_context **)malloc(capacity * sizeof(*contexts));
        states = (xair_sym_state **)malloc(capacity * sizeof(*states));
        if (contexts == NULL || states == NULL) {
            free(states); free(contexts); budget_memory_release(&shared->budget, allocation);
            xair_mutex_unlock(&shared->lock); return XAIR_SYM_ERR_OOM;
        }
        if (shared->terminal_count != 0) {
            memcpy(contexts, shared->terminal_contexts,
                shared->terminal_count * sizeof(*contexts));
            memcpy(states, shared->terminal_states,
                shared->terminal_count * sizeof(*states));
        }
        free(shared->terminal_contexts); free(shared->terminal_states);
        budget_memory_release(&shared->budget,
            shared->terminal_capacity * (sizeof(*contexts) + sizeof(*states)));
        shared->terminal_contexts = contexts; shared->terminal_states = states;
        shared->terminal_capacity = capacity;
    }
    status = xair_sym_snapshot_take(state, &snapshot);
    if (status == XAIR_SYM_OK) status = xair_sym_snapshot_clone_isolated(snapshot, &isolated_context, &isolated_state);
    xair_sym_snapshot_destroy(snapshot);
    if (status == XAIR_SYM_OK) {
        size_t initial = 0;
        isolated_context->parallel_budget = &shared->budget;
        if (!isolated_allocation_estimate(isolated_context, isolated_state, &initial) ||
            !xair_sym_parallel_memory_reserve(isolated_context, initial))
            status = XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    if (status != XAIR_SYM_OK) {
        xair_sym_state_destroy(isolated_state); xair_sym_context_destroy(isolated_context);
        xair_mutex_unlock(&shared->lock); return status;
    }
    shared->terminal_contexts[shared->terminal_count] = isolated_context;
    shared->terminal_states[shared->terminal_count++] = isolated_state;
    if (shared->callback != NULL) status = shared->callback(state, shared->user);
    xair_mutex_unlock(&shared->lock);
    return status;
}

static xair_sym_expr_id first_partition_symbol(const xair_sym_context *context) {
    size_t i;
    for (i = 0; i < context->expression_count; ++i)
        if (context->expressions[i]->kind == XAIR_SYM_EXPR_SYMBOL) return (xair_sym_expr_id)i;
    return XAIR_SYM_INVALID_ID;
}

static xair_sym_status constrain_partition(xair_sym_state *state, size_t partition, size_t count) {
    xair_sym_expr_id symbol = first_partition_symbol(state->context);
    xair_sym_expr_id divisor = XAIR_SYM_INVALID_ID, index = XAIR_SYM_INVALID_ID;
    xair_sym_expr_id remainder = XAIR_SYM_INVALID_ID, condition = XAIR_SYM_INVALID_ID;
    xair_sym_expr_id partition_value = XAIR_SYM_INVALID_ID;
    uint16_t bits;
    xair_sym_status status;
    if (count <= 1) return XAIR_SYM_OK;
    if (symbol == XAIR_SYM_INVALID_ID) return partition == 0 ? XAIR_SYM_OK : XAIR_SYM_ERR_INFEASIBLE;
    bits = state->context->expressions[symbol]->bits;
    if (bits < 64) status = xair_sym_unary(state->context, XAIR_OP_ZEXT, 64, symbol, 0, &partition_value);
    else if (bits > 64) status = xair_sym_unary(state->context, XAIR_OP_EXTRACT, 64, symbol, 0, &partition_value);
    else { partition_value = symbol; status = XAIR_SYM_OK; }
    if (status == XAIR_SYM_OK) status = xair_sym_const(state->context, 64, (uint64_t)count, &divisor);
    if (status == XAIR_SYM_OK) status = xair_sym_const(state->context, 64, (uint64_t)partition, &index);
    if (status == XAIR_SYM_OK) status = xair_sym_binary(state->context, XAIR_OP_UREM, 64, partition_value, divisor, &remainder);
    if (status == XAIR_SYM_OK) status = xair_sym_binary(state->context, XAIR_OP_EQ, 1, remainder, index, &condition);
    if (status == XAIR_SYM_OK) status = xair_sym_state_assume(state, condition);
    if (status == XAIR_SYM_OK && state->constraints != NULL)
        state->partition_constraint_identity = state->constraints->identity;
    return status;
}

static int run_partition(void *opaque) {
    parallel_worker *worker = (parallel_worker *)opaque;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    worker->status = xair_sym_snapshot_clone_isolated(worker->snapshot, &context, &state);
    if (worker->status == XAIR_SYM_OK) {
        size_t initial = 0;
        context->parallel_budget = &worker->shared->budget;
        if (!isolated_allocation_estimate(context, state, &initial) ||
            !xair_sym_parallel_memory_reserve(context, initial))
            worker->status = XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    if (worker->status == XAIR_SYM_OK) worker->status = constrain_partition(
        state, worker->partition, worker->partition_count);
    if (worker->status == XAIR_SYM_ERR_INFEASIBLE) { worker->status = XAIR_SYM_OK; goto done; }
    if (worker->status == XAIR_SYM_OK) worker->status = xair_sym_state_attach_program(
        state, worker->shared->program);
    if (worker->status == XAIR_SYM_OK) worker->status = xair_sym_explore_detailed(state,
        &worker->options, invoke_unique_terminal, worker->shared, &worker->result, &worker->diagnostic);
done:
    xair_sym_state_destroy(state); xair_sym_context_destroy(context);
    return 0;
}

void xair_sym_parallel_options_init(xair_sym_parallel_options *options) {
    if (options == NULL) return;
    options->workers = 1; xair_sym_explore_options_init(&options->explore);
}

xair_sym_status xair_sym_parallel_explore_detailed(const xair_sym_snapshot *snapshot,
    const xair_sym_parallel_options *options, xair_sym_terminal_cb callback, void *user,
    xair_sym_explore_result *result, xair_diagnostic *diagnostic) {
    parallel_shared shared;
    parallel_worker *workers;
    xair_thread *threads;
    size_t i, created = 0, worker_count, program_bytes = 0, support_bytes = 0;
    xair_sym_status status = XAIR_SYM_OK;
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (diagnostic != NULL) xair_diagnostic_init(diagnostic);
    if (snapshot == NULL || options == NULL || result == NULL || options->workers == 0 || options->workers > 256)
        return XAIR_SYM_ERR_BAD_ARG;
    memset(&shared, 0, sizeof(shared));
    shared.callback = callback; shared.user = user;
    if (!xair_mutex_init(&shared.lock)) return XAIR_SYM_ERR_INTERNAL;
    if (!xair_mutex_init(&shared.budget.lock)) { xair_mutex_destroy(&shared.lock); return XAIR_SYM_ERR_INTERNAL; }
    worker_count = options->workers;
    if (worker_count > options->explore.max_states) worker_count = options->explore.max_states;
    if (worker_count > options->explore.max_block_steps) worker_count = options->explore.max_block_steps;
    if (worker_count == 0) { xair_mutex_destroy(&shared.budget.lock); xair_mutex_destroy(&shared.lock); return XAIR_SYM_ERR_BAD_ARG; }
    shared.budget.remaining_states = options->explore.max_states;
    shared.budget.remaining_steps = options->explore.max_block_steps;
    shared.budget.remaining_forks = options->explore.max_symbolic_forks;
    shared.budget.max_memory = options->explore.analysis.max_memory;
    shared.budget.remaining_memory = options->explore.analysis.max_memory;
    if (!program_allocation_estimate(snapshot->state->module, &program_bytes) ||
        (shared.budget.max_memory != 0 && program_bytes > shared.budget.remaining_memory)) {
        xair_mutex_destroy(&shared.budget.lock); xair_mutex_destroy(&shared.lock);
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    if (shared.budget.max_memory != 0) {
        shared.budget.remaining_memory -= program_bytes;
        shared.budget.peak_memory = program_bytes;
    }
    status = xair_sym_program_compile(snapshot->state->module, &shared.program);
    if (status != XAIR_SYM_OK) {
        xair_mutex_destroy(&shared.budget.lock); xair_mutex_destroy(&shared.lock); return status;
    }
    shared.budget.block_count = xair_module_block_count(snapshot->state->module);
    if (!add_allocation(&support_bytes,
            shared.budget.block_count != 0 ? shared.budget.block_count : 1u, sizeof(uint8_t)) ||
        !add_allocation(&support_bytes, worker_count, sizeof(*workers) + sizeof(*threads)) ||
        !budget_memory_reserve(&shared.budget, support_bytes)) {
        xair_sym_program_destroy(shared.program); xair_mutex_destroy(&shared.budget.lock);
        xair_mutex_destroy(&shared.lock); return XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    shared.budget.covered_blocks = (uint8_t *)calloc(shared.budget.block_count != 0 ? shared.budget.block_count : 1u, 1);
    if (shared.budget.covered_blocks == NULL) {
        budget_memory_release(&shared.budget, support_bytes);
        xair_sym_program_destroy(shared.program); xair_mutex_destroy(&shared.budget.lock);
        xair_mutex_destroy(&shared.lock); return XAIR_SYM_ERR_OOM;
    }
    workers = (parallel_worker *)calloc(worker_count, sizeof(*workers));
    threads = (xair_thread *)calloc(worker_count, sizeof(*threads));
    if (workers == NULL || threads == NULL) {
        free(threads); free(workers); free(shared.budget.covered_blocks);
        budget_memory_release(&shared.budget, support_bytes);
        xair_sym_program_destroy(shared.program); xair_mutex_destroy(&shared.budget.lock);
        xair_mutex_destroy(&shared.lock); return XAIR_SYM_ERR_OOM;
    }
    for (i = 0; i < worker_count; ++i) {
        workers[i].snapshot = snapshot; workers[i].options = options->explore; workers[i].shared = &shared;
        workers[i].partition = i; workers[i].partition_count = worker_count;
        workers[i].options.max_states = options->explore.max_states;
        workers[i].options.max_block_steps = options->explore.max_block_steps;
        workers[i].options.max_symbolic_forks = options->explore.max_symbolic_forks;
        workers[i].status = XAIR_SYM_ERR_INTERNAL;
        if (!xair_thread_create(&threads[i], run_partition, &workers[i])) { status = XAIR_SYM_ERR_INTERNAL; break; }
        created++;
    }
    for (i = 0; i < created; ++i) {
        int ignored;
        if (!xair_thread_join(&threads[i], &ignored) && status == XAIR_SYM_OK) status = XAIR_SYM_ERR_INTERNAL;
        if (workers[i].status != XAIR_SYM_OK && status == XAIR_SYM_OK) status = workers[i].status;
        result->states_processed += workers[i].result.states_processed;
        result->states_queued += workers[i].result.states_queued;
        result->states_pruned += workers[i].result.states_pruned;
        result->forks += workers[i].result.forks;
        result->solver_queries += workers[i].result.solver_queries;
        result->unresolved_operations += workers[i].result.unresolved_operations;
        result->limits_reached += workers[i].result.limits_reached;
    }
    result->workers_started = created; result->partitions = worker_count;
    result->peak_memory_bytes = shared.budget.peak_memory;
    for (i = 0; i < shared.budget.block_count; ++i)
        if (shared.budget.covered_blocks[i]) result->coverage_blocks++;
    result->terminal_states = shared.terminal_count;
    result->duplicate_terminal_states = shared.duplicates;
    result->completion_reason = status == XAIR_SYM_ERR_CANCELED ? XAIR_SYM_CANCELED :
        status == XAIR_SYM_ERR_RESOURCE_LIMIT ? XAIR_SYM_LIMIT_REACHED :
        status != XAIR_SYM_OK ? XAIR_SYM_FAILED :
        result->unresolved_operations != 0 ? XAIR_SYM_INCOMPLETE : XAIR_SYM_COMPLETED;
    if (diagnostic != NULL && status != XAIR_SYM_OK) {
        for (i = 0; i < created; ++i) if (workers[i].status == status) { *diagnostic = workers[i].diagnostic; break; }
    }
    for (i = 0; i < shared.terminal_count; ++i) {
        xair_sym_state_destroy(shared.terminal_states[i]);
        xair_sym_context_destroy(shared.terminal_contexts[i]);
    }
    free(shared.terminal_contexts); free(shared.terminal_states);
    xair_sym_program_destroy(shared.program);
    free(shared.budget.covered_blocks); xair_mutex_destroy(&shared.budget.lock);
    free(threads); free(workers); xair_mutex_destroy(&shared.lock);
    return status;
}

xair_sym_status xair_sym_parallel_explore(const xair_sym_snapshot *snapshot,
    const xair_sym_parallel_options *options, xair_sym_terminal_cb callback, void *user) {
    xair_sym_explore_result result;
    return xair_sym_parallel_explore_detailed(snapshot, options, callback, user, &result, NULL);
}
