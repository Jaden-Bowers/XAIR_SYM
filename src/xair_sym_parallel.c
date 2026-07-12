#include "xair_sym_internal.h"

#include <stdlib.h>
#include <threads.h>

typedef struct {
    const xair_sym_snapshot *snapshot;
    xair_sym_explore_options explore;
    xair_sym_terminal_cb callback;
    void *user;
    mtx_t *callback_lock;
    xair_sym_status status;
    size_t worker_index;
} xair_sym_worker;

typedef struct {
    xair_sym_terminal_cb callback;
    void *user;
    mtx_t *lock;
} synchronized_callback;

static xair_sym_status invoke_synchronized(xair_sym_state *state, void *user) {
    synchronized_callback *callback = (synchronized_callback *)user;
    xair_sym_status status;
    if (callback->callback == NULL) return XAIR_SYM_OK;
    if (mtx_lock(callback->lock) != thrd_success) return XAIR_SYM_ERR_BAD_ARG;
    status = callback->callback(state, callback->user);
    (void)mtx_unlock(callback->lock);
    return status;
}

static int run_worker(void *argument) {
    xair_sym_worker *worker = (xair_sym_worker *)argument;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_program *program = NULL;
    synchronized_callback callback;
    worker->status = xair_sym_snapshot_clone_isolated(worker->snapshot, &context, &state);
    if (worker->status != XAIR_SYM_OK) return 0;
    worker->status = xair_sym_program_compile(state->module, &program);
    if (worker->status == XAIR_SYM_OK) worker->status = xair_sym_state_attach_program(state, program);
    if (worker->status == XAIR_SYM_OK) {
        callback.callback = worker->callback; callback.user = worker->user; callback.lock = worker->callback_lock;
        worker->explore.search = (xair_sym_search_policy)(worker->worker_index % 3u);
        worker->status = xair_sym_explore_with_options(state, &worker->explore, invoke_synchronized, &callback);
    }
    xair_sym_program_destroy(program); xair_sym_state_destroy(state); xair_sym_context_destroy(context);
    return 0;
}

void xair_sym_parallel_options_init(xair_sym_parallel_options *options) {
    if (options == NULL) return;
    options->workers = 1;
    xair_sym_explore_options_init(&options->explore);
}

xair_sym_status xair_sym_parallel_explore(
    const xair_sym_snapshot *snapshot,
    const xair_sym_parallel_options *options,
    xair_sym_terminal_cb callback,
    void *user) {
    thrd_t *threads;
    xair_sym_worker *workers;
    mtx_t callback_lock;
    size_t created = 0;
    size_t i;
    xair_sym_status status = XAIR_SYM_OK;
    if (snapshot == NULL || options == NULL || options->workers == 0 || options->workers > 256) return XAIR_SYM_ERR_BAD_ARG;
    threads = (thrd_t *)calloc(options->workers, sizeof(*threads));
    workers = (xair_sym_worker *)calloc(options->workers, sizeof(*workers));
    if (threads == NULL || workers == NULL) { free(workers); free(threads); return XAIR_SYM_ERR_OOM; }
    if (mtx_init(&callback_lock, mtx_plain) != thrd_success) { free(workers); free(threads); return XAIR_SYM_ERR_BAD_ARG; }
    for (i = 0; i < options->workers; ++i) {
        workers[i].snapshot = snapshot; workers[i].explore = options->explore;
        workers[i].callback = callback; workers[i].user = user; workers[i].callback_lock = &callback_lock;
        workers[i].worker_index = i; workers[i].status = XAIR_SYM_ERR_BAD_ARG;
        if (thrd_create(&threads[i], run_worker, &workers[i]) != thrd_success) { status = XAIR_SYM_ERR_BAD_ARG; break; }
        created++;
    }
    for (i = 0; i < created; ++i) {
        int ignored;
        if (thrd_join(threads[i], &ignored) != thrd_success && status == XAIR_SYM_OK) status = XAIR_SYM_ERR_BAD_ARG;
        if (workers[i].status != XAIR_SYM_OK && status == XAIR_SYM_OK) status = workers[i].status;
    }
    mtx_destroy(&callback_lock); free(workers); free(threads); return status;
}
