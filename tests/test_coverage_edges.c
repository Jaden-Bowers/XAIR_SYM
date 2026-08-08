#include "xair_sym/xair_sym.h"
#include "../src/xair_sym_internal.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require_xair(xair_status status) { assert(status == XAIR_OK); }

static void require_sym_at(xair_sym_status status, int line) {
    if (status != XAIR_SYM_OK)
        fprintf(stderr, "unexpected symbolic status at line %d: %s\n", line,
            xair_sym_status_name(status));
    assert(status == XAIR_SYM_OK);
}
#define require_sym(status) require_sym_at((status), __LINE__)

static void make_module(xair_module **out_module, xair_block_id *out_block,
    xair_value_id *out_value) {
    require_xair(xair_module_create(out_module));
    require_xair(xair_block_create(*out_module, "edge_entry", out_block));
    require_xair(xair_block_add_param(*out_module, *out_block, xair_type_i(8),
        "edge_value", out_value));
    require_xair(xair_set_return(*out_module, *out_block, out_value, 1));
    require_xair(xair_module_freeze(*out_module));
}

static uint8_t *read_file(const char *path, size_t *out_size) {
    FILE *file = fopen(path, "rb");
    long length;
    uint8_t *bytes;
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    length = ftell(file);
    assert(length >= 0);
    assert(fseek(file, 0, SEEK_SET) == 0);
    bytes = (uint8_t *)malloc((size_t)length != 0 ? (size_t)length : 1u);
    assert(bytes != NULL);
    assert(fread(bytes, 1, (size_t)length, file) == (size_t)length);
    assert(fclose(file) == 0);
    *out_size = (size_t)length;
    return bytes;
}

static void refresh_snapshot_checksum(uint8_t *bytes, size_t size) {
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t i;
    assert(size >= 8);
    for (i = 0; i < size - 8; ++i)
        hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
    for (i = 0; i < 8; ++i) bytes[size - 8 + i] = (uint8_t)(hash >> (i * 8u));
}

static xair_sym_status count_terminal(xair_sym_state *state, void *user) {
    size_t *count = (size_t *)user;
    assert(state != NULL);
    ++*count;
    return XAIR_SYM_OK;
}

static xair_sym_status noop_model(xair_sym_state *state, xair_op_id op, void *user) {
    (void)state; (void)op; (void)user;
    return XAIR_SYM_OK;
}

static void test_concolic_and_exchange_edges(xair_module *module,
    xair_block_id block) {
    static const char path[] = "xair_sym_coverage_testcase.bin";
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL, *inverted = NULL;
    xair_sym_trace *trace = NULL;
    xair_sym_trace_branch branch;
    xair_sym_expr_id symbol, wide, answer, condition, concrete;
    xair_sym_expr_view view;
    uint8_t payload[3] = {1, 2, 3}, loaded[4] = {0};
    size_t loaded_size = 99, i;
    FILE *file;

    remove(path);
    assert(xair_sym_trace_create(NULL) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_trace_create(&trace));
    assert(xair_sym_trace_count(NULL) == 0);
    assert(xair_sym_trace_add_branch(NULL, block, 0, 0) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_trace_add_branch(trace, block, XAIR_SYM_INVALID_ID, 0) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "edge_symbol", &symbol));
    require_sym(xair_sym_const_wide(context, 128, 1, 2, &wide));
    require_sym(xair_sym_const(context, 8, 42, &answer));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, symbol, answer, &condition));
    for (i = 0; i < 17; ++i)
        require_sym(xair_sym_trace_add_branch(trace, block, condition, (i & 1u) != 0u));
    assert(xair_sym_trace_count(trace) == 17);
    require_sym(xair_sym_trace_get(trace, 0, &branch));
    assert(branch.block == block && branch.condition == condition && branch.taken == 0);
    assert(xair_sym_trace_get(NULL, 0, &branch) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_trace_get(trace, 17, &branch) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_trace_get(trace, 0, NULL) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_concolic_invert(state, trace, 0, &inverted));
    xair_sym_state_destroy(inverted);
    inverted = NULL;
    assert(xair_sym_concolic_invert(NULL, trace, 0, &inverted) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_concolic_invert(state, trace, 17, &inverted) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_state_concretize(state, symbol, &concrete));
    require_sym(xair_sym_expr_get(context, concrete, &view));
    assert(view.kind == XAIR_SYM_EXPR_CONST && view.bits == 8);
    assert(xair_sym_state_concretize(state, wide, &concrete) == XAIR_SYM_ERR_UNSUPPORTED);
    assert(xair_sym_state_concretize(NULL, symbol, &concrete) == XAIR_SYM_ERR_BAD_ARG);

    assert(xair_sym_testcase_write(NULL, payload, sizeof(payload)) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_testcase_write(path, NULL, 1) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_testcase_write(path, payload, sizeof(payload)));
    assert(xair_sym_testcase_read(path, loaded, 2, &loaded_size) == XAIR_SYM_ERR_RANGE);
    require_sym(xair_sym_testcase_read(path, loaded, sizeof(loaded), &loaded_size));
    assert(loaded_size == sizeof(payload) && memcmp(loaded, payload, sizeof(payload)) == 0);
    remove(path);
    assert(xair_sym_testcase_read(path, loaded, sizeof(loaded), &loaded_size) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_testcase_read(NULL, loaded, sizeof(loaded), &loaded_size) == XAIR_SYM_ERR_BAD_ARG);
    file = fopen(path, "wb"); assert(file != NULL);
    assert(fwrite("not-a-testcase", 1, 14, file) == 14); assert(fclose(file) == 0);
    assert(xair_sym_testcase_read(path, loaded, sizeof(loaded), &loaded_size) == XAIR_SYM_ERR_BAD_ARG);
    remove(path);
    require_sym(xair_sym_testcase_write(path, NULL, 0));
    require_sym(xair_sym_testcase_read(path, NULL, 0, &loaded_size));
    assert(loaded_size == 0);
    remove(path);

    xair_sym_trace_destroy(trace);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
}

static void test_memory_edges(xair_module *module, xair_block_id block) {
    static const uint8_t backing[2] = {0x11, 0x22};
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL, *clone = NULL;
    xair_sym_expr_id byte, other, address, loaded;
    xair_sym_taint_id taint, loaded_taint, union_taint;
    xair_sym_object_id object, second;

    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_const(context, 8, 0xaa, &byte));
    require_sym(xair_sym_const(context, 8, 0xbb, &other));
    require_sym(xair_sym_symbol(context, 64, "edge_address", &address));
    require_sym(xair_sym_taint_source(context, "edge_memory", &taint));
    assert(xair_sym_memory_make_unique(NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_memory_map_lazy(state, 0x1000, 0, 3, NULL, 0, 0, &object) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_memory_map_lazy(state, 0x1000, 2, 3, backing, sizeof(backing), 0, &object));
    assert(xair_sym_object_add(state, 0x1001, 2, 3, &second) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_object_add(state, 0x2000, 2, 3, &second));
    require_sym(xair_sym_memory_load8(state, 0x1000, &loaded));
    require_sym(xair_sym_memory_store8(state, 0x1000, byte));
    require_sym(xair_sym_memory_store_taint8(state, 0x1000, taint));
    require_sym(xair_sym_state_clone(state, &clone));
    require_sym(xair_sym_memory_store8(clone, 0x1000, other));
    require_sym(xair_sym_memory_load8(state, 0x1000, &loaded)); assert(loaded == byte);
    require_sym(xair_sym_memory_load8(clone, 0x1000, &loaded)); assert(loaded == other);
    require_sym(xair_sym_memory_union_taint(state, 1, XAIR_SYM_TAINT_NONE, 0, &union_taint));
    assert(union_taint == taint);
    require_sym(xair_sym_memory_union_taint(state, 1, taint, 1, &union_taint));
    require_sym(xair_sym_memory_load_taint8(state, 0x1000, &loaded_taint));
    assert(loaded_taint != XAIR_SYM_TAINT_NONE);
    require_sym(xair_sym_memory_load_symbolic8(state, address, &loaded, &loaded_taint));
    require_sym(xair_sym_memory_store_symbolic8(state, address, other, taint));
    assert(xair_sym_memory_validate_range(state, 0x1000, 0, 1) == XAIR_SYM_ERR_RANGE);
    assert(xair_sym_memory_validate_range(state, UINT64_MAX, 2, 1) == XAIR_SYM_ERR_RANGE);
    assert(xair_sym_object_remove(state, 99) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_object_remove_containing(state, 0x2001) == XAIR_SYM_ERR_RANGE);
    require_sym(xair_sym_object_remove_containing(state, 0x2000));
    xair_sym_memory_havoc(state);
    assert(state->memory_havoc_version == 1);
    require_sym(xair_sym_object_remove(state, object));
    xair_sym_state_destroy(clone);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
}

static void test_snapshot_edges(xair_module *module, xair_block_id block,
    xair_value_id value) {
    static const char path[] = "xair_sym_coverage_snapshot.bin";
    xair_sym_context *context = NULL, *isolated_context = NULL;
    xair_sym_state *state = NULL, *isolated_state = NULL;
    xair_sym_environment *environment = NULL;
    xair_sym_snapshot *snapshot = NULL, *loaded = NULL;
    xair_sym_snapshot_metadata metadata, mismatched;
    xair_sym_expr_id symbol, one, condition;
    xair_sym_taint_id source_taint, sanitized_taint, transformed_taint, sink_taint;
    xair_sym_object_id object;
    static const uint8_t backing[] = {1, 0, 2, 0, 3, 0, 4, 0};
    uint8_t *bytes, *corrupt;
    size_t size, i, limit;

    remove(path);
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "snapshot_edge", &symbol));
    require_sym(xair_sym_const(context, 8, 1, &one));
    require_sym(xair_sym_binary(context, XAIR_OP_NE, 1, symbol, one, &condition));
    require_sym(xair_sym_state_assume(state, condition));
    require_sym(xair_sym_taint_source(context, "snapshot_source", &source_taint));
    require_sym(xair_sym_taint_sanitize_ex(context, source_taint,
        "snapshot_sanitizer", 1, &sanitized_taint));
    require_sym(xair_sym_taint_transform(context, sanitized_taint,
        "snapshot_transform", condition, 1, &transformed_taint));
    require_sym(xair_sym_taint_sink(context, transformed_taint,
        "snapshot_sink", 0x5000, &sink_taint));
    require_sym(xair_sym_state_set_value(state, value, symbol));
    require_sym(xair_sym_state_set_taint(state, value, sink_taint));
    require_sym(xair_sym_memory_map_lazy(state, 0x5000, 16, 3,
        backing, sizeof(backing), 1, &object));
    require_sym(xair_sym_memory_store8(state, 0x500f, symbol));
    require_sym(xair_sym_memory_store_taint8(state, 0x500f, transformed_taint));
    require_sym(xair_sym_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64,
        XAIR_CC_SYSV_X64, UINT64_C(0x00010000), UINT64_C(0x70000000),
        0x1000, UINT64_C(0x40000000), &environment));
    xair_sym_environment_attach_builtin(state, environment); environment = NULL;
    require_sym(xair_sym_snapshot_take(state, &snapshot));
    require_sym(xair_sym_snapshot_metadata_get(snapshot, &metadata));
    require_sym(xair_sym_snapshot_save(snapshot, path));
    bytes = read_file(path, &size);
    require_sym(xair_sym_snapshot_load_bytes(context, module, bytes, size, &loaded));
    xair_sym_snapshot_destroy(loaded); loaded = NULL;
    require_sym(xair_sym_snapshot_load_bytes_checked(context, module, bytes, size,
        &metadata, 0, &loaded));
    xair_sym_snapshot_destroy(loaded); loaded = NULL;
    mismatched = metadata; mismatched.binary_hash++;
    assert(xair_sym_snapshot_load_bytes_checked(context, module, bytes, size,
        &mismatched, XAIR_SYM_SNAPSHOT_EXPECT_BINARY, &loaded) != XAIR_SYM_OK);
    assert(xair_sym_snapshot_load_bytes_checked(context, module, bytes, size,
        &metadata, UINT32_MAX, &loaded) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_snapshot_load_bytes(NULL, module, bytes, size, &loaded) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_snapshot_load_bytes(context, module, NULL, size, &loaded) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_snapshot_clone_isolated(snapshot, &isolated_context, &isolated_state));
    xair_sym_state_destroy(isolated_state); xair_sym_context_destroy(isolated_context);
    assert(xair_sym_snapshot_clone_isolated(NULL, &isolated_context, &isolated_state) == XAIR_SYM_ERR_BAD_ARG);

    limit = size - 8u;
    for (i = 0; i < limit; ++i) {
        xair_sym_context *fresh = NULL;
        require_sym(xair_sym_context_create(&fresh));
        assert(xair_sym_snapshot_load_bytes(fresh, module, bytes, i, &loaded) != XAIR_SYM_OK);
        assert(loaded == NULL);
        xair_sym_context_destroy(fresh);
    }
    corrupt = (uint8_t *)malloc(size); assert(corrupt != NULL);
    memcpy(corrupt, bytes, size);
    limit = size;
    for (i = 0; i < limit; ++i) {
        static const uint8_t mutations[] = {0, 0xff, 0x5a};
        size_t mutation;
        uint8_t saved = corrupt[i];
        for (mutation = 0; mutation < sizeof(mutations); ++mutation) {
            xair_sym_context *fresh = NULL;
            corrupt[i] = mutations[mutation];
            if (corrupt[i] == saved) continue;
            refresh_snapshot_checksum(corrupt, size);
            require_sym(xair_sym_context_create(&fresh));
            if (xair_sym_snapshot_load_bytes(fresh, module, corrupt, size, &loaded) == XAIR_SYM_OK)
                xair_sym_snapshot_destroy(loaded);
            xair_sym_context_destroy(fresh);
            loaded = NULL;
        }
        corrupt[i] = saved;
        refresh_snapshot_checksum(corrupt, size);
    }
    {
        uint64_t seed = UINT64_C(0x9e3779b97f4a7c15);
        size_t iteration;
        for (iteration = 0; iteration < 4096; ++iteration) {
            xair_sym_context *fresh = NULL;
            size_t changes, change;
            memcpy(corrupt, bytes, size);
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            changes = 1u + (size_t)(seed & 3u);
            for (change = 0; change < changes; ++change) {
                size_t position;
                seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                position = (size_t)(seed % (size - 8u));
                corrupt[position] = (uint8_t)(seed >> 24u);
            }
            refresh_snapshot_checksum(corrupt, size);
            require_sym(xair_sym_context_create(&fresh));
            if (xair_sym_snapshot_load_bytes(fresh, module, corrupt, size, &loaded) == XAIR_SYM_OK)
                xair_sym_snapshot_destroy(loaded);
            xair_sym_context_destroy(fresh); loaded = NULL;
        }
    }
    free(corrupt); free(bytes); remove(path);
    xair_sym_snapshot_destroy(snapshot);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
}

static void test_environment_parallel_and_cancel(xair_module *module,
    xair_block_id block, xair_value_id value) {
    xair_sym_context *context = NULL, *cancel_context = NULL;
    xair_sym_state *state = NULL, *cancel_state = NULL;
    xair_sym_environment *environment = NULL, *copy = NULL;
    xair_sym_snapshot *snapshot = NULL;
    xair_sym_parallel_options parallel;
    xair_sym_model_kind kind;
    xair_sym_model_info info;
    xair_sym_model_identity identity = {0};
    xair_analysis_options analysis;
    xair_sym_cancel_token *token = NULL;
    xair_sym_expr_id symbol, one, condition;
    xair_sym_sat sat;
    size_t terminal_count = 0;
    uint64_t first_buffer, second_buffer;
    xair_sym_expr_id input_symbols[4];
    size_t i;

    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "parallel_edge", &symbol));
    require_sym(xair_sym_state_set_value(state, value, symbol));
    require_sym(xair_sym_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64,
        XAIR_CC_SYSV_X64, UINT64_C(0x00010000), UINT64_C(0x70000000),
        0x1000, UINT64_C(0x40000000), &environment));
    require_sym(xair_sym_environment_clone_builtin(environment, context, &copy));
    xair_sym_environment_attach_builtin(state, copy); copy = NULL;
    require_sym(xair_sym_environment_model(environment, "malloc", &kind));
    assert(kind == XAIR_SYM_MODEL_ALLOC);
    assert(xair_sym_environment_model(NULL, "malloc", &kind) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_environment_model(environment, NULL, &kind) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_environment_model_info(environment, "definitely_unknown", &info));
    assert(info.kind == XAIR_SYM_MODEL_UNKNOWN);
    identity.name = "malloc";
    require_sym(xair_sym_environment_model_identity(environment, &identity, &info));
    assert(xair_sym_environment_register_model(NULL, &identity, &info,
        noop_model, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_environment_register_model(environment, NULL, &info,
        noop_model, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_environment_register_model(environment, &identity, &info,
        NULL, NULL) == XAIR_SYM_ERR_BAD_ARG);
    for (i = 0; i < 9; ++i) {
        char name[32];
        xair_sym_model_identity registered = {0};
        (void)snprintf(name, sizeof(name), "edge_model_%zu", i);
        registered.module = (i & 1u) != 0u ? "edge_module" : NULL;
        registered.name = name;
        registered.ordinal = (uint32_t)(i + 1u);
        registered.address = 0x1000 + i;
        registered.user_identity = (i & 1u) != 0u ? "edge_semantic" : NULL;
        info.kind = XAIR_SYM_MODEL_LENGTH;
        info.version_major = 1; info.version_minor = (uint16_t)i;
        require_sym(xair_sym_environment_register_model(environment, &registered,
            &info, noop_model, NULL));
    }
    identity.module = "edge_module"; identity.name = "edge_model_1";
    identity.ordinal = 2; identity.address = 0x1001; identity.user_identity = "edge_semantic";
    require_sym(xair_sym_environment_model_identity(environment, &identity, &info));
    assert(info.kind == XAIR_SYM_MODEL_LENGTH);
    identity.module = "wrong";
    require_sym(xair_sym_environment_model_identity(environment, &identity, &info));
    assert(info.kind == XAIR_SYM_MODEL_UNKNOWN);
    identity.module = NULL; identity.name = "read"; identity.ordinal = 0;
    identity.address = 0; identity.user_identity = NULL;
    require_sym(xair_sym_environment_model_identity(environment, &identity, &info));
    assert(info.kind == XAIR_SYM_MODEL_INPUT);
    assert(xair_sym_environment_allocate(environment, state, 0, &first_buffer) == XAIR_SYM_ERR_BAD_ARG);
    require_sym(xair_sym_environment_allocate(environment, state, 16, &first_buffer));
    require_sym(xair_sym_environment_allocate(environment, state, 16, &second_buffer));
    require_sym(xair_sym_environment_input(environment, state, first_buffer, 0,
        "network", NULL));
    require_sym(xair_sym_environment_input(environment, state, first_buffer, 1,
        "network", input_symbols));
    require_sym(xair_sym_environment_input(environment, state, first_buffer + 1, 1,
        "file", input_symbols + 1));
    require_sym(xair_sym_environment_input(environment, state, first_buffer + 2, 1,
        "driver", input_symbols + 2));
    require_sym(xair_sym_environment_input(environment, state, first_buffer + 3, 1,
        "user", input_symbols + 3));
    require_sym(xair_sym_environment_copy(environment, state, second_buffer, first_buffer, 4));
    require_sym(xair_sym_environment_copy(environment, state, second_buffer, first_buffer, 0));
    assert(xair_sym_environment_copy(environment, state, UINT64_MAX, first_buffer,
        2) == XAIR_SYM_ERR_RANGE);
    require_sym(xair_sym_snapshot_take(state, &snapshot));
    xair_sym_parallel_options_init(&parallel);
    parallel.workers = 1;
    require_sym(xair_sym_parallel_explore(snapshot, &parallel, count_terminal, &terminal_count));
    assert(terminal_count == 1);
    assert(xair_sym_parallel_explore(NULL, &parallel, count_terminal, &terminal_count) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_parallel_explore(snapshot, NULL, count_terminal, &terminal_count) == XAIR_SYM_ERR_BAD_ARG);

    require_sym(xair_sym_cancel_token_create(&token));
    assert(!xair_sym_cancel_token_requested(token));
    xair_sym_cancel_token_request(token);
    assert(xair_sym_cancel_token_requested(token));
    require_sym(xair_sym_context_create(&cancel_context));
    xair_analysis_options_init(&analysis); analysis.cancel_token = token;
    xair_sym_context_set_analysis_options(cancel_context, &analysis);
    require_sym(xair_sym_state_create(cancel_context, module, block, &cancel_state));
    require_sym(xair_sym_symbol(cancel_context, 8, "cancel_edge", &symbol));
    require_sym(xair_sym_const(cancel_context, 8, 1, &one));
    require_sym(xair_sym_binary(cancel_context, XAIR_OP_EQ, 1, symbol, one, &condition));
    assert(xair_sym_check(cancel_state, condition, &sat) == XAIR_SYM_ERR_CANCELED);
    xair_sym_cancel_token_reset(token);
    assert(!xair_sym_cancel_token_requested(token));

    xair_sym_state_destroy(cancel_state); xair_sym_context_destroy(cancel_context);
    xair_sym_cancel_token_destroy(token);
    xair_sym_snapshot_destroy(snapshot);
    xair_sym_environment_destroy(environment);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
}

static void check_expression(xair_sym_state *state, xair_sym_context *context,
    xair_sym_expr_id expression) {
    xair_sym_expr_id zero, condition;
    xair_sym_sat sat;
    uint16_t bits = context->expressions[expression]->bits;
    require_sym(xair_sym_const(context, bits, 0, &zero));
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, expression, zero, &condition));
    require_sym(xair_sym_check(state, condition, &sat));
    assert(sat == XAIR_SYM_SAT);
}

static void test_operator_and_folding_matrix(xair_module *module, xair_block_id block) {
    static const xair_opcode arithmetic[] = {
        XAIR_OP_ADD, XAIR_OP_SUB, XAIR_OP_MUL, XAIR_OP_UDIV, XAIR_OP_SDIV,
        XAIR_OP_UREM, XAIR_OP_SREM, XAIR_OP_AND, XAIR_OP_OR, XAIR_OP_XOR,
        XAIR_OP_SHL, XAIR_OP_LSHR, XAIR_OP_ASHR, XAIR_OP_ROL, XAIR_OP_ROR,
        XAIR_OP_ADDR_ADD, XAIR_OP_ADDR_SUB
    };
    static const xair_opcode comparisons[] = {
        XAIR_OP_EQ, XAIR_OP_NE, XAIR_OP_ULT, XAIR_OP_ULE, XAIR_OP_SLT, XAIR_OP_SLE
    };
    static const xair_opcode extracts[] = {
        XAIR_OP_FLAG_ZF, XAIR_OP_FLAG_CF, XAIR_OP_FLAG_OF,
        XAIR_OP_FLAG_SF, XAIR_OP_FLAG_PF, XAIR_OP_FLAG_AF
    };
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_expr_id a, b, condition, expression, wide, low, high, selected;
    xair_sym_expr_id flags[4];
    xair_sym_expr_id c0, c1, c7, c8, cff, cmin, cneg1;
    size_t i, j;
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 8, "matrix_a", &a));
    require_sym(xair_sym_symbol(context, 8, "matrix_b", &b));
    for (i = 0; i < sizeof(arithmetic) / sizeof(arithmetic[0]); ++i) {
        require_sym(xair_sym_binary(context, arithmetic[i], 8, a, b, &expression));
        check_expression(state, context, expression);
    }
    for (i = 0; i < sizeof(comparisons) / sizeof(comparisons[0]); ++i) {
        xair_sym_sat sat;
        require_sym(xair_sym_binary(context, comparisons[i], 1, a, b, &condition));
        require_sym(xair_sym_check(state, condition, &sat));
    }
    require_sym(xair_sym_unary(context, XAIR_OP_ZEXT, 16, a, 0, &wide));
    check_expression(state, context, wide);
    require_sym(xair_sym_unary(context, XAIR_OP_SEXT, 16, a, 0, &wide));
    check_expression(state, context, wide);
    require_sym(xair_sym_unary(context, XAIR_OP_TRUNC, 4, a, 0, &low));
    check_expression(state, context, low);
    require_sym(xair_sym_unary(context, XAIR_OP_EXTRACT, 4, a, 4, &high));
    check_expression(state, context, high);
    require_sym(xair_sym_binary(context, XAIR_OP_CONCAT, 8, low, high, &expression));
    check_expression(state, context, expression);
    require_sym(xair_sym_binary(context, XAIR_OP_EQ, 1, a, b, &condition));
    require_sym(xair_sym_select(context, condition, a, b, &selected));
    check_expression(state, context, selected);
    require_sym(xair_sym_unary(context, XAIR_OP_INT_TO_ADDR, 8, a, 0, &expression));
    check_expression(state, context, expression);
    require_sym(xair_sym_unary(context, XAIR_OP_ADDR_TO_INT, 8, a, 0, &expression));
    check_expression(state, context, expression);

    require_sym(xair_sym_unary(context, XAIR_OP_FLAGS_LOGIC, 6, a, 0, &flags[0]));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_ADD, 6, a, b, &flags[1]));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_SUB, 6, a, b, &flags[2]));
    require_sym(xair_sym_binary(context, XAIR_OP_FLAGS_SHL, 6, a, b, &flags[3]));
    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
        for (j = 0; j < sizeof(extracts) / sizeof(extracts[0]); ++j) {
            xair_sym_sat sat;
            require_sym(xair_sym_unary(context, extracts[j], 1, flags[i], 0, &expression));
            require_sym(xair_sym_check(state, expression, &sat));
        }
    }

    require_sym(xair_sym_const(context, 8, 0, &c0));
    require_sym(xair_sym_const(context, 8, 1, &c1));
    require_sym(xair_sym_const(context, 8, 7, &c7));
    require_sym(xair_sym_const(context, 8, 8, &c8));
    require_sym(xair_sym_const(context, 8, 0xff, &cff));
    require_sym(xair_sym_binary(context, XAIR_OP_ASHR, 8, cff, c8, &expression));
    require_sym(xair_sym_binary(context, XAIR_OP_ROL, 8, c1, c0, &expression));
    require_sym(xair_sym_binary(context, XAIR_OP_ROR, 8, c1, c7, &expression));
    require_sym(xair_sym_binary(context, XAIR_OP_SDIV, 8, cff, c1, &expression));
    require_sym(xair_sym_binary(context, XAIR_OP_SREM, 8, cff, c1, &expression));
    require_sym(xair_sym_const(context, 64, UINT64_C(0x8000000000000000), &cmin));
    require_sym(xair_sym_const(context, 64, UINT64_MAX, &cneg1));
    require_sym(xair_sym_binary(context, XAIR_OP_SDIV, 64, cmin, cneg1, &expression));
    require_sym(xair_sym_binary(context, XAIR_OP_UDIV, 8, cff, c0, &expression));
    require_sym(xair_sym_unary(context, XAIR_OP_SEXT, 16, cff, 0, &wide));
    assert(xair_sym_binary(context, XAIR_OP_CONCAT, 8, a, b, &expression) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_unary(context, XAIR_OP_EXTRACT, 8, a, 1, &expression) == XAIR_SYM_ERR_BAD_ARG);
    xair_sym_state_destroy(state);
    xair_sym_context_destroy(context);
}

static void test_unknown_environment_call(void) {
    xair_module *module = NULL;
    xair_block_id block;
    xair_value_id argument, inputs[1], results[2];
    xair_type result_types[2] = {xair_type_i(64), xair_type_mem(0, 64)};
    const char *result_names[2] = {"unknown_result", "memory"};
    xair_op_attributes attributes;
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_environment *environment = NULL;
    xair_sym_expr_id argument_expr;
    xair_sym_taint_id argument_taint;
    xair_sym_explore_options options;
    xair_sym_explore_result result;
    xair_diagnostic diagnostic;
    size_t terminals = 0;
    memset(&attributes, 0, sizeof(attributes));
    attributes.kind = XAIR_ATTR_CALL;
    attributes.call_kind = XAIR_CALL_DIRECT_EXTERNAL;
    attributes.calling_convention = XAIR_CC_SYSV_X64;
    attributes.effects = XAIR_EFFECT_READ_MEMORY | XAIR_EFFECT_WRITE_MEMORY;
    attributes.import_module = "unknown_module";
    attributes.import_name = "unknown_edge_call";
    require_xair(xair_module_create(&module));
    require_xair(xair_block_create(module, "unknown_environment", &block));
    require_xair(xair_block_add_param(module, block, xair_type_i(64), "argument", &argument));
    inputs[0] = argument;
    require_xair(xair_build_call(module, block, inputs, 1, result_types,
        result_names, 2, &attributes, results));
    require_xair(xair_set_return(module, block, results, 1));
    require_xair(xair_module_freeze(module));
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_symbol(context, 64, "unknown_argument", &argument_expr));
    require_sym(xair_sym_taint_source(context, "unknown_argument_taint", &argument_taint));
    require_sym(xair_sym_state_set_value(state, argument, argument_expr));
    require_sym(xair_sym_state_set_taint(state, argument, argument_taint));
    require_sym(xair_sym_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64,
        XAIR_CC_SYSV_X64, UINT64_C(0x00010000), UINT64_C(0x70000000),
        0x1000, UINT64_C(0x40000000), &environment));
    require_sym(xair_sym_state_attach_environment(state, environment));
    xair_sym_environment_destroy(environment);
    xair_sym_explore_options_init(&options);
    options.max_states = 4; options.max_block_steps = 4;
    require_sym(xair_sym_explore_detailed(state, &options, count_terminal,
        &terminals, &result, &diagnostic));
    assert(terminals == 1 && result.completion_reason == XAIR_SYM_INCOMPLETE &&
        result.unresolved_operations == 1);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context);
    xair_module_destroy(module);
}

static void test_builtin_environment_calls(void) {
    static const char *names[] = {"malloc", "calloc", "memset", "memcpy",
        "strlen", "read", "ProbeForRead", "free", "IoCompleteRequest"};
    xair_module *module = NULL;
    xair_block_id block;
    xair_value_id arguments[3], calloc_inputs[2], call_result, returns[1];
    xair_sym_context *context = NULL;
    xair_sym_state *state = NULL;
    xair_sym_environment *environment = NULL;
    xair_sym_expr_id constants[3], byte, zero;
    xair_sym_explore_options options;
    xair_sym_explore_result result;
    xair_diagnostic diagnostic;
    uint64_t destination, source;
    size_t i, terminals = 0;
    require_xair(xair_module_create(&module));
    require_xair(xair_block_create(module, "builtin_environment", &block));
    for (i = 0; i < 3; ++i)
        require_xair(xair_block_add_param(module, block, xair_type_i(64),
            "argument", &arguments[i]));
    calloc_inputs[0] = arguments[2]; calloc_inputs[1] = arguments[2];
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        xair_op_attributes attributes;
        xair_type result_type = xair_type_i(64);
        const char *result_name = "call_result";
        const xair_value_id *inputs = arguments;
        size_t input_count = 3;
        size_t result_count = 1;
        memset(&attributes, 0, sizeof(attributes));
        attributes.kind = XAIR_ATTR_CALL;
        attributes.call_kind = XAIR_CALL_DIRECT_EXTERNAL;
        attributes.calling_convention = XAIR_CC_SYSV_X64;
        attributes.effects = XAIR_EFFECT_READ_MEMORY | XAIR_EFFECT_WRITE_MEMORY;
        attributes.import_name = names[i];
        if (strcmp(names[i], "malloc") == 0) { inputs = &arguments[2]; input_count = 1; }
        if (strcmp(names[i], "calloc") == 0) { inputs = calloc_inputs; input_count = 2; }
        if (strcmp(names[i], "strlen") == 0) { inputs = &arguments[1]; input_count = 1; }
        if (strcmp(names[i], "free") == 0) input_count = 1;
        if (strcmp(names[i], "ProbeForRead") == 0) { inputs = &arguments[1]; input_count = 2; }
        if (strcmp(names[i], "IoCompleteRequest") == 0) { input_count = 0; result_count = 0; }
        require_xair(xair_build_call(module, block, inputs, input_count,
            result_count != 0 ? &result_type : NULL,
            result_count != 0 ? &result_name : NULL, result_count,
            &attributes, result_count != 0 ? &call_result : NULL));
    }
    returns[0] = arguments[0];
    require_xair(xair_set_return(module, block, returns, 1));
    require_xair(xair_module_freeze(module));
    require_sym(xair_sym_context_create(&context));
    require_sym(xair_sym_state_create(context, module, block, &state));
    require_sym(xair_sym_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64,
        XAIR_CC_SYSV_X64, UINT64_C(0x00010000), UINT64_C(0x70000000),
        0x1000, UINT64_C(0x40000000), &environment));
    require_sym(xair_sym_environment_allocate(environment, state, 16, &destination));
    require_sym(xair_sym_environment_allocate(environment, state, 16, &source));
    require_sym(xair_sym_const(context, 8, 'A', &byte));
    require_sym(xair_sym_const(context, 8, 0, &zero));
    require_sym(xair_sym_memory_store8(state, source, byte));
    require_sym(xair_sym_memory_store8(state, source + 1u, zero));
    require_sym(xair_sym_const(context, 64, destination, &constants[0]));
    require_sym(xair_sym_const(context, 64, source, &constants[1]));
    require_sym(xair_sym_const(context, 64, 2, &constants[2]));
    for (i = 0; i < 3; ++i)
        require_sym(xair_sym_state_set_value(state, arguments[i], constants[i]));
    require_sym(xair_sym_state_attach_environment(state, environment));
    xair_sym_environment_destroy(environment);
    xair_sym_explore_options_init(&options);
    options.max_states = 4; options.max_block_steps = 32;
    require_sym(xair_sym_explore_detailed(state, &options, count_terminal,
        &terminals, &result, &diagnostic));
    assert(terminals == 1 && result.completion_reason == XAIR_SYM_COMPLETED);
    xair_sym_state_destroy(state); xair_sym_context_destroy(context);
    xair_module_destroy(module);
}

int main(void) {
    xair_module *module = NULL;
    xair_block_id block;
    xair_value_id value;
    make_module(&module, &block, &value);
    assert(strcmp(xair_sym_version_string(), "0.6.0") == 0);
    test_concolic_and_exchange_edges(module, block);
    test_memory_edges(module, block);
    test_snapshot_edges(module, block, value);
    test_environment_parallel_and_cancel(module, block, value);
    test_operator_and_folding_matrix(module, block);
    test_unknown_environment_call();
    test_builtin_environment_calls();
    xair_module_destroy(module);
    return 0;
}
