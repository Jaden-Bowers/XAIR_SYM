#include "xair_sym/xair_sym.h"
#include "../src/xair_sym_internal.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_environment_retain(xair_sym_environment *environment);
void test_environment_release(xair_sym_environment *environment);
xair_sym_status test_environment_model_info(const xair_sym_environment *environment,
    const char *name, xair_sym_model_info *out_info);
xair_sym_status test_environment_input(xair_sym_environment *environment,
    xair_sym_state *state, uint64_t address, size_t size,
    const char *source_name, xair_sym_expr_id *out_symbols);
xair_sym_status test_environment_copy(xair_sym_environment *environment,
    xair_sym_state *state, uint64_t destination, uint64_t source, size_t size);

#define xair_sym_model_call_get test_model_call_get
#define xair_sym_model_call_argument_get test_model_call_argument_get
#define xair_sym_model_call_result_set test_model_call_result_set
#define xair_sym_model_call_mark_incomplete test_model_call_mark_incomplete
#define xair_sym_model_call_terminate test_model_call_terminate
#define xair_sym_model_call_confidence_set test_model_call_confidence_set
#define xair_sym_environment_clone_builtin test_environment_clone_builtin
#define xair_sym_environment_create_builtin_snapshot test_environment_create_builtin_snapshot
#define xair_sym_environment_create_builtin test_environment_create_builtin
#define xair_sym_environment_attach_builtin test_environment_attach_builtin
#define xair_sym_process_options_init test_process_options_init
#define xair_sym_process_create test_process_create
#define xair_sym_environment_retain test_environment_retain
#define xair_sym_environment_release test_environment_release
#define xair_sym_environment_destroy test_environment_destroy
#define xair_sym_state_attach_environment test_state_attach_environment
#define xair_sym_environment_register_model test_environment_register_model
#define xair_sym_environment_register_model_kind test_environment_register_model_kind
#define xair_sym_environment_model test_environment_model
#define xair_sym_environment_model_info test_environment_model_info
#define xair_sym_environment_model_identity test_environment_model_identity
#define xair_sym_environment_model_version test_environment_model_version
#define xair_sym_environment_allocate test_environment_allocate
#define xair_sym_environment_input test_environment_input
#define xair_sym_environment_copy test_environment_copy
#include "../src/xair_sym_environment.c"
#undef xair_sym_model_call_get
#undef xair_sym_environment_create_builtin
#undef xair_sym_model_call_argument_get
#undef xair_sym_model_call_result_set
#undef xair_sym_model_call_mark_incomplete
#undef xair_sym_model_call_terminate
#undef xair_sym_model_call_confidence_set
#undef xair_sym_environment_clone_builtin
#undef xair_sym_environment_create_builtin_snapshot
#undef xair_sym_environment_attach_builtin
#undef xair_sym_process_options_init
#undef xair_sym_process_create
#undef xair_sym_environment_retain
#undef xair_sym_environment_release
#undef xair_sym_environment_destroy
#undef xair_sym_state_attach_environment
#undef xair_sym_environment_register_model
#undef xair_sym_environment_register_model_kind
#undef xair_sym_environment_model
#undef xair_sym_environment_model_info
#undef xair_sym_environment_model_identity
#undef xair_sym_environment_model_version
#undef xair_sym_environment_allocate
#undef xair_sym_environment_input
#undef xair_sym_environment_copy

static void test_text_and_builtin_lookup(void) {
    char *copy;
    uint64_t empty_hash = model_hash_text(17, NULL);
    assert(lookup_model(NULL) == XAIR_SYM_MODEL_UNKNOWN);
    assert(lookup_model("malloc") == XAIR_SYM_MODEL_ALLOC);
    assert(lookup_model("IoCompleteRequest") == XAIR_SYM_MODEL_DRIVER_COMPLETE);
    assert(lookup_model("not-a-model") == XAIR_SYM_MODEL_UNKNOWN);
    assert(copy_text(NULL) == NULL);
    copy = copy_text("copied"); assert(copy != NULL && strcmp(copy, "copied") == 0); free(copy);
    assert(empty_hash != model_hash_text(17, "text"));
    assert(identity_text_matches(NULL, NULL));
    assert(identity_text_matches(NULL, "anything"));
    assert(!identity_text_matches("registered", NULL));
    assert(identity_text_matches("same", "same"));
    assert(!identity_text_matches("left", "right"));
}

static void test_registered_model_matching(void) {
    xair_sym_environment environment;
    xair_sym_registered_model models[2];
    xair_op_attributes attributes;
    memset(&environment, 0, sizeof(environment));
    memset(models, 0, sizeof(models));
    memset(&attributes, 0, sizeof(attributes));
    environment.models = models; environment.model_count = 2;
    models[0].module = "kernel32"; models[0].name = "ReadFile";
    models[0].user_identity = "custom.read"; models[0].ordinal = 7; models[0].address = 0x1234;
    models[1].name = "fallback";
    attributes.import_module = "kernel32"; attributes.import_name = "ReadFile";
    attributes.semantic_id = "custom.read"; attributes.import_ordinal = 7; attributes.direct_target = 0x1234;
    assert(find_registered_model(&environment, &attributes) == &models[0]);
    attributes.import_module = "other"; assert(find_registered_model(&environment, &attributes) == NULL); attributes.import_module = "kernel32";
    attributes.import_name = "other"; assert(find_registered_model(&environment, &attributes) == NULL); attributes.import_name = "ReadFile";
    attributes.semantic_id = "other"; assert(find_registered_model(&environment, &attributes) == NULL); attributes.semantic_id = "custom.read";
    attributes.import_ordinal = 8; assert(find_registered_model(&environment, &attributes) == NULL); attributes.import_ordinal = 7;
    attributes.direct_target = 0x1235; assert(find_registered_model(&environment, &attributes) == NULL); attributes.direct_target = 0x1234;
    attributes.import_module = NULL; attributes.import_name = "fallback"; attributes.semantic_id = NULL;
    attributes.import_ordinal = 99; attributes.direct_target = 99;
    assert(find_registered_model(&environment, &attributes) == &models[1]);
    environment.model_count = 0; assert(find_registered_model(&environment, &attributes) == NULL);
}

static void test_loop_limits(void) {
    xair_sym_context *context = NULL;
    xair_cancel_token *token = NULL;
    xair_analysis_options analysis;
    assert(xair_sym_context_create(&context) == XAIR_SYM_OK);
    assert(loop_guard(context, 0) == XAIR_SYM_OK);
    assert(xair_cancel_token_create(&token) == XAIR_OK);
    xair_analysis_options_init(&analysis); analysis.cancel_token = token;
    xair_sym_context_set_analysis_options(context, &analysis);
    xair_cancel_token_request(token); assert(loop_guard(context, 0) == XAIR_SYM_ERR_CANCELED);
    xair_cancel_token_reset(token); analysis.max_wall_time = 1;
    xair_sym_context_set_analysis_options(context, &analysis); context->analysis_started_ms = 0;
    assert(loop_guard(context, 0) == XAIR_SYM_ERR_RESOURCE_LIMIT);
    analysis.max_wall_time = 0; analysis.max_bytes = 4;
    xair_sym_context_set_analysis_options(context, &analysis);
    assert(loop_guard(context, 3) == XAIR_SYM_OK);
    assert(loop_guard(context, 4) == XAIR_SYM_ERR_RESOURCE_LIMIT);
    xair_cancel_token_destroy(token); xair_sym_context_destroy(context);
}

static void test_builtin_environment_edges(void) {
    xair_sym_context *context = NULL;
    xair_sym_environment source;
    xair_sym_environment *environment = NULL;
    xair_sym_environment *copy = NULL;
    xair_sym_model_kind kind = XAIR_SYM_MODEL_UNKNOWN;
    xair_sym_model_info info;
    xair_sym_model_identity identity;
    xair_sym_process_options options;
    xair_module *module = NULL;
    xair_block_id entry;
    xair_sym_state *state = NULL;

    assert(xair_sym_context_create(&context) == XAIR_SYM_OK);
    memset(&source, 0, sizeof(source));
    source.refs = 1;
    source.context = context;
    source.arch = XAIR_ARCH_X86_64;
    source.abi = XAIR_CC_WIN64;
    source.model_version = UINT64_C(0x00010001);
    source.stack_base = 0x70000000u;
    source.stack_size = 4096u;
    source.heap_next = 0x90000000u;

    assert(test_environment_clone_builtin(NULL, context, &copy) == XAIR_SYM_ERR_UNSUPPORTED);
    assert(test_environment_clone_builtin(&source, NULL, &copy) == XAIR_SYM_ERR_UNSUPPORTED);
    assert(test_environment_clone_builtin(&source, context, NULL) == XAIR_SYM_ERR_UNSUPPORTED);
    source.model_count = 1;
    assert(test_environment_clone_builtin(&source, context, &copy) == XAIR_SYM_ERR_UNSUPPORTED);
    source.model_count = 0;
    assert(test_environment_clone_builtin(&source, context, &copy) == XAIR_SYM_OK);
    assert(copy != NULL && copy->arch == source.arch && copy->abi == source.abi &&
        copy->stack_base == source.stack_base && copy->heap_next == source.heap_next);
    test_environment_release(copy);
    copy = NULL;

    assert(test_environment_create_builtin_snapshot(NULL, XAIR_ARCH_X86_64, XAIR_CC_WIN64,
        UINT64_C(0x00010001), 0x70000000u, 4096u, 0x90000000u, &environment) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64, XAIR_CC_WIN64,
        UINT64_C(0x00010001), 0x70000000u, 4096u, 0x90000000u, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_create_builtin_snapshot(context, (xair_arch)99, XAIR_CC_WIN64,
        UINT64_C(0x00010001), 0x70000000u, 4096u, 0x90000000u, &environment) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64, (xair_calling_convention)99,
        UINT64_C(0x00010001), 0x70000000u, 4096u, 0x90000000u, &environment) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64, XAIR_CC_WIN64,
        7u, 0x70000000u, 4096u, 0x90000000u, &environment) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64, XAIR_CC_WIN64,
        UINT64_C(0x00010001), 0x70000000u, 0u, 0x90000000u, &environment) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64, XAIR_CC_WIN64,
        UINT64_C(0x00010001), UINT64_MAX - 3u, 8u, 0x90000000u, &environment) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_create_builtin_snapshot(context, XAIR_ARCH_X86_64, XAIR_CC_WIN64,
        UINT64_C(0x00010001), 0x70000000u, 4096u, 0x90000000u, &environment) == XAIR_SYM_OK);
    assert(environment != NULL && environment->stack_size == 4096u);

    memset(&info, 0, sizeof(info));
    memset(&identity, 0, sizeof(identity));
    assert(xair_sym_environment_model(NULL, "malloc", &kind) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_environment_model(environment, NULL, &kind) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_environment_model(environment, "malloc", NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_environment_model(environment, "malloc", &kind) == XAIR_SYM_OK);
    assert(kind == XAIR_SYM_MODEL_ALLOC);
    assert(xair_sym_environment_model(environment, "not-a-model", &kind) == XAIR_SYM_OK);
    assert(kind == XAIR_SYM_MODEL_UNKNOWN);
    assert(test_environment_model_info(NULL, "calloc", &info) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_model_info(environment, NULL, &info) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_model_info(environment, "calloc", NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_environment_model_info(environment, "calloc", &info) == XAIR_SYM_OK);
    assert(info.kind == XAIR_SYM_MODEL_ALLOC && info.version_major == 1u);
    assert(xair_sym_environment_model_identity(NULL, &identity, &info) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_environment_model_identity(environment, NULL, &info) == XAIR_SYM_ERR_BAD_ARG);
    assert(xair_sym_environment_model_identity(environment, &identity, NULL) == XAIR_SYM_ERR_BAD_ARG);
    identity.name = "memcpy";
    assert(xair_sym_environment_model_identity(environment, &identity, &info) == XAIR_SYM_OK);
    assert(info.kind == XAIR_SYM_MODEL_COPY && info.version_major == 1u);
    identity.name = NULL; identity.user_identity = "IoCompleteRequest";
    assert(xair_sym_environment_model_identity(environment, &identity, &info) == XAIR_SYM_OK);
    assert(info.kind == XAIR_SYM_MODEL_DRIVER_COMPLETE);
    identity.user_identity = "not-a-model";
    assert(xair_sym_environment_model_identity(environment, &identity, &info) == XAIR_SYM_OK);
    assert(info.kind == XAIR_SYM_MODEL_UNKNOWN && info.version_major == 0u);

    test_process_options_init(NULL, XAIR_ARCH_X86_64);
    test_process_options_init(&options, XAIR_ARCH_X86_32);
    assert(options.stack_base == UINT64_C(0x70000000) && options.abi == XAIR_CC_CDECL_X86);
    test_process_options_init(&options, XAIR_ARCH_X86_64);
    assert(options.stack_base == UINT64_C(0x00007fff00000000) && options.abi == XAIR_CC_UNKNOWN);

    assert(xair_module_create(&module) == XAIR_OK);
    assert(xair_block_create(module, "entry", &entry) == XAIR_OK);
    assert(xair_set_return(module, entry, NULL, 0) == XAIR_OK);
    assert(xair_sym_state_create(context, module, entry, &state) == XAIR_SYM_OK);
    test_environment_attach_builtin(NULL, environment);
    test_environment_attach_builtin(state, environment);
    assert(state->environment == environment && state->call_model == environment_call_model &&
        state->call_model_user == environment);
    environment = NULL;
    test_environment_attach_builtin(state, NULL);
    assert(state->environment == NULL && state->call_model == NULL && state->call_model_user == NULL);
    xair_sym_state_destroy(state);
    xair_module_destroy(module);
    xair_sym_context_destroy(context);
}

static void test_initialize_entry_parameter_roles(void) {
    typedef struct {
        const char *name;
        xair_type type;
        const char *expected_symbol_prefix;
        uint64_t expected_const;
        int expect_const;
    } param_spec;
    const param_spec specs[] = {
        {"rsp", xair_type_addr(64), NULL, 0x12345000u, 1},
        {"fs_base", xair_type_addr(64), NULL, 0xaaaabbbbccccddddull, 1},
        {"gs_base", xair_type_addr(64), NULL, 0x1111222233334444ull, 1},
        {"rcx", xair_type_i(64), "win64_argument_rcx_", 0, 0},
        {"rdx", xair_type_i(64), "win64_argument_rdx_", 0, 0},
        {"r8", xair_type_i(64), "win64_argument_r8_", 0, 0},
        {"r9", xair_type_i(64), "win64_argument_r9_", 0, 0},
        {"rbx", xair_type_i(64), "win64_callee_saved_rbx_", 0, 0},
        {"rbp", xair_type_i(64), "win64_callee_saved_rbp_", 0, 0},
        {"rdi", xair_type_i(64), "win64_callee_saved_rdi_", 0, 0},
        {"rsi", xair_type_i(64), "win64_callee_saved_rsi_", 0, 0},
        {"r12", xair_type_i(64), "win64_callee_saved_r12_", 0, 0},
        {"r13", xair_type_i(64), "win64_callee_saved_r13_", 0, 0},
        {"r14", xair_type_i(64), "win64_callee_saved_r14_", 0, 0},
        {"r15", xair_type_i(64), "win64_callee_saved_r15_", 0, 0},
        {"rax", xair_type_i(64), "win64_return_caller_saved_rax_", 0, 0},
        {"r10", xair_type_i(64), "win64_caller_saved_r10_", 0, 0},
        {"r11", xair_type_i(64), "win64_caller_saved_r11_", 0, 0},
        {"rflags", xair_type_flags(6), "win64_unknown_flags_rflags_", 0, 0},
        {"scratch", xair_type_i(32), "initial_scratch_", 0, 0},
        {NULL, xair_type_i(16), "initial_v", 0, 0},
        {"memory", xair_type_mem(0, 64), NULL, 0, 0}
    };
    xair_sym_context *context = NULL;
    xair_module *module = NULL;
    xair_block_id entry;
    xair_value_id params[sizeof(specs) / sizeof(specs[0])];
    xair_sym_state *state = NULL;
    size_t i;

    assert(xair_sym_context_create(&context) == XAIR_SYM_OK);
    assert(xair_module_create(&module) == XAIR_OK);
    assert(xair_block_create(module, "entry", &entry) == XAIR_OK);
    for (i = 0; i < sizeof(specs) / sizeof(specs[0]); ++i)
        assert(xair_block_add_param(module, entry, specs[i].type, specs[i].name, &params[i]) == XAIR_OK);
    assert(xair_set_return(module, entry, NULL, 0) == XAIR_OK);
    assert(xair_sym_state_create(context, module, entry, &state) == XAIR_SYM_OK);
    state->abi = XAIR_CC_WIN64;
    state->fs_base = specs[1].expected_const;
    state->gs_base = specs[2].expected_const;
    assert(initialize_entry_parameters(context, state, entry, specs[0].expected_const) == XAIR_SYM_OK);

    for (i = 0; i < sizeof(specs) / sizeof(specs[0]); ++i) {
        xair_type type = specs[i].type;
        assert(state->defined[params[i]] != 0);
        if (type.kind == XAIR_TYPE_MEM) {
            assert(state->values[params[i]] == XAIR_SYM_INVALID_ID);
        } else {
            xair_sym_expr_view view;
            assert(xair_sym_expr_get(context, state->values[params[i]], &view) == XAIR_SYM_OK);
            if (specs[i].expect_const) {
                assert(view.kind == XAIR_SYM_EXPR_CONST);
                assert(view.immediate == specs[i].expected_const);
            } else {
                size_t prefix_len;
                assert(view.kind == XAIR_SYM_EXPR_SYMBOL);
                assert(view.symbol != NULL);
                prefix_len = strlen(specs[i].expected_symbol_prefix);
                if (strncmp(view.symbol, specs[i].expected_symbol_prefix, prefix_len) != 0) {
                    fprintf(stderr, "unexpected symbol for %s: %s, expected prefix %s\n",
                        specs[i].name == NULL ? "(null)" : specs[i].name,
                        view.symbol, specs[i].expected_symbol_prefix);
                    assert(0);
                }
                assert(type.kind != XAIR_TYPE_FLAGS || view.bits == 6u);
            }
        }
    }

    xair_sym_state_destroy(state);
    xair_module_destroy(module);
    xair_sym_context_destroy(context);
}

int main(void) {
    test_text_and_builtin_lookup();
    test_registered_model_matching();
    test_loop_limits();
    test_builtin_environment_edges();
    test_initialize_entry_parameter_roles();
    return 0;
}
