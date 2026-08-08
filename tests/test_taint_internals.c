#include "xair_sym/xair_sym.h"
#include "../src/xair_sym_internal.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

xair_sym_status test_taint_source_ex(xair_sym_context *, const char *,
    const xair_sym_taint_details *, xair_sym_taint_id *);
xair_sym_status test_taint_sanitize_ex(xair_sym_context *, xair_sym_taint_id,
    const char *, int, xair_sym_taint_id *);

#define xair_sym_context_set_taint_mode test_context_set_taint_mode
#define xair_sym_taint_source test_taint_source
#define xair_sym_taint_source_ex test_taint_source_ex
#define xair_sym_taint_union test_taint_union
#define xair_sym_taint_sanitize test_taint_sanitize
#define xair_sym_taint_sanitize_ex test_taint_sanitize_ex
#define xair_sym_taint_transform test_taint_transform
#define xair_sym_taint_get test_taint_get
#define xair_sym_taint_get_details test_taint_get_details
#define xair_sym_taint_sink test_taint_sink
#define xair_sym_taint_sink_count test_taint_sink_count
#define xair_sym_taint_sink_get test_taint_sink_get
#define xair_sym_state_set_taint test_state_set_taint
#define xair_sym_state_get_taint test_state_get_taint
#define xair_sym_taint_operands test_taint_operands
#include "../src/xair_sym_taint.c"
#undef xair_sym_context_set_taint_mode
#undef xair_sym_taint_source
#undef xair_sym_taint_source_ex
#undef xair_sym_taint_union
#undef xair_sym_taint_sanitize
#undef xair_sym_taint_sanitize_ex
#undef xair_sym_taint_transform
#undef xair_sym_taint_get
#undef xair_sym_taint_get_details
#undef xair_sym_taint_sink
#undef xair_sym_taint_sink_count
#undef xair_sym_taint_sink_get
#undef xair_sym_state_set_taint
#undef xair_sym_state_get_taint
#undef xair_sym_taint_operands

static void test_detail_equality(void) {
    xair_sym_taint_details a, b;
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
    assert(nullable_equal(NULL, NULL)); assert(nullable_equal(NULL, ""));
    assert(!nullable_equal(NULL, "x")); assert(nullable_equal("x", "x"));
    assert(details_equal(&a, &b));
#define DIFFER(field) do { b.field++; assert(!details_equal(&a, &b)); b.field = a.field; } while (0)
    DIFFER(category); DIFFER(source_address); DIFFER(call_site); DIFFER(sink_address);
    DIFFER(byte_offset); DIFFER(guard); DIFFER(byte_length); DIFFER(confidence);
    DIFFER(implicit); DIFFER(sanitizer_validated);
#undef DIFFER
    b.transform = "different"; assert(!details_equal(&a, &b)); b.transform = NULL;
    b.sink = "different"; assert(!details_equal(&a, &b));
    assert(taint_hash(1, 2) == taint_hash(1, 2));
}

static void test_invalid_and_identity_paths(void) {
    xair_sym_context *context = NULL;
    xair_sym_taint_details details;
    xair_sym_taint_id a, b, out;
    xair_sym_taint_view view;
    xair_sym_expr_id byte, guard;
    xair_sym_state fake_state;
    xair_sym_taint_id fake_taints[1] = {XAIR_SYM_TAINT_NONE};
    xair_op_view op;
    memset(&details, 0, sizeof(details));
    assert(xair_sym_context_create(&context) == XAIR_SYM_OK);
    assert(test_taint_source_ex(NULL, "x", &details, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_source_ex(context, NULL, &details, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_source_ex(context, "", &details, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_source_ex(context, "x", NULL, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_source_ex(context, "x", &details, NULL) == XAIR_SYM_ERR_BAD_ARG);
    details.transform = "bad"; assert(test_taint_source_ex(context, "x", &details, &out) == XAIR_SYM_ERR_BAD_ARG); details.transform = NULL;
    details.sink = "bad"; assert(test_taint_source_ex(context, "x", &details, &out) == XAIR_SYM_ERR_BAD_ARG); details.sink = NULL;
    details.guard = 99; assert(test_taint_source_ex(context, "x", &details, &out) == XAIR_SYM_ERR_BAD_ARG); details.guard = 0;
    assert(test_taint_source_ex(context, "a", &details, &a) == XAIR_SYM_OK);
    assert(test_taint_source_ex(context, "a", &details, &out) == XAIR_SYM_OK && out == a);
    assert(test_taint_source_ex(context, "b", &details, &b) == XAIR_SYM_OK);

#define INVALID_SANITIZE(ctx,input,name,result) assert(test_taint_sanitize(ctx,input,name,result) == XAIR_SYM_ERR_BAD_ARG)
    INVALID_SANITIZE(NULL, a, "sanitize", &out); INVALID_SANITIZE(context, 0, "sanitize", &out);
    INVALID_SANITIZE(context, 9999, "sanitize", &out); INVALID_SANITIZE(context, a, NULL, &out);
    INVALID_SANITIZE(context, a, "", &out); INVALID_SANITIZE(context, a, "sanitize", NULL);
#undef INVALID_SANITIZE
#define INVALID_SINK(ctx,input,name,result) assert(test_taint_sink(ctx,input,name,0,result) == XAIR_SYM_ERR_BAD_ARG)
    INVALID_SINK(NULL, a, "sink", &out); INVALID_SINK(context, 0, "sink", &out);
    INVALID_SINK(context, 9999, "sink", &out); INVALID_SINK(context, a, NULL, &out);
    INVALID_SINK(context, a, "", &out); INVALID_SINK(context, a, "sink", NULL);
#undef INVALID_SINK
    assert(test_taint_union(NULL, a, b, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_union(context, a, b, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_union(context, 9999, b, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_union(context, a, 9999, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_union(context, XAIR_SYM_TAINT_NONE, b, &out) == XAIR_SYM_OK && out == b);
    assert(test_taint_union(context, a, XAIR_SYM_TAINT_NONE, &out) == XAIR_SYM_OK && out == a);
    assert(test_taint_union(context, a, a, &out) == XAIR_SYM_OK && out == a);
    assert(test_taint_union(context, b, a, &out) == XAIR_SYM_OK);

    assert(xair_sym_const(context, 8, 1, &byte) == XAIR_SYM_OK);
    assert(xair_sym_const(context, 1, 1, &guard) == XAIR_SYM_OK);
#define BAD_TRANSFORM(ctx,input,name,g,result) assert(test_taint_transform(ctx,input,name,g,0,result) == XAIR_SYM_ERR_BAD_ARG)
    BAD_TRANSFORM(NULL, a, "t", guard, &out); BAD_TRANSFORM(context, 0, "t", guard, &out);
    BAD_TRANSFORM(context, 9999, "t", guard, &out); BAD_TRANSFORM(context, a, NULL, guard, &out);
    BAD_TRANSFORM(context, a, "", guard, &out); BAD_TRANSFORM(context, a, "t", guard, NULL);
    BAD_TRANSFORM(context, a, "t", 9999, &out); BAD_TRANSFORM(context, a, "t", byte, &out);
#undef BAD_TRANSFORM
    assert(test_taint_transform(context, a, "t", XAIR_SYM_INVALID_ID, 1, &out) == XAIR_SYM_OK);
    assert(test_taint_get(NULL, a, &view) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_get(context, 0, &view) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_get(context, 9999, &view) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_get(context, a, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_get(context, a, &view) == XAIR_SYM_OK && view.name != NULL);
    assert(test_taint_get_details(NULL, a, &details) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_get_details(context, 0, &details) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_get_details(context, 9999, &details) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_get_details(context, a, NULL) == XAIR_SYM_ERR_BAD_ARG);
    test_context_set_taint_mode(NULL, XAIR_SYM_TAINT_EXPLICIT);
    test_context_set_taint_mode(context, (xair_sym_taint_mode)99);
    test_context_set_taint_mode(context, XAIR_SYM_TAINT_STRICT_IMPLICIT);
    assert(test_taint_sink_count(NULL) == 0);
    assert(test_taint_sink_get(NULL, 0, &out) == XAIR_SYM_ERR_BAD_ARG && out == XAIR_SYM_TAINT_NONE);
    assert(test_taint_sink_get(context, 0, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_sink_get(context, 0, &out) == XAIR_SYM_ERR_RANGE);
    memset(&fake_state, 0, sizeof(fake_state)); fake_state.context = context;
    fake_state.value_count = 1; fake_state.value_taints = fake_taints;
    assert(test_state_set_taint(NULL, 0, a) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_state_set_taint(&fake_state, 1, a) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_state_set_taint(&fake_state, 0, 9999) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_state_set_taint(&fake_state, 0, a) == XAIR_SYM_OK);
    assert(test_state_get_taint(NULL, 0, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_state_get_taint(&fake_state, 0, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_state_get_taint(&fake_state, 1, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_state_get_taint(&fake_state, 0, &out) == XAIR_SYM_OK && out == a);
    memset(&op, 0, sizeof(op));
    assert(test_taint_operands(NULL, &op, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_operands(&fake_state, NULL, &out) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_operands(&fake_state, &op, NULL) == XAIR_SYM_ERR_BAD_ARG);
    assert(test_taint_operands(&fake_state, &op, &out) == XAIR_SYM_OK);
    xair_sym_context_destroy(context);
}

int main(void) {
    test_detail_equality();
    test_invalid_and_identity_paths();
    return 0;
}
