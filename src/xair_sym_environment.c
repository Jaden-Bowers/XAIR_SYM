#include "xair_sym_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const char *name; xair_sym_model_kind kind; } builtin_model;

static const builtin_model builtin_models[] = {
    {"malloc", XAIR_SYM_MODEL_ALLOC}, {"calloc", XAIR_SYM_MODEL_ALLOC}, {"realloc", XAIR_SYM_MODEL_ALLOC},
    {"free", XAIR_SYM_MODEL_FREE}, {"memcpy", XAIR_SYM_MODEL_COPY}, {"memmove", XAIR_SYM_MODEL_COPY},
    {"memset", XAIR_SYM_MODEL_FILL}, {"read", XAIR_SYM_MODEL_INPUT}, {"recv", XAIR_SYM_MODEL_INPUT},
    {"recvfrom", XAIR_SYM_MODEL_INPUT}, {"strlen", XAIR_SYM_MODEL_LENGTH}, {"exit", XAIR_SYM_MODEL_NO_RETURN},
    {"abort", XAIR_SYM_MODEL_NO_RETURN}, {"HeapAlloc", XAIR_SYM_MODEL_ALLOC}, {"HeapFree", XAIR_SYM_MODEL_FREE},
    {"RtlAllocateHeap", XAIR_SYM_MODEL_ALLOC}, {"RtlFreeHeap", XAIR_SYM_MODEL_FREE},
    {"RtlCopyMemory", XAIR_SYM_MODEL_COPY}, {"ReadFile", XAIR_SYM_MODEL_INPUT},
    {"ExitProcess", XAIR_SYM_MODEL_NO_RETURN}, {"ExAllocatePool", XAIR_SYM_MODEL_ALLOC},
    {"ExAllocatePoolWithTag", XAIR_SYM_MODEL_ALLOC}, {"ExFreePool", XAIR_SYM_MODEL_FREE},
    {"ProbeForRead", XAIR_SYM_MODEL_DRIVER_INPUT}, {"ProbeForWrite", XAIR_SYM_MODEL_DRIVER_INPUT},
    {"IoCompleteRequest", XAIR_SYM_MODEL_DRIVER_COMPLETE},
    {"memcmp", XAIR_SYM_MODEL_COMPARE}
};

static xair_sym_model_kind lookup_model(const char *name) {
    size_t i;
    if (name == NULL) return XAIR_SYM_MODEL_UNKNOWN;
    for (i = 0; i < sizeof(builtin_models) / sizeof(builtin_models[0]); ++i)
        if (strcmp(name, builtin_models[i].name) == 0) return builtin_models[i].kind;
    return XAIR_SYM_MODEL_UNKNOWN;
}

static char *copy_text(const char *text) {
    size_t size;
    char *copy;
    if (text == NULL) return NULL;
    size = strlen(text) + 1u;
    copy = (char *)malloc(size);
    if (copy != NULL) memcpy(copy, text, size);
    return copy;
}

static uint64_t model_hash_text(uint64_t hash, const char *text) {
    const unsigned char *cursor = (const unsigned char *)(text != NULL ? text : "");
    while (*cursor != 0) hash = (hash ^ *cursor++) * UINT64_C(1099511628211);
    return (hash ^ UINT64_C(0xff)) * UINT64_C(1099511628211);
}

static int identity_text_matches(const char *registered, const char *actual) {
    return registered == NULL || (actual != NULL && strcmp(registered, actual) == 0);
}

static xair_sym_registered_model *find_registered_model(xair_sym_environment *environment,
    const xair_op_attributes *attributes) {
    size_t i;
    for (i = 0; i < environment->model_count; ++i) {
        xair_sym_registered_model *model = &environment->models[i];
        if (!identity_text_matches(model->module, attributes->import_module) ||
            !identity_text_matches(model->name, attributes->import_name) ||
            !identity_text_matches(model->user_identity, attributes->semantic_id)) continue;
        if (model->ordinal != 0 && model->ordinal != attributes->import_ordinal) continue;
        if (model->address != 0 && model->address != attributes->direct_target) continue;
        return model;
    }
    return NULL;
}

xair_sym_status xair_sym_model_call_get(xair_sym_state *state, xair_op_id call_op,
    xair_sym_model_call_view *out_call) {
    xair_op_attributes attributes;
    const xair_value_id *values;
    const xair_source_id *sources;
    size_t source_count;
    size_t argument_count, result_count;
    if (out_call != NULL) memset(out_call, 0, sizeof(*out_call));
    if (state == NULL || out_call == NULL ||
        xair_op_attributes_get(state->module, call_op, &attributes) != XAIR_OK ||
        attributes.kind != XAIR_ATTR_CALL ||
        xair_op_inputs(state->module, call_op, &values, &argument_count) != XAIR_OK ||
        xair_op_results(state->module, call_op, &values, &result_count) != XAIR_OK)
        return XAIR_SYM_ERR_BAD_ARG;
    out_call->struct_size = (uint32_t)sizeof(*out_call);
    out_call->context = state->context;
    out_call->abi = attributes.calling_convention != XAIR_CC_UNKNOWN ?
        attributes.calling_convention : state->abi;
    out_call->call_op = call_op;
    out_call->call_site = 0;
    if (xair_op_sources(state->module, call_op, &sources, &source_count) == XAIR_OK && source_count != 0) {
        xair_source_record source;
        if (xair_module_get_source(state->module, sources[0], &source) == XAIR_OK)
            out_call->call_site = source.location.instruction_va;
    }
    out_call->direct_target = attributes.direct_target;
    out_call->effects = attributes.effects;
    out_call->confidence = attributes.confidence;
    out_call->output_confidence = (xair_confidence)state->model_output_confidence;
    out_call->import_module = attributes.import_module;
    out_call->import_name = attributes.import_name != NULL ? attributes.import_name : attributes.semantic_id;
    out_call->import_ordinal = attributes.import_ordinal;
    out_call->argument_count = argument_count;
    out_call->result_count = result_count;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_model_call_argument_get(xair_sym_state *state, xair_op_id call_op,
    size_t index, xair_sym_expr_id *out_expression, xair_sym_taint_id *out_taint) {
    const xair_value_id *inputs;
    size_t count;
    xair_value_id value;
    if (out_expression != NULL) *out_expression = XAIR_SYM_INVALID_ID;
    if (out_taint != NULL) *out_taint = XAIR_SYM_TAINT_NONE;
    if (state == NULL || out_expression == NULL || out_taint == NULL ||
        xair_op_inputs(state->module, call_op, &inputs, &count) != XAIR_OK || index >= count)
        return XAIR_SYM_ERR_BAD_ARG;
    value = inputs[index];
    if (!state->defined[value]) return XAIR_SYM_ERR_BAD_ARG;
    *out_expression = state->values[value];
    *out_taint = state->value_taints[value];
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_model_call_result_set(xair_sym_state *state, xair_op_id call_op,
    size_t index, xair_sym_expr_id expression, xair_sym_taint_id taint) {
    const xair_value_id *results;
    size_t count;
    xair_value_id value;
    xair_type type;
    xair_sym_status status;
    if (state == NULL || taint > state->context->taint_count ||
        xair_op_results(state->module, call_op, &results, &count) != XAIR_OK || index >= count)
        return XAIR_SYM_ERR_BAD_ARG;
    value = results[index]; type = xair_value_type(state->module, value);
    if (type.kind == XAIR_TYPE_MEM) {
        if (expression != XAIR_SYM_INVALID_ID) return XAIR_SYM_ERR_BAD_ARG;
        state->defined[value] = 1; state->values[value] = XAIR_SYM_INVALID_ID; status = XAIR_SYM_OK;
    } else status = xair_sym_state_set_value(state, value, expression);
    if (status != XAIR_SYM_OK) return status;
    return xair_sym_state_set_taint(state, value, taint);
}

void xair_sym_model_call_mark_incomplete(xair_sym_state *state, int memory_havoc) {
    if (state == NULL) return;
    state->completeness = XAIR_SYM_INCOMPLETE;
    state->unresolved_operations++;
    if (memory_havoc) xair_sym_memory_havoc(state);
}

void xair_sym_model_call_terminate(xair_sym_state *state) {
    if (state != NULL) state->terminate_requested = 1;
}

xair_sym_status xair_sym_model_call_confidence_set(xair_sym_state *state,
    xair_op_id call_op, xair_confidence confidence) {
    xair_op_attributes attributes;
    if (state == NULL || confidence > XAIR_CONFIDENCE_EXACT ||
        xair_op_attributes_get(state->module, call_op, &attributes) != XAIR_OK ||
        attributes.kind != XAIR_ATTR_CALL) return XAIR_SYM_ERR_BAD_ARG;
    state->model_output_confidence = (uint8_t)confidence;
    return XAIR_SYM_OK;
}

static xair_sym_status call_scalar_values(xair_sym_state *state, xair_op_id op,
    uint64_t *values, size_t capacity, size_t *out_count) {
    const xair_value_id *inputs;
    size_t input_count, i, count = 0;
    if (xair_op_inputs(state->module, op, &inputs, &input_count) != XAIR_OK) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < input_count; ++i) {
        xair_type type = xair_value_type(state->module, inputs[i]);
        xair_sym_expr_id expression;
        if (type.kind == XAIR_TYPE_MEM || type.kind == XAIR_TYPE_FLAGS) continue;
        if (count == capacity || xair_sym_state_get_value(state, inputs[i], &expression) != XAIR_SYM_OK)
            return XAIR_SYM_ERR_BAD_ARG;
        if (state->context->expressions[expression]->kind != XAIR_SYM_EXPR_CONST ||
            state->context->expressions[expression]->bits > 64) return XAIR_SYM_ERR_UNSUPPORTED;
        values[count] = state->context->expressions[expression]->immediate;
        count++;
    }
    *out_count = count;
    return XAIR_SYM_OK;
}

static xair_sym_status loop_guard(xair_sym_context *context, size_t completed) {
    if (xair_cancel_token_requested(context->analysis.cancel_token)) return XAIR_SYM_ERR_CANCELED;
    if (context->analysis.max_wall_time != 0 &&
        xair_monotonic_milliseconds() - context->analysis_started_ms >= context->analysis.max_wall_time)
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (context->analysis.max_bytes != 0 && completed >= context->analysis.max_bytes)
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    return XAIR_SYM_OK;
}

static void rollback_memory_transaction(xair_sym_state *state,
    xair_sym_memory *saved_memory, uint64_t saved_heap_next,
    size_t saved_object_bytes, size_t saved_parallel_reserved,
    const xair_sym_stats *saved_stats) {
    size_t release = state->context->parallel_memory_reserved > saved_parallel_reserved ?
        state->context->parallel_memory_reserved - saved_parallel_reserved : 0u;
    xair_sym_memory_release(state->memory);
    state->memory = saved_memory;
    state->heap_next = saved_heap_next;
    state->context->object_bytes = saved_object_bytes;
    xair_sym_parallel_memory_release(state->context, release);
    state->context->stats = *saved_stats;
}

static xair_sym_status set_call_results(xair_sym_state *state, xair_op_id op,
    int has_value, uint64_t value) {
    const xair_value_id *results;
    size_t result_count, i;
    if (xair_op_results(state->module, op, &results, &result_count) != XAIR_OK) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < result_count; ++i) {
        xair_type type = xair_value_type(state->module, results[i]);
        xair_sym_expr_id expression;
        xair_sym_status status;
        if (type.kind == XAIR_TYPE_MEM) {
            state->defined[results[i]] = 1;
            state->values[results[i]] = XAIR_SYM_INVALID_ID;
            continue;
        }
        if (has_value && (type.kind == XAIR_TYPE_INT || type.kind == XAIR_TYPE_ADDR)) {
            uint64_t canonical = type.bits >= 64u ? value :
                value & ((UINT64_C(1) << type.bits) - 1u);
            status = xair_sym_const(state->context, type.bits, canonical, &expression);
            has_value = 0;
        } else {
            char symbol[80];
            (void)snprintf(symbol, sizeof(symbol), "call_%u_%llu_result_%zu", (unsigned)op,
                (unsigned long long)state->context->stats.model_calls, i);
            status = xair_sym_symbol(state->context, type.bits == 0 ? 1 : type.bits, symbol, &expression);
        }
        if (status != XAIR_SYM_OK) return status;
        status = xair_sym_state_set_value(state, results[i], expression);
        if (status != XAIR_SYM_OK) return status;
    }
    return XAIR_SYM_OK;
}

static xair_sym_status unknown_call_fallback(xair_sym_state *state, xair_op_id op,
    const xair_op_attributes *attributes) {
    const xair_value_id *results;
    size_t result_count, i;
    xair_op_view view;
    xair_sym_taint_id taint = XAIR_SYM_TAINT_NONE;
    xair_sym_status status;
    int havoc = (attributes->effects & XAIR_EFFECT_WRITE_MEMORY) != 0;
    status = set_call_results(state, op, 0, 0);
    if (status != XAIR_SYM_OK) return status;
    if (xair_module_get_op(state->module, op, &view) == XAIR_OK)
        status = xair_sym_taint_operands(state, &view, &taint);
    if (status != XAIR_SYM_OK) return status;
    if (xair_op_results(state->module, op, &results, &result_count) != XAIR_OK) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < result_count; ++i) {
        if (xair_value_type(state->module, results[i]).kind == XAIR_TYPE_MEM) havoc = 1;
        else if (taint != XAIR_SYM_TAINT_NONE) {
            status = xair_sym_state_set_taint(state, results[i], taint);
            if (status != XAIR_SYM_OK) return status;
        }
    }
    if (havoc) xair_sym_memory_havoc(state);
    state->unresolved_operations++;
    state->completeness = XAIR_SYM_INCOMPLETE;
    return XAIR_SYM_OK;
}

/* ISO memcmp constrains the sign, not the nonzero magnitude. Keep the latter
 * symbolic so implementation-specific return-value tests are not falsely proved.
 * Only concrete bounded pointers/lengths and fully available memory are modeled. */
static xair_sym_status compare_call(xair_sym_state *state,xair_op_id op,const uint64_t *args,size_t count) {
    const xair_value_id *outputs;size_t output_count,i,result_index=SIZE_MAX;
    xair_sym_expr_id equal,less,zero,value,eq_result,negative,rule,combined;
    xair_sym_taint_id taint=XAIR_SYM_TAINT_NONE;
    xair_sym_status status;uint16_t bits=0;char name[96];
#define CMP_NEED(expression) do {status=(expression);if(status!=XAIR_SYM_OK)return status;}while(0)
    if(count!=3||args[2]>256||args[0]>UINT64_MAX-args[2]||args[1]>UINT64_MAX-args[2])return XAIR_SYM_ERR_UNSUPPORTED;
    if(xair_op_results(state->module,op,&outputs,&output_count)!=XAIR_OK)return XAIR_SYM_ERR_BAD_ARG;
    for(i=0;i<output_count;++i){xair_type type=xair_value_type(state->module,outputs[i]);
        if(type.kind==XAIR_TYPE_INT){if(result_index!=SIZE_MAX)return XAIR_SYM_ERR_UNSUPPORTED;result_index=i;bits=type.bits;}}
    if(result_index==SIZE_MAX||bits!=32)return XAIR_SYM_ERR_UNSUPPORTED;
    CMP_NEED(xair_sym_const(state->context,1,1,&equal));
    CMP_NEED(xair_sym_const(state->context,1,0,&less));
    for(i=(size_t)args[2];i>0;--i){xair_sym_expr_id a,b,eq,lt,next; xair_sym_taint_id at,bt;
        CMP_NEED(loop_guard(state->context,(size_t)args[2]-i));
        CMP_NEED(xair_sym_memory_load8(state,args[0]+i-1,&a));CMP_NEED(xair_sym_memory_load8(state,args[1]+i-1,&b));
        CMP_NEED(xair_sym_memory_load_taint8(state,args[0]+i-1,&at));CMP_NEED(xair_sym_memory_load_taint8(state,args[1]+i-1,&bt));
        CMP_NEED(xair_sym_taint_union(state->context,taint,at,&taint));CMP_NEED(xair_sym_taint_union(state->context,taint,bt,&taint));
        CMP_NEED(xair_sym_binary(state->context,XAIR_OP_EQ,1,a,b,&eq));
        CMP_NEED(xair_sym_binary(state->context,XAIR_OP_ULT,1,a,b,&lt));
        CMP_NEED(xair_sym_select(state->context,eq,less,lt,&next));less=next;
        CMP_NEED(xair_sym_binary(state->context,XAIR_OP_AND,1,equal,eq,&next));equal=next;
    }
    snprintf(name,sizeof(name),"memcmp_%u_%llu_sign_result",(unsigned)op,(unsigned long long)state->context->stats.model_calls);
    CMP_NEED(xair_sym_symbol(state->context,bits,name,&value));CMP_NEED(xair_sym_const(state->context,bits,0,&zero));
    CMP_NEED(xair_sym_binary(state->context,XAIR_OP_EQ,1,value,zero,&eq_result));
    CMP_NEED(xair_sym_binary(state->context,XAIR_OP_SLT,1,value,zero,&negative));
    CMP_NEED(xair_sym_binary(state->context,XAIR_OP_EQ,1,eq_result,equal,&rule));
    CMP_NEED(xair_sym_binary(state->context,XAIR_OP_EQ,1,negative,less,&combined));
    CMP_NEED(xair_sym_state_assume(state,rule));CMP_NEED(xair_sym_state_assume(state,combined));
    CMP_NEED(set_call_results(state,op,0,0));
    CMP_NEED(xair_sym_model_call_result_set(state,op,result_index,value,taint));
#undef CMP_NEED
    return XAIR_SYM_OK;
}

static xair_sym_status environment_call_model(xair_sym_state *state, xair_op_id op, void *user) {
    xair_sym_environment *environment = (xair_sym_environment *)user;
    xair_op_attributes attributes;
    xair_sym_model_kind kind;
    uint64_t args[16], result_value = 0;
    size_t count = 0;
    const char *call_name;
    xair_sym_registered_model *registered;
    xair_sym_status status;
    if (state == NULL || environment == NULL || xair_op_attributes_get(state->module, op, &attributes) != XAIR_OK)
        return XAIR_SYM_ERR_BAD_ARG;
    state->model_library_version = environment->model_version;
    call_name = attributes.import_name != NULL ? attributes.import_name : attributes.semantic_id;
    registered = find_registered_model(environment, &attributes);
    if (registered != NULL && registered->callback != NULL) {
        state->context->stats.model_calls++;
        return registered->callback(state, op, registered->user);
    }
    kind = registered != NULL ? registered->info.kind : lookup_model(call_name);
    state->context->stats.model_calls++;
    if (kind == XAIR_SYM_MODEL_UNKNOWN) {
        state->context->stats.unknown_calls++;
        return unknown_call_fallback(state, op, &attributes);
    }
    status = call_scalar_values(state, op, args, sizeof(args) / sizeof(args[0]), &count);
    if (status == XAIR_SYM_ERR_UNSUPPORTED) {
        return unknown_call_fallback(state, op, &attributes);
    }
    if (status != XAIR_SYM_OK) return status;
    if(kind==XAIR_SYM_MODEL_COMPARE) {
        status=compare_call(state,op,args,count);
        return status==XAIR_SYM_ERR_UNSUPPORTED?unknown_call_fallback(state,op,&attributes):status;
    }
    switch (kind) {
    case XAIR_SYM_MODEL_ALLOC: {
        xair_sym_object_id object;
        uint64_t requested;
        size_t size;
        uint64_t aligned;
        int zero_initialize = 0;
        if (call_name != NULL && strcmp(call_name, "realloc") == 0) {
            xair_sym_object *old_object = NULL;
            xair_sym_memory *saved_memory;
            uint64_t saved_heap_next;
            size_t saved_object_bytes, saved_parallel_reserved;
            xair_sym_stats saved_stats;
            size_t object_i, copy_size;
            if (count < 2 || args[1] > SIZE_MAX) return XAIR_SYM_ERR_RESOURCE_LIMIT;
            if (args[0] == 0) requested = args[1];
            else {
                for (object_i = 0; object_i < state->memory->count; ++object_i) {
                    xair_sym_object *candidate = &state->memory->objects[object_i];
                    if (args[0] == candidate->base) {
                        old_object = candidate; break;
                    }
                }
                if (old_object == NULL) return XAIR_SYM_ERR_BAD_ARG;
                saved_memory = state->memory; xair_sym_memory_retain(saved_memory);
                saved_heap_next = state->heap_next;
                saved_object_bytes = state->context->object_bytes;
                saved_parallel_reserved = state->context->parallel_memory_reserved;
                saved_stats = state->context->stats;
                if (args[1] == 0) {
                    status = xair_sym_object_remove_containing(state, args[0]);
                    if (status == XAIR_SYM_OK) status = set_call_results(state, op, 1, 0);
                    if (status != XAIR_SYM_OK) {
                        rollback_memory_transaction(state, saved_memory, saved_heap_next,
                            saved_object_bytes, saved_parallel_reserved, &saved_stats); return status;
                    }
                    xair_sym_memory_release(saved_memory); return XAIR_SYM_OK;
                }
                requested = args[1];
                size = (size_t)requested;
                if (size > SIZE_MAX - 15u) return XAIR_SYM_ERR_RESOURCE_LIMIT;
                aligned = (uint64_t)((size + 15u) & ~(size_t)15u);
                copy_size = old_object->size < size ? old_object->size : size;
                result_value = state->heap_next;
                status = xair_sym_object_add(state, result_value, size, 3u, &object);
                if (status == XAIR_SYM_OK) status = xair_sym_environment_copy(
                    environment, state, result_value, args[0], copy_size);
                if (status == XAIR_SYM_OK) status = xair_sym_object_remove_containing(state, args[0]);
                if (status == XAIR_SYM_OK) state->heap_next += aligned;
                if (status == XAIR_SYM_OK) status = set_call_results(state, op, 1, result_value);
                if (status != XAIR_SYM_OK) {
                    rollback_memory_transaction(state, saved_memory, saved_heap_next,
                        saved_object_bytes, saved_parallel_reserved, &saved_stats); return status;
                }
                xair_sym_memory_release(saved_memory); return XAIR_SYM_OK;
            }
        }
        if (call_name != NULL && strcmp(call_name, "calloc") == 0) {
            if (count < 2 || (args[0] != 0 && args[1] > UINT64_MAX / args[0])) return XAIR_SYM_ERR_RESOURCE_LIMIT;
            requested = count < 2 ? 0 : args[0] * args[1];
            zero_initialize = 1;
        } else if (call_name != NULL && (strcmp(call_name, "ExAllocatePool") == 0 ||
            strcmp(call_name, "ExAllocatePoolWithTag") == 0)) {
            requested = count < 2 ? 0 : args[1];
        } else requested = count == 0 ? 0 : args[count - 1];
        if (requested > SIZE_MAX) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        size = requested == 0 ? 1 : (size_t)requested;
        if (size > SIZE_MAX - 15u) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        aligned = (uint64_t)((size + 15u) & ~(size_t)15u);
        result_value = state->heap_next;
        status = xair_sym_memory_map_lazy(state, result_value, size, 3u, NULL, 0,
            zero_initialize, &object);
        if (status == XAIR_SYM_OK) state->heap_next += aligned;
        break;
    }
    case XAIR_SYM_MODEL_FREE:
        {
            size_t pointer_index = call_name != NULL &&
                (strcmp(call_name, "HeapFree") == 0 || strcmp(call_name, "RtlFreeHeap") == 0) ? 2u : 0u;
            status = count <= pointer_index ? XAIR_SYM_ERR_BAD_ARG :
                args[pointer_index] == 0 ? XAIR_SYM_OK :
                xair_sym_object_remove_containing(state, args[pointer_index]);
        }
        result_value = status == XAIR_SYM_OK ? 1 : 0;
        break;
    case XAIR_SYM_MODEL_COPY:
        status = count < 3 ? XAIR_SYM_ERR_BAD_ARG :
            xair_sym_environment_copy(environment, state, args[count - 3], args[count - 2], (size_t)args[count - 1]);
        result_value = count < 3 ? 0 : args[count - 3];
        break;
    case XAIR_SYM_MODEL_FILL: {
        size_t i, size = count < 3 ? 0 : (size_t)args[count - 1];
        xair_sym_expr_id byte;
        xair_sym_expr_id *values;
        xair_sym_taint_id *taints;
        size_t allocation;
        if (count < 3) return XAIR_SYM_ERR_BAD_ARG;
        if (args[count - 1] > SIZE_MAX || size > SIZE_MAX / (sizeof(*values) + sizeof(*taints)))
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
        if (size == 0) { result_value = args[count - 3]; break; }
        status = xair_sym_memory_validate_range(state, args[count - 3], size, 2u);
        if (status != XAIR_SYM_OK) return status;
        status = loop_guard(state->context, 0);
        if (status != XAIR_SYM_OK) return status;
        status = xair_sym_const(state->context, 8, args[count - 2] & 0xffu, &byte);
        if (status != XAIR_SYM_OK) return status;
        allocation = size * (sizeof(*values) + sizeof(*taints));
        if (!xair_sym_parallel_memory_reserve(state->context, allocation)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        values = (xair_sym_expr_id *)malloc(size * sizeof(*values));
        taints = (xair_sym_taint_id *)calloc(size, sizeof(*taints));
        if (values == NULL || taints == NULL) {
            free(taints); free(values); xair_sym_parallel_memory_release(state->context, allocation);
            return XAIR_SYM_ERR_OOM;
        }
        for (i = 0; i < size; ++i) values[i] = byte;
        status = xair_sym_memory_store_bytes(state, args[count - 3], values, taints, size);
        free(taints); free(values); xair_sym_parallel_memory_release(state->context, allocation);
        result_value = args[count - 3];
        break;
    }
    case XAIR_SYM_MODEL_INPUT:
    case XAIR_SYM_MODEL_DRIVER_INPUT: {
        size_t address_index = 1u, size_index = 2u;
        size_t size;
        uint64_t address;
        if (kind == XAIR_SYM_MODEL_DRIVER_INPUT) { address_index = 0u; size_index = 1u; }
        if (count <= size_index || args[size_index] > SIZE_MAX) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        size = (size_t)args[size_index];
        if (size > SIZE_MAX / sizeof(xair_sym_expr_id)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        address = args[address_index];
        {
            size_t allocation = (size != 0 ? size : 1u) * sizeof(xair_sym_expr_id);
            xair_sym_expr_id *symbols;
            if (!xair_sym_parallel_memory_reserve(state->context, allocation)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
            symbols = (xair_sym_expr_id *)malloc(allocation);
            if (symbols == NULL) {
                xair_sym_parallel_memory_release(state->context, allocation); return XAIR_SYM_ERR_OOM;
            }
        status = xair_sym_environment_input(environment, state, address, size,
            call_name != NULL && strcmp(call_name, "ReadFile") == 0 ? "file" :
            call_name != NULL && strcmp(call_name, "read") == 0 ? "file" :
            kind == XAIR_SYM_MODEL_INPUT ? "network" : "driver", symbols);
        free(symbols);
            xair_sym_parallel_memory_release(state->context, allocation);
        }
        if (status == XAIR_SYM_OK && call_name != NULL && strcmp(call_name, "ReadFile") == 0) {
            size_t byte_i;
            if (count < 4) return XAIR_SYM_ERR_BAD_ARG;
            if (args[3] != 0) {
                xair_sym_expr_id bytes_written[4];
                xair_sym_taint_id clean[4] = {0, 0, 0, 0};
                if (args[3] > UINT64_MAX - 3u) return XAIR_SYM_ERR_RANGE;
                status = xair_sym_memory_validate_range(state, args[3], 4u, 2u);
                for (byte_i = 0; byte_i < 4u && status == XAIR_SYM_OK; ++byte_i)
                    status = xair_sym_const(state->context, 8,
                        ((uint64_t)(uint32_t)size >> (byte_i * 8u)) & 0xffu, &bytes_written[byte_i]);
                if (status == XAIR_SYM_OK)
                    status = xair_sym_memory_store_bytes(state, args[3], bytes_written, clean, 4u);
            }
            result_value = 1u;
        } else result_value = size;
        break;
    }
    case XAIR_SYM_MODEL_LENGTH: {
        size_t length = 0;
        xair_sym_expr_id byte;
        uint64_t byte_value;
        if (count == 0) return XAIR_SYM_ERR_BAD_ARG;
        for (;;) {
            xair_sym_expr_view view;
            if(length>=256||args[count-1]>UINT64_MAX-length)return unknown_call_fallback(state,op,&attributes);
            status=loop_guard(state->context,length);if(status!=XAIR_SYM_OK)return status;
            if(xair_sym_memory_load8(state,args[count-1]+length,&byte)!=XAIR_SYM_OK||
               xair_sym_expr_get(state->context,byte,&view)!=XAIR_SYM_OK||view.kind!=XAIR_SYM_EXPR_CONST)
                return unknown_call_fallback(state,op,&attributes);
            byte_value=view.immediate;if(byte_value==0)break;++length;
        }
        result_value = length;
        status = XAIR_SYM_OK;
        break;
    }
    case XAIR_SYM_MODEL_NO_RETURN:
    case XAIR_SYM_MODEL_DRIVER_COMPLETE:
        state->terminate_requested = 1;
        status = XAIR_SYM_OK;
        break;
    default:
        status = XAIR_SYM_ERR_UNSUPPORTED;
        break;
    }
    if (status != XAIR_SYM_OK) return status;
    return set_call_results(state, op, 1, result_value);
}

xair_sym_status xair_sym_environment_clone_builtin(const xair_sym_environment *source,
    xair_sym_context *context, xair_sym_environment **out_environment) {
    xair_sym_environment *copy;
    if (out_environment != NULL) *out_environment = NULL;
    if (source == NULL || context == NULL || out_environment == NULL || source->model_count != 0)
        return XAIR_SYM_ERR_UNSUPPORTED;
    copy = (xair_sym_environment *)calloc(1, sizeof(*copy));
    if (copy == NULL) return XAIR_SYM_ERR_OOM;
    copy->refs = 1; copy->context = context; copy->arch = source->arch; copy->abi = source->abi;
    copy->model_version = source->model_version; copy->stack_base = source->stack_base;
    copy->stack_size = source->stack_size; copy->heap_next = source->heap_next;
    *out_environment = copy;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_environment_create_builtin_snapshot(xair_sym_context *context,
    xair_arch arch, xair_calling_convention abi, uint64_t model_version,
    uint64_t stack_base, size_t stack_size, uint64_t heap_next,
    xair_sym_environment **out_environment) {
    xair_sym_environment *environment;
    if (out_environment != NULL) *out_environment = NULL;
    if (context == NULL || out_environment == NULL ||
        (arch != XAIR_ARCH_X86_32 && arch != XAIR_ARCH_X86_64) ||
        abi > XAIR_CC_STDCALL_X86 || model_version != UINT64_C(0x00010001) ||
        stack_size == 0 || stack_base > UINT64_MAX - (stack_size - 1u)) return XAIR_SYM_ERR_BAD_ARG;
    environment = (xair_sym_environment *)calloc(1, sizeof(*environment));
    if (environment == NULL) return XAIR_SYM_ERR_OOM;
    environment->refs = 1; environment->context = context; environment->arch = arch;
    environment->abi = abi; environment->model_version = model_version;
    environment->stack_base = stack_base; environment->stack_size = stack_size;
    environment->heap_next = heap_next;
    *out_environment = environment;
    return XAIR_SYM_OK;
}

void xair_sym_environment_attach_builtin(xair_sym_state *state, xair_sym_environment *environment) {
    if (state == NULL) return;
    xair_sym_environment_release(state->environment);
    state->environment = environment;
    state->call_model = environment != NULL ? environment_call_model : NULL;
    state->call_model_user = environment;
}

void xair_sym_process_options_init(xair_sym_process_options *options, xair_arch arch) {
    if (options == NULL) return;
    memset(options, 0, sizeof(*options));
    xair_analysis_options_init(&options->analysis);
    options->stack_size = 1024u * 1024u;
    options->max_segment_size = 512u * 1024u * 1024u;
    options->stack_base = arch == XAIR_ARCH_X86_32 ? UINT64_C(0x70000000) : UINT64_C(0x00007fff00000000);
    options->abi = arch == XAIR_ARCH_X86_32 ? XAIR_CC_CDECL_X86 : XAIR_CC_UNKNOWN;
}

static xair_sym_status initialize_segment(
    xair_sym_context *context,
    xair_sym_state *state,
    const xair_binary_segment *segment,
    size_t max_segment_size) {
    xair_sym_object_id object;
    size_t size;
    uint8_t *owned_bytes = NULL;
    xair_sym_status status;
    if (segment->mem_size == 0) return XAIR_SYM_OK;
    if (segment->mem_size > max_segment_size || segment->mem_size > SIZE_MAX || segment->file_size > segment->mem_size) {
        return XAIR_SYM_ERR_RANGE;
    }
    if (segment->file_size != 0 && segment->bytes == NULL) return XAIR_SYM_ERR_BAD_ARG;
    size = (size_t)segment->mem_size;
    if (segment->file_size != 0) {
        owned_bytes = (uint8_t *)malloc((size_t)segment->file_size);
        if (owned_bytes == NULL) return XAIR_SYM_ERR_OOM;
        memcpy(owned_bytes, segment->bytes, (size_t)segment->file_size);
    }
    status = xair_sym_memory_map_lazy(state, segment->va, size, segment->perms,
        owned_bytes, (size_t)segment->file_size, 1, &object);
    if (status == XAIR_SYM_OK && owned_bytes != NULL && state->memory->objects[object].backing_ref != NULL)
        state->memory->objects[object].backing_ref->owned = 1;
    else if (status != XAIR_SYM_OK) free(owned_bytes);
    (void)context;
    (void)object;
    return status;
}

static xair_sym_status initialize_entry_parameters(
    xair_sym_context *context,
    xair_sym_state *state,
    xair_block_id entry,
    uint64_t stack_pointer) {
    size_t count = xair_block_param_count(state->module, entry);
    size_t i;
    for (i = 0; i < count; ++i) {
        xair_value_id parameter;
        xair_type type;
        const char *name;
        xair_sym_expr_id value;
        xair_sym_status status;
        if (xair_block_param_value(state->module, entry, i, &parameter) != XAIR_OK) return XAIR_SYM_ERR_BAD_ARG;
        type = xair_value_type(state->module, parameter);
        name = xair_value_name(state->module, parameter);
        if (type.kind == XAIR_TYPE_MEM) {
            state->defined[parameter] = 1;
            state->values[parameter] = XAIR_SYM_INVALID_ID;
            continue;
        } else if (type.kind == XAIR_TYPE_INT || type.kind == XAIR_TYPE_ADDR || type.kind == XAIR_TYPE_FLAGS) {
            if (name != NULL && (strcmp(name, "rsp") == 0 || strcmp(name, "esp") == 0)) {
                status = xair_sym_const(context, type.bits, stack_pointer, &value);
            } else if (name != NULL && strcmp(name, "fs_base") == 0) {
                status = xair_sym_const(context, type.bits, state->fs_base, &value);
            } else if (name != NULL && strcmp(name, "gs_base") == 0) {
                status = xair_sym_const(context, type.bits, state->gs_base, &value);
            } else {
                char symbol_name[80];
                const char *role = "initial";
                if (state->abi == XAIR_CC_WIN64 && name != NULL) {
                    if (strcmp(name, "rcx") == 0 || strcmp(name, "rdx") == 0 ||
                        strcmp(name, "r8") == 0 || strcmp(name, "r9") == 0) role = "win64_argument";
                    else if (strcmp(name, "rbx") == 0 || strcmp(name, "rbp") == 0 ||
                        strcmp(name, "rdi") == 0 || strcmp(name, "rsi") == 0 ||
                        strcmp(name, "r12") == 0 || strcmp(name, "r13") == 0 ||
                        strcmp(name, "r14") == 0 || strcmp(name, "r15") == 0) role = "win64_callee_saved";
                    else if (strcmp(name, "rax") == 0) role = "win64_return_caller_saved";
                    else if (strcmp(name, "r10") == 0 || strcmp(name, "r11") == 0) role = "win64_caller_saved";
                    else if (type.kind == XAIR_TYPE_FLAGS) role = "win64_unknown_flags";
                }
                (void)snprintf(symbol_name, sizeof(symbol_name), "%s_%s_%u", role,
                    name == NULL ? "value" : name, (unsigned)parameter);
                status = xair_sym_symbol(context, type.bits, symbol_name, &value);
            }
        } else {
            return XAIR_SYM_ERR_UNSUPPORTED;
        }
        if (status != XAIR_SYM_OK) return status;
        status = xair_sym_state_set_value(state, parameter, value);
        if (status != XAIR_SYM_OK) return status;
    }
    return XAIR_SYM_OK;
}

static xair_sym_status initialize_postdominators(xair_sym_context *context, const xair_cfg *cfg) {
    size_t block_count = xair_module_block_count(xair_cfg_module(cfg));
    size_t function_i, block_i;
    free(context->immediate_postdominators);
    context->immediate_postdominators = (xair_block_id *)malloc(
        (block_count != 0 ? block_count : 1) * sizeof(*context->immediate_postdominators));
    if (context->immediate_postdominators == NULL) return XAIR_SYM_ERR_OOM;
    context->immediate_postdominator_count = block_count;
    for (block_i = 0; block_i < block_count; ++block_i)
        context->immediate_postdominators[block_i] = XAIR_INVALID_ID;
    for (function_i = 0; function_i < xair_cfg_function_count(cfg); ++function_i) {
        xair_cfg_function_analysis *analysis = NULL;
        const xair_cfg_node_id *nodes;
        size_t node_count, node_i;
        if (xair_cfg_analyze_function(cfg, (xair_function_id)function_i, &analysis) != XAIR_OK) continue;
        nodes = xair_cfg_function_nodes(cfg, (xair_function_id)function_i, &node_count);
        for (node_i = 0; node_i < node_count; ++node_i) {
            const xair_cfg_node *node = xair_cfg_get_node(cfg, nodes[node_i]);
            xair_cfg_node_id postdom_id = xair_cfg_analysis_immediate_postdominator(analysis, nodes[node_i]);
            const xair_cfg_node *postdom = xair_cfg_get_node(cfg, postdom_id);
            if (node != NULL && postdom != NULL && node->ir_block < block_count)
                context->immediate_postdominators[node->ir_block] = postdom->ir_block;
        }
        xair_cfg_function_analysis_destroy(analysis);
    }
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_process_create(
    xair_sym_context *context,
    const xair_cfg *cfg,
    const xair_binary_view *binary,
    const xair_sym_process_options *options,
    xair_sym_environment **out_environment,
    xair_sym_state **out_state) {
    xair_cfg_node_id entry_node;
    const xair_cfg_node *node;
    xair_sym_environment *environment;
    xair_sym_state *state = NULL;
    xair_sym_object_id stack_object;
    uint64_t stack_pointer;
    size_t i;
    uint64_t mapped_bytes = 0;
    uint64_t started = xair_monotonic_milliseconds();
    xair_sym_status status;
    if (out_environment != NULL) *out_environment = NULL;
    if (out_state != NULL) *out_state = NULL;
    if (context == NULL || cfg == NULL || binary == NULL || options == NULL || out_environment == NULL || out_state == NULL ||
        options->stack_size < (binary != NULL && binary->arch == XAIR_ARCH_X86_64 ? 256u : 64u) ||
        options->max_segment_size == 0 || !xair_cfg_is_frozen(cfg)) return XAIR_SYM_ERR_BAD_ARG;
    if (options->abi > XAIR_CC_STDCALL_X86) return XAIR_SYM_ERR_BAD_ARG;
    if ((options->analysis.max_segments != 0 && binary->segment_count > options->analysis.max_segments) ||
        xair_cancel_token_requested(options->analysis.cancel_token))
        return xair_cancel_token_requested(options->analysis.cancel_token) ?
            XAIR_SYM_ERR_CANCELED : XAIR_SYM_ERR_RESOURCE_LIMIT;
    for (i = 0; i < binary->segment_count; ++i) {
        if (binary->segments[i].mem_size > UINT64_MAX - mapped_bytes) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        mapped_bytes += binary->segments[i].mem_size;
    }
    if (options->stack_size > UINT64_MAX - mapped_bytes) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    mapped_bytes += options->stack_size;
    if (options->analysis.max_bytes != 0 && mapped_bytes > options->analysis.max_bytes)
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (options->stack_base > UINT64_MAX - options->stack_size) return XAIR_SYM_ERR_RANGE;
    xair_sym_context_set_analysis_options(context, &options->analysis);
    entry_node = xair_cfg_find_node_start(cfg, binary->entry);
    if (entry_node == XAIR_CFG_INVALID_ID) entry_node = xair_cfg_find_node_containing(cfg, binary->entry);
    node = xair_cfg_get_node(cfg, entry_node);
    if (node == NULL || node->ir_block == XAIR_INVALID_ID) return XAIR_SYM_ERR_UNSUPPORTED;
    environment = (xair_sym_environment *)calloc(1, sizeof(*environment));
    if (environment == NULL) return XAIR_SYM_ERR_OOM;
    environment->refs = 1;
    environment->context = context; environment->arch = binary->arch;
    environment->abi = options->abi != XAIR_CC_UNKNOWN ? options->abi :
        (binary->format == XAIR_BINARY_FORMAT_PE ? XAIR_CC_WIN64 : XAIR_CC_SYSV_X64);
    environment->model_version = UINT64_C(0x00010001);
    environment->stack_base = options->stack_base; environment->stack_size = options->stack_size;
    environment->heap_next = binary->arch == XAIR_ARCH_X86_32 ? UINT64_C(0x50000000) : UINT64_C(0x0000600000000000);
    status = xair_sym_state_create(context, xair_cfg_module(cfg), node->ir_block, &state);
    if (status != XAIR_SYM_OK) goto fail;
    state->abi = environment->abi;
    state->binary_hash = xair_cfg_binary_hash(cfg);
    state->model_library_version = environment->model_version;
    state->options_fingerprint = xair_cfg_options_fingerprint(cfg);
    state->heap_next = environment->heap_next;
    xair_sym_state_set_call_model(state, environment_call_model, environment);
    state->environment = environment;
    xair_sym_environment_retain(environment);
    state->fs_base = options->fs_base;
    state->gs_base = options->gs_base;
    if (environment->abi == XAIR_CC_WIN64 && state->gs_base == 0)
        state->gs_base = UINT64_C(0x00007fffff000000);
    status = initialize_postdominators(context, cfg);
    if (status != XAIR_SYM_OK) goto fail;
    for (i = 0; i < binary->segment_count; ++i) {
        if (xair_cancel_token_requested(options->analysis.cancel_token)) { status = XAIR_SYM_ERR_CANCELED; goto fail; }
        if (options->analysis.max_wall_time != 0 &&
            xair_monotonic_milliseconds() - started >= options->analysis.max_wall_time) {
            status = XAIR_SYM_ERR_RESOURCE_LIMIT; goto fail;
        }
        status = initialize_segment(context, state, &binary->segments[i], options->max_segment_size);
        if (status != XAIR_SYM_OK) goto fail;
        if (options->analysis.progress_callback != NULL)
            options->analysis.progress_callback(XAIR_STAGE_SYMBOLIC, i + 1,
                binary->segment_count, options->analysis.progress_user);
    }
    if (options->enable_minimal_process_environment) {
        xair_sym_object_id process_object;
        uint64_t base = environment->abi == XAIR_CC_WIN64 ? state->gs_base : state->fs_base;
        if (base == 0) { status = XAIR_SYM_ERR_UNSUPPORTED; goto fail; }
        status = xair_sym_memory_map_lazy(state, base, XAIR_SYM_PAGE_SIZE, 3u, NULL, 0, 1, &process_object);
        if (status != XAIR_SYM_OK) goto fail;
        (void)process_object;
    }
    status = xair_sym_object_add(state, options->stack_base, options->stack_size, 3u, &stack_object);
    if (status != XAIR_SYM_OK) goto fail;
    (void)stack_object;
    stack_pointer = (options->stack_base + options->stack_size) & ~UINT64_C(15);
    stack_pointer -= environment->abi == XAIR_CC_WIN64 ? 40u : 8u;
    for (i = 0; i < (environment->abi == XAIR_CC_WIN64 ? 40u : 8u); ++i) {
        xair_sym_expr_id zero;
        status = xair_sym_const(context, 8, 0, &zero);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_store8(state, stack_pointer + i, zero);
        if (status != XAIR_SYM_OK) goto fail;
    }
    status = initialize_entry_parameters(context, state, node->ir_block, stack_pointer);
    if (status != XAIR_SYM_OK) goto fail;
    *out_environment = environment; *out_state = state;
    return XAIR_SYM_OK;
fail:
    xair_sym_state_destroy(state); xair_sym_environment_release(environment); return status;
}

void xair_sym_environment_retain(xair_sym_environment *environment) {
    if (environment != NULL) environment->refs++;
}

void xair_sym_environment_release(xair_sym_environment *environment) {
    size_t i;
    if (environment == NULL || --environment->refs != 0) return;
    for (i = 0; i < environment->model_count; ++i) {
        free(environment->models[i].module);
        free(environment->models[i].name);
        free(environment->models[i].user_identity);
    }
    free(environment->models);
    free(environment);
}

void xair_sym_environment_destroy(xair_sym_environment *environment) {
    xair_sym_environment_release(environment);
}

xair_sym_status xair_sym_state_attach_environment(xair_sym_state *state,
    xair_sym_environment *environment) {
    if (state == NULL || environment == NULL || state->context != environment->context)
        return XAIR_SYM_ERR_BAD_ARG;
    xair_sym_environment_retain(environment);
    xair_sym_environment_attach_builtin(state, environment);
    state->abi = environment->abi;
    state->model_library_version = environment->model_version;
    state->heap_next = environment->heap_next;
    return XAIR_SYM_OK;
}

static xair_sym_status environment_register_model_impl(xair_sym_environment *environment,
    const xair_sym_model_identity *identity, const xair_sym_model_info *info,
    xair_sym_call_model_cb callback, void *user, int callback_required) {
    xair_sym_registered_model *entry;
    if (environment == NULL || identity == NULL || info == NULL ||
        (callback_required && callback == NULL) ||
        (identity->module == NULL && identity->name == NULL && identity->ordinal == 0 &&
         identity->address == 0 && identity->user_identity == NULL)) return XAIR_SYM_ERR_BAD_ARG;
    if (environment->model_count == environment->model_capacity) {
        size_t capacity = environment->model_capacity == 0 ? 8u : environment->model_capacity * 2u;
        xair_sym_registered_model *models;
        if (capacity < environment->model_capacity || capacity > SIZE_MAX / sizeof(*models))
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
        models = (xair_sym_registered_model *)realloc(environment->models, capacity * sizeof(*models));
        if (models == NULL) return XAIR_SYM_ERR_OOM;
        environment->models = models;
        environment->model_capacity = capacity;
    }
    entry = &environment->models[environment->model_count];
    memset(entry, 0, sizeof(*entry));
    entry->module = copy_text(identity->module);
    entry->name = copy_text(identity->name);
    entry->user_identity = copy_text(identity->user_identity);
    if ((identity->module != NULL && entry->module == NULL) ||
        (identity->name != NULL && entry->name == NULL) ||
        (identity->user_identity != NULL && entry->user_identity == NULL)) {
        free(entry->module); free(entry->name); free(entry->user_identity); memset(entry, 0, sizeof(*entry));
        return XAIR_SYM_ERR_OOM;
    }
    entry->ordinal = identity->ordinal; entry->address = identity->address;
    entry->info = *info; entry->callback = callback; entry->user = user;
    environment->model_count++;
    environment->model_version = model_hash_text(environment->model_version, identity->module);
    environment->model_version = model_hash_text(environment->model_version, identity->name);
    environment->model_version = model_hash_text(environment->model_version, identity->user_identity);
    environment->model_version = (environment->model_version ^ identity->ordinal) * UINT64_C(1099511628211);
    environment->model_version = (environment->model_version ^ identity->address) * UINT64_C(1099511628211);
    environment->model_version = (environment->model_version ^ (uint64_t)info->kind) * UINT64_C(1099511628211);
    environment->model_version = (environment->model_version ^ info->version_major) * UINT64_C(1099511628211);
    environment->model_version = (environment->model_version ^ info->version_minor) * UINT64_C(1099511628211);
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_environment_register_model(xair_sym_environment *environment,
    const xair_sym_model_identity *identity, const xair_sym_model_info *info,
    xair_sym_call_model_cb callback, void *user) {
    return environment_register_model_impl(
        environment, identity, info, callback, user, 1);
}

xair_sym_status xair_sym_environment_register_model_kind(
    xair_sym_environment *environment, const xair_sym_model_identity *identity,
    const xair_sym_model_info *info) {
    return environment_register_model_impl(
        environment, identity, info, NULL, NULL, 0);
}

xair_sym_status xair_sym_environment_model(
    const xair_sym_environment *environment,
    const char *name,
    xair_sym_model_kind *out_kind) {
    xair_sym_model_info info;
    if (environment == NULL || name == NULL || out_kind == NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (xair_sym_environment_model_info(environment, name, &info) != XAIR_SYM_OK) return XAIR_SYM_ERR_BAD_ARG;
    *out_kind = info.kind;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_environment_create_builtin(xair_sym_context *context,
    xair_arch arch,xair_calling_convention abi,xair_sym_environment **out_environment) {
    return xair_sym_environment_create_builtin_snapshot(context,arch,abi,
        UINT64_C(0x00010001),UINT64_C(0x70000000),4096,UINT64_C(0x40000000),out_environment);
}

xair_sym_status xair_sym_environment_model_info(
    const xair_sym_environment *environment,
    const char *name,
    xair_sym_model_info *out_info) {
    size_t i;
    if (environment == NULL || name == NULL || out_info == NULL) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < sizeof(builtin_models) / sizeof(builtin_models[0]); ++i) {
        if (strcmp(name, builtin_models[i].name) == 0) {
            out_info->kind = builtin_models[i].kind;
            out_info->version_major = 1;
            out_info->version_minor = 0;
            return XAIR_SYM_OK;
        }
    }
    out_info->kind = XAIR_SYM_MODEL_UNKNOWN;
    out_info->version_major = 0;
    out_info->version_minor = 0;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_environment_model_identity(const xair_sym_environment *environment,
    const xair_sym_model_identity *identity, xair_sym_model_info *out_info) {
    const char *name;
    size_t i;
    if (environment == NULL || identity == NULL || out_info == NULL) return XAIR_SYM_ERR_BAD_ARG;
    for (i = 0; i < environment->model_count; ++i) {
        const xair_sym_registered_model *model = &environment->models[i];
        if (!identity_text_matches(model->module, identity->module) ||
            !identity_text_matches(model->name, identity->name) ||
            !identity_text_matches(model->user_identity, identity->user_identity) ||
            (model->ordinal != 0 && model->ordinal != identity->ordinal) ||
            (model->address != 0 && model->address != identity->address)) continue;
        *out_info = model->info;
        return XAIR_SYM_OK;
    }
    name = identity->name != NULL ? identity->name : identity->user_identity;
    out_info->kind = lookup_model(name);
    out_info->version_major = out_info->kind == XAIR_SYM_MODEL_UNKNOWN ? 0 : 1;
    out_info->version_minor = 0;
    return XAIR_SYM_OK;
}

uint64_t xair_sym_environment_model_version(const xair_sym_environment *environment) {
    return environment == NULL ? 0 : environment->model_version;
}

xair_sym_status xair_sym_environment_allocate(
    xair_sym_environment *environment,
    xair_sym_state *state,
    size_t size,
    uint64_t *out_address) {
    xair_sym_object_id object;
    uint64_t aligned;
    xair_sym_status status;
    if (environment == NULL || state == NULL || out_address == NULL || size == 0) return XAIR_SYM_ERR_BAD_ARG;
    *out_address = 0;
    if (xair_cancel_token_requested(state->context->analysis.cancel_token)) return XAIR_SYM_ERR_CANCELED;
    if (state->context->analysis.max_bytes != 0 && size > state->context->analysis.max_bytes)
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (size > SIZE_MAX - 15u) return XAIR_SYM_ERR_RANGE;
    aligned = (uint64_t)((size + 15u) & ~(size_t)15u);
    if (aligned < size || environment->heap_next > UINT64_MAX - aligned) return XAIR_SYM_ERR_RANGE;
    status = xair_sym_object_add(state, environment->heap_next, size, 3u, &object);
    if (status != XAIR_SYM_OK) return status;
    (void)object; *out_address = environment->heap_next; environment->heap_next += aligned;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_environment_input(
    xair_sym_environment *environment,
    xair_sym_state *state,
    uint64_t address,
    size_t size,
    const char *source_name,
    xair_sym_expr_id *out_symbols) {
    xair_sym_taint_id taint;
    size_t i;
    uint64_t origin;
    xair_sym_status status;
    if (environment == NULL || state == NULL || source_name == NULL ||
        (size != 0 && out_symbols == NULL)) return XAIR_SYM_ERR_BAD_ARG;
    if (size != 0 && address > UINT64_MAX - (size - 1u)) return XAIR_SYM_ERR_RANGE;
    if (state->context->analysis.max_bytes != 0 && size > state->context->analysis.max_bytes)
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (size == 0) return XAIR_SYM_OK;
    status = xair_sym_memory_validate_range(state, address, size, 2u);
    if (status != XAIR_SYM_OK) return status;
    status = loop_guard(state->context, 0);
    if (status != XAIR_SYM_OK) return status;
    origin = state->context->expression_count;
    {
        xair_sym_taint_details details;
        memset(&details, 0, sizeof(details));
        details.category = strcmp(source_name, "network") == 0 ? XAIR_SYM_TAINT_CATEGORY_NETWORK :
            strcmp(source_name, "file") == 0 ? XAIR_SYM_TAINT_CATEGORY_FILE :
            strcmp(source_name, "driver") == 0 ? XAIR_SYM_TAINT_CATEGORY_DRIVER : XAIR_SYM_TAINT_CATEGORY_USER;
        details.source_address = address;
        details.call_site = origin;
        details.byte_length = size;
        status = xair_sym_taint_source_ex(state->context, source_name, &details, &taint);
    }
    if (status != XAIR_SYM_OK) return status;
    for (i = 0; i < size; ++i) {
        char name[96];
        (void)snprintf(name, sizeof(name), "%s_%llu_%zu", source_name,
            (unsigned long long)origin, i);
        status = xair_sym_symbol(state->context, 8, name, &out_symbols[i]);
        if (status != XAIR_SYM_OK) return status;
    }
    {
        xair_sym_taint_id *taints;
        size_t allocation;
        if (size > SIZE_MAX / sizeof(*taints)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        allocation = size * sizeof(*taints);
        if (!xair_sym_parallel_memory_reserve(state->context, allocation)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        taints = (xair_sym_taint_id *)malloc(allocation);
        if (taints == NULL) {
            xair_sym_parallel_memory_release(state->context, allocation); return XAIR_SYM_ERR_OOM;
        }
        for (i = 0; i < size; ++i) taints[i] = taint;
        status = xair_sym_memory_store_bytes(state, address, out_symbols, taints, size);
        free(taints); xair_sym_parallel_memory_release(state->context, allocation);
    }
    return status;
}

xair_sym_status xair_sym_environment_copy(
    xair_sym_environment *environment,
    xair_sym_state *state,
    uint64_t destination,
    uint64_t source,
    size_t size) {
    size_t i;
    xair_sym_expr_id *values;
    xair_sym_taint_id *taints;
    xair_sym_status status = XAIR_SYM_OK;
    if (environment == NULL || state == NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (size != 0 && (destination > UINT64_MAX - (size - 1u) || source > UINT64_MAX - (size - 1u)))
        return XAIR_SYM_ERR_RANGE;
    if (state->context->analysis.max_bytes != 0 && size > state->context->analysis.max_bytes)
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (size == 0) return XAIR_SYM_OK;
    status = xair_sym_memory_validate_range(state, source, size, 1u);
    if (status == XAIR_SYM_OK) status = xair_sym_memory_validate_range(state, destination, size, 2u);
    if (status != XAIR_SYM_OK) return status;
    if (size > SIZE_MAX / sizeof(*values) || size > SIZE_MAX / sizeof(*taints)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    {
        size_t elements = size != 0 ? size : 1u;
        size_t allocation = elements * (sizeof(*values) + sizeof(*taints));
        if (!xair_sym_parallel_memory_reserve(state->context, allocation)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    values = (xair_sym_expr_id *)malloc((size != 0 ? size : 1) * sizeof(*values));
    taints = (xair_sym_taint_id *)malloc((size != 0 ? size : 1) * sizeof(*taints));
    if (values == NULL || taints == NULL) {
        free(taints); free(values); xair_sym_parallel_memory_release(state->context, allocation);
        return XAIR_SYM_ERR_OOM;
    }
    for (i = 0; i < size; ++i) {
        status = loop_guard(state->context, i);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_load8(state, source + i, &values[i]);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_load_taint8(state, source + i, &taints[i]);
        if (status != XAIR_SYM_OK) break;
    }
    if (status == XAIR_SYM_OK)
        status = xair_sym_memory_store_bytes(state, destination, values, taints, size);
    free(taints); free(values);
        xair_sym_parallel_memory_release(state->context, allocation);
    }
    return status;
}
