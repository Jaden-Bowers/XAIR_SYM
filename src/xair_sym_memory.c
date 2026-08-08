#include "xair_sym_internal.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void page_retain(xair_sym_page *page) { if (page != NULL) page->refs++; }

static void page_release(xair_sym_page *page) {
    if (page != NULL && --page->refs == 0) free(page);
}

static xair_sym_backing *backing_create(const uint8_t *bytes, size_t size, int owned) {
    xair_sym_backing *backing;
    size_t i;
    if (size == 0) return NULL;
    backing = (xair_sym_backing *)malloc(sizeof(*backing));
    if (backing == NULL) return NULL;
    backing->refs = 1;
    backing->bytes = bytes;
    backing->size = size;
    backing->owned = owned != 0;
    backing->hash = UINT64_C(1469598103934665603);
    for (i = 0; i < size; ++i)
        backing->hash = (backing->hash ^ bytes[i]) * UINT64_C(1099511628211);
    return backing;
}

static void backing_retain(xair_sym_backing *backing) {
    if (backing != NULL) backing->refs++;
}

static void backing_release(xair_sym_backing *backing) {
    if (backing == NULL || --backing->refs != 0) return;
    if (backing->owned) free((void *)backing->bytes);
    free(backing);
}

static xair_sym_page *page_create(void) {
    xair_sym_page *page = (xair_sym_page *)malloc(sizeof(*page));
    size_t i;
    if (page == NULL) return NULL;
    page->refs = 1;
    for (i = 0; i < XAIR_SYM_PAGE_SIZE; ++i) page->bytes[i] = XAIR_SYM_INVALID_ID;
    memset(page->taints, 0, sizeof(page->taints));
    return page;
}

static void object_release(xair_sym_object *object) {
    size_t i;
    if (object == NULL) return;
    for (i = 0; i < object->page_count; ++i) page_release(object->pages[i]);
    free(object->pages);
    backing_release(object->backing_ref);
    memset(object, 0, sizeof(*object));
}

xair_sym_memory *xair_sym_memory_create(void) {
    xair_sym_memory *memory = (xair_sym_memory *)calloc(1, sizeof(*memory));
    if (memory != NULL) { memory->refs = 1; memory->version = 1; }
    return memory;
}

void xair_sym_memory_retain(xair_sym_memory *memory) { if (memory != NULL) memory->refs++; }

void xair_sym_memory_release(xair_sym_memory *memory) {
    size_t i;
    if (memory == NULL || --memory->refs != 0) return;
    for (i = 0; i < memory->count; ++i) object_release(&memory->objects[i]);
    free(memory->objects);
    free(memory);
}

xair_sym_status xair_sym_memory_make_unique(xair_sym_state *state) {
    xair_sym_memory *copy;
    size_t i, page_i, needed = sizeof(*copy);
    if (state == NULL || state->memory == NULL) return XAIR_SYM_ERR_BAD_ARG;
    if (state->memory->refs == 1) return XAIR_SYM_OK;
    if (state->memory->count > (SIZE_MAX - needed) / sizeof(*copy->objects))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    needed += state->memory->count * sizeof(*copy->objects);
    for (i = 0; i < state->memory->count; ++i) {
        size_t pages = state->memory->objects[i].page_count != 0 ?
            state->memory->objects[i].page_count : 1u;
        if (pages > (SIZE_MAX - needed) / sizeof(xair_sym_page *))
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
        needed += pages * sizeof(xair_sym_page *);
    }
    if (state->context->analysis.max_memory != 0) {
        if (needed > state->context->analysis.max_memory ||
            state->context->object_bytes > state->context->analysis.max_memory - needed)
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    if (!xair_sym_parallel_memory_reserve(state->context, needed)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    copy = xair_sym_memory_create();
    if (copy == NULL) { xair_sym_parallel_memory_release(state->context, needed); return XAIR_SYM_ERR_OOM; }
    copy->version = state->memory->version;
    if (state->memory->count != 0) {
        copy->objects = (xair_sym_object *)calloc(state->memory->count, sizeof(*copy->objects));
        if (copy->objects == NULL) {
            xair_sym_memory_release(copy); xair_sym_parallel_memory_release(state->context, needed);
            return XAIR_SYM_ERR_OOM;
        }
        copy->capacity = state->memory->count;
        for (i = 0; i < state->memory->count; ++i) {
            const xair_sym_object *source = &state->memory->objects[i];
            xair_sym_object *target = &copy->objects[i];
            *target = *source;
            backing_retain(target->backing_ref);
            target->pages = (xair_sym_page **)calloc(source->page_count != 0 ? source->page_count : 1,
                sizeof(*target->pages));
            if (target->pages == NULL) {
                copy->count = i + 1; xair_sym_memory_release(copy);
                xair_sym_parallel_memory_release(state->context, needed); return XAIR_SYM_ERR_OOM;
            }
            for (page_i = 0; page_i < source->page_count; ++page_i) {
                target->pages[page_i] = source->pages[page_i];
                page_retain(target->pages[page_i]);
            }
            copy->count++;
        }
    }
    xair_sym_memory_release(state->memory);
    state->memory = copy;
    state->context->stats.memory_cow_copies++;
    return XAIR_SYM_OK;
}

static size_t lower_bound_object(const xair_sym_memory *memory, uint64_t address) {
    size_t lo = 0, hi = memory->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (memory->objects[mid].base < address) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static xair_sym_object *find_object(xair_sym_memory *memory, uint64_t address) {
    size_t index = lower_bound_object(memory, address);
    if (index < memory->count && memory->objects[index].base == address) return &memory->objects[index];
    if (index == 0) return NULL;
    --index;
    return address - memory->objects[index].base < memory->objects[index].size ? &memory->objects[index] : NULL;
}

xair_sym_status xair_sym_memory_validate_range(const xair_sym_state *state,
    uint64_t address, size_t size, uint32_t permission) {
    xair_sym_object *object;
    if (state == NULL || size == 0 || address > UINT64_MAX - (size - 1u)) return XAIR_SYM_ERR_RANGE;
    object = find_object(state->memory, address);
    if (object == NULL || (object->permissions & permission) != permission || size > object->size ||
        address - object->base > object->size - size) return XAIR_SYM_ERR_RANGE;
    return XAIR_SYM_OK;
}

static xair_sym_status object_make_page_unique(xair_sym_state *state, xair_sym_object *object,
    size_t page_index, xair_sym_page **out_page) {
    xair_sym_page *page = object->pages[page_index];
    if (page == NULL) {
        if (state->context->analysis.max_memory != 0 &&
            (sizeof(*page) > state->context->analysis.max_memory ||
             state->context->object_bytes > state->context->analysis.max_memory - sizeof(*page)))
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
        if (!xair_sym_parallel_memory_reserve(state->context, sizeof(*page))) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        page = page_create();
        if (page == NULL) { xair_sym_parallel_memory_release(state->context, sizeof(*page)); return XAIR_SYM_ERR_OOM; }
        object->pages[page_index] = page;
        state->context->object_bytes += sizeof(*page);
        state->context->stats.memory_pages++;
    } else if (page->refs != 1) {
        if (state->context->analysis.max_memory != 0 &&
            (sizeof(*page) > state->context->analysis.max_memory ||
             state->context->object_bytes > state->context->analysis.max_memory - sizeof(*page)))
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
        xair_sym_page *copy;
        if (!xair_sym_parallel_memory_reserve(state->context, sizeof(*page))) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        copy = (xair_sym_page *)malloc(sizeof(*copy));
        if (copy == NULL) { xair_sym_parallel_memory_release(state->context, sizeof(*page)); return XAIR_SYM_ERR_OOM; }
        memcpy(copy, page, sizeof(*copy));
        copy->refs = 1;
        page_release(page);
        object->pages[page_index] = copy;
        page = copy;
        state->context->object_bytes += sizeof(*page);
        state->context->stats.memory_page_copies++;
    }
    object->version++;
    state->memory->version++;
    *out_page = page;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_map_lazy(xair_sym_state *state, uint64_t base, size_t size,
    uint32_t permissions, const uint8_t *backing, size_t backing_size, int zero_fill,
    xair_sym_object_id *out_object) {
    xair_sym_object object;
    size_t index, page_count;
    xair_sym_status status;
    if (state == NULL || out_object == NULL || size == 0 || backing_size > size ||
        (backing_size != 0 && backing == NULL) || base > UINT64_MAX - (size - 1)) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_memory_make_unique(state);
    if (status != XAIR_SYM_OK) return status;
    index = lower_bound_object(state->memory, base);
    if ((index != 0 && base - state->memory->objects[index - 1].base < state->memory->objects[index - 1].size) ||
        (index < state->memory->count && state->memory->objects[index].base - base < size)) return XAIR_SYM_ERR_BAD_ARG;
    if (state->memory->count == state->memory->capacity) {
        size_t capacity = state->memory->capacity == 0 ? 4 : state->memory->capacity * 2;
        size_t additional;
        xair_sym_object *objects;
        if (capacity < state->memory->capacity || capacity > SIZE_MAX / sizeof(*objects))
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
        additional = (capacity - state->memory->capacity) * sizeof(*objects);
        if (!xair_sym_parallel_memory_reserve(state->context, additional)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        objects = (xair_sym_object *)realloc(state->memory->objects, capacity * sizeof(*objects));
        if (objects == NULL) { xair_sym_parallel_memory_release(state->context, additional); return XAIR_SYM_ERR_OOM; }
        state->memory->objects = objects;
        state->memory->capacity = capacity;
    }
    page_count = (size >> XAIR_SYM_PAGE_SHIFT) + ((size & (XAIR_SYM_PAGE_SIZE - 1u)) != 0u);
    if (page_count > SIZE_MAX / sizeof(*object.pages)) return XAIR_SYM_ERR_RESOURCE_LIMIT;
    if (state->context->analysis.max_memory != 0) {
        size_t allocation = page_count * sizeof(*object.pages);
        if (allocation > state->context->analysis.max_memory ||
            state->context->object_bytes > state->context->analysis.max_memory - allocation)
            return XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    memset(&object, 0, sizeof(object));
    object.base = base; object.size = size; object.permissions = permissions;
    object.backing = backing; object.backing_size = backing_size; object.zero_fill = zero_fill != 0;
    if (backing_size != 0 && !xair_sym_parallel_memory_reserve(state->context, sizeof(*object.backing_ref)))
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    object.backing_ref = backing_create(backing, backing_size, 0);
    if (backing_size != 0 && object.backing_ref == NULL) {
        xair_sym_parallel_memory_release(state->context, sizeof(*object.backing_ref)); return XAIR_SYM_ERR_OOM;
    }
    object.page_count = page_count; object.version = 1;
    if (!xair_sym_parallel_memory_reserve(state->context, page_count * sizeof(*object.pages))) {
        backing_release(object.backing_ref);
        xair_sym_parallel_memory_release(state->context,
            backing_size != 0 ? sizeof(*object.backing_ref) : 0u);
        return XAIR_SYM_ERR_RESOURCE_LIMIT;
    }
    object.pages = (xair_sym_page **)calloc(page_count != 0 ? page_count : 1, sizeof(*object.pages));
    if (object.pages == NULL) {
        backing_release(object.backing_ref);
        xair_sym_parallel_memory_release(state->context, page_count * sizeof(*object.pages) +
            (backing_size != 0 ? sizeof(*object.backing_ref) : 0u));
        return XAIR_SYM_ERR_OOM;
    }
    state->context->object_bytes += page_count * sizeof(*object.pages);
    memmove(&state->memory->objects[index + 1], &state->memory->objects[index],
        (state->memory->count - index) * sizeof(*state->memory->objects));
    state->memory->objects[index] = object;
    state->memory->count++;
    state->memory->version++;
    state->context->stats.memory_objects++;
    *out_object = (xair_sym_object_id)index;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_object_add(xair_sym_state *state, uint64_t base, size_t size,
    uint32_t permissions, xair_sym_object_id *out_object) {
    return xair_sym_memory_map_lazy(state, base, size, permissions, NULL, 0, 0, out_object);
}

xair_sym_status xair_sym_object_remove(xair_sym_state *state, xair_sym_object_id id) {
    xair_sym_status status;
    if (state == NULL || id >= state->memory->count) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_memory_make_unique(state);
    if (status != XAIR_SYM_OK) return status;
    object_release(&state->memory->objects[id]);
    memmove(&state->memory->objects[id], &state->memory->objects[id + 1],
        (state->memory->count - id - 1) * sizeof(*state->memory->objects));
    state->memory->count--;
    state->memory->version++;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_object_remove_containing(xair_sym_state *state, uint64_t address) {
    xair_sym_object *object;
    xair_sym_object_id id;
    if (state == NULL) return XAIR_SYM_ERR_BAD_ARG;
    object = find_object(state->memory, address);
    if (object == NULL || object->base != address) return XAIR_SYM_ERR_RANGE;
    id = (xair_sym_object_id)(object - state->memory->objects);
    return xair_sym_object_remove(state, id);
}

static xair_sym_status store_expr(xair_sym_state *state, uint64_t address,
    xair_sym_expr_id value, int initialize) {
    xair_sym_object *object;
    xair_sym_page *page;
    size_t offset;
    xair_sym_status status = xair_sym_memory_make_unique(state);
    if (status != XAIR_SYM_OK) return status;
    object = find_object(state->memory, address);
    if (object == NULL || (!initialize && (object->permissions & 2u) == 0)) return XAIR_SYM_ERR_RANGE;
    offset = (size_t)(address - object->base);
    status = object_make_page_unique(state, object, offset >> XAIR_SYM_PAGE_SHIFT, &page);
    if (status != XAIR_SYM_OK) return status;
    page->bytes[offset & (XAIR_SYM_PAGE_SIZE - 1u)] = value;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_store8(xair_sym_state *state, uint64_t address, xair_sym_expr_id value) {
    if (state == NULL || value >= state->context->expression_count || state->context->expressions[value]->bits != 8)
        return XAIR_SYM_ERR_BAD_ARG;
    return store_expr(state, address, value, 0);
}

xair_sym_status xair_sym_memory_initialize8(xair_sym_state *state, uint64_t address, xair_sym_expr_id value) {
    if (state == NULL || value >= state->context->expression_count || state->context->expressions[value]->bits != 8)
        return XAIR_SYM_ERR_BAD_ARG;
    return store_expr(state, address, value, 1);
}

static xair_sym_status load_expr(const xair_sym_state *state, uint64_t address,
    xair_sym_expr_id *out_value, int require_read) {
    xair_sym_object *object;
    size_t offset, page_offset;
    xair_sym_page *page;
    if (state == NULL || out_value == NULL) return XAIR_SYM_ERR_BAD_ARG;
    object = find_object(state->memory, address);
    if (object == NULL || (require_read && (object->permissions & 1u) == 0)) return XAIR_SYM_ERR_RANGE;
    offset = (size_t)(address - object->base);
    page = object->pages[offset >> XAIR_SYM_PAGE_SHIFT];
    page_offset = offset & (XAIR_SYM_PAGE_SIZE - 1u);
    if (page != NULL && page->bytes[page_offset] != XAIR_SYM_INVALID_ID) {
        *out_value = page->bytes[page_offset];
        return XAIR_SYM_OK;
    }
    if (state->memory_havoc_version != 0) {
        char name[96];
        (void)snprintf(name, sizeof(name), "memory_havoc_%llu_%016llx",
            (unsigned long long)state->memory_havoc_version,
            (unsigned long long)address);
        return xair_sym_symbol(state->context, 8, name, out_value);
    }
    if (offset < object->backing_size)
        return xair_sym_const(state->context, 8, object->backing[offset], out_value);
    if (object->zero_fill) return xair_sym_const(state->context, 8, 0, out_value);
    return XAIR_SYM_ERR_RANGE;
}

void xair_sym_memory_havoc(xair_sym_state *state) {
    if (state == NULL) return;
    if (state->memory_havoc_version != UINT64_MAX) state->memory_havoc_version++;
    state->memory->version++;
}

xair_sym_status xair_sym_memory_load8(const xair_sym_state *state, uint64_t address, xair_sym_expr_id *out_value) {
    return load_expr(state, address, out_value, 1);
}

static xair_sym_status store_taint(xair_sym_state *state, uint64_t address,
    xair_sym_taint_id taint, int initialize) {
    xair_sym_object *object;
    xair_sym_page *page;
    size_t offset;
    xair_sym_status status = xair_sym_memory_make_unique(state);
    if (status != XAIR_SYM_OK) return status;
    object = find_object(state->memory, address);
    if (object == NULL || (!initialize && (object->permissions & 2u) == 0)) return XAIR_SYM_ERR_RANGE;
    offset = (size_t)(address - object->base);
    status = object_make_page_unique(state, object, offset >> XAIR_SYM_PAGE_SHIFT, &page);
    if (status != XAIR_SYM_OK) return status;
    page->taints[offset & (XAIR_SYM_PAGE_SIZE - 1u)] = taint;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_store_taint8(xair_sym_state *state, uint64_t address, xair_sym_taint_id taint) {
    if (state == NULL || taint > state->context->taint_count) return XAIR_SYM_ERR_BAD_ARG;
    return store_taint(state, address, taint, 0);
}

xair_sym_status xair_sym_memory_store_bytes(xair_sym_state *state, uint64_t address,
    const xair_sym_expr_id *values, const xair_sym_taint_id *taints, size_t count) {
    xair_sym_memory *saved;
    size_t i;
    xair_sym_status status;
    if (state == NULL || values == NULL || count == 0) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_memory_validate_range(state, address, count, 2u);
    if (status != XAIR_SYM_OK) return status;
    for (i = 0; i < count; ++i) {
        if (values[i] >= state->context->expression_count ||
            state->context->expressions[values[i]]->bits != 8u ||
            (taints != NULL && taints[i] > state->context->taint_count)) return XAIR_SYM_ERR_BAD_ARG;
    }
    saved = state->memory; xair_sym_memory_retain(saved);
    for (i = 0; i < count; ++i) {
        status = xair_sym_memory_store8(state, address + i, values[i]);
        if (status == XAIR_SYM_OK) status = xair_sym_memory_store_taint8(
            state, address + i, taints != NULL ? taints[i] : XAIR_SYM_TAINT_NONE);
        if (status != XAIR_SYM_OK) {
            xair_sym_memory_release(state->memory); state->memory = saved; return status;
        }
    }
    xair_sym_memory_release(saved);
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_initialize_taint8(xair_sym_state *state, uint64_t address, xair_sym_taint_id taint) {
    if (state == NULL || taint > state->context->taint_count) return XAIR_SYM_ERR_BAD_ARG;
    return store_taint(state, address, taint, 1);
}

xair_sym_status xair_sym_memory_load_taint8(const xair_sym_state *state, uint64_t address,
    xair_sym_taint_id *out_taint) {
    xair_sym_object *object;
    size_t offset;
    xair_sym_page *page;
    if (state == NULL || out_taint == NULL) return XAIR_SYM_ERR_BAD_ARG;
    object = find_object(state->memory, address);
    if (object == NULL || (object->permissions & 1u) == 0) return XAIR_SYM_ERR_RANGE;
    offset = (size_t)(address - object->base);
    page = object->pages[offset >> XAIR_SYM_PAGE_SHIFT];
    *out_taint = page == NULL ? XAIR_SYM_TAINT_NONE : page->taints[offset & (XAIR_SYM_PAGE_SIZE - 1u)];
    return XAIR_SYM_OK;
}

static xair_sym_status address_condition(xair_sym_state *state, xair_sym_expr_id address,
    uint64_t concrete, xair_sym_expr_id *out_condition) {
    xair_sym_expr_id constant;
    xair_sym_status status = xair_sym_const(state->context,
        state->context->expressions[address]->bits, concrete, &constant);
    if (status != XAIR_SYM_OK) return status;
    return xair_sym_binary(state->context, XAIR_OP_EQ, 1, address, constant, out_condition);
}

xair_sym_status xair_sym_memory_load_symbolic8(xair_sym_state *state, xair_sym_expr_id address,
    xair_sym_expr_id *out_value, xair_sym_taint_id *out_taint) {
    xair_sym_expr_id result = XAIR_SYM_INVALID_ID, valid = XAIR_SYM_INVALID_ID;
    xair_sym_taint_id result_taint = XAIR_SYM_TAINT_NONE;
    size_t object_i, candidates = 0;
    if (state == NULL || out_value == NULL || out_taint == NULL || address >= state->context->expression_count)
        return XAIR_SYM_ERR_BAD_ARG;
    *out_value = XAIR_SYM_INVALID_ID;
    *out_taint = XAIR_SYM_TAINT_NONE;
    for (object_i = 0; object_i < state->memory->count; ++object_i) {
        xair_sym_object *object = &state->memory->objects[object_i];
        size_t offset;
        if ((object->permissions & 1u) == 0) continue;
        if (object->size > XAIR_SYM_SYMBOLIC_ADDRESS_LIMIT - candidates) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        candidates += object->size;
        for (offset = 0; offset < object->size; ++offset) {
            xair_sym_expr_id condition, value, selected = XAIR_SYM_INVALID_ID, combined = XAIR_SYM_INVALID_ID;
            xair_sym_status status = load_expr(state, object->base + offset, &value, 0);
            if (status != XAIR_SYM_OK) continue;
            status = address_condition(state, address, object->base + offset, &condition);
            if (status != XAIR_SYM_OK) return status;
            {
                xair_sym_taint_id byte_taint = XAIR_SYM_TAINT_NONE;
                xair_sym_taint_id guarded = XAIR_SYM_TAINT_NONE;
                xair_sym_page *taint_page = object->pages[offset >> XAIR_SYM_PAGE_SHIFT];
                if (taint_page != NULL)
                    byte_taint = taint_page->taints[offset & (XAIR_SYM_PAGE_SIZE - 1u)];
                if (byte_taint != XAIR_SYM_TAINT_NONE) {
                    status = xair_sym_taint_transform(state->context, byte_taint,
                        "symbolic_load_guard", condition, 0, &guarded);
                    if (status == XAIR_SYM_OK) status = xair_sym_taint_union(
                        state->context, result_taint, guarded, &result_taint);
                    if (status != XAIR_SYM_OK) return status;
                }
            }
            if (result == XAIR_SYM_INVALID_ID) { result = value; valid = condition; }
            else {
                status = xair_sym_select(state->context, condition, value, result, &selected);
                if (status == XAIR_SYM_OK) status = xair_sym_binary(state->context, XAIR_OP_OR, 1, valid, condition, &combined);
                if (status != XAIR_SYM_OK) return status;
                result = selected; valid = combined;
            }
        }
    }
    if (result == XAIR_SYM_INVALID_ID) return XAIR_SYM_ERR_RANGE;
    {
        xair_sym_status status = xair_sym_state_assume(state, valid);
        if (status != XAIR_SYM_OK) return status;
    }
    *out_value = result;
    *out_taint = result_taint;
    return XAIR_SYM_OK;
}

xair_sym_status xair_sym_memory_store_symbolic8(xair_sym_state *state, xair_sym_expr_id address,
    xair_sym_expr_id value, xair_sym_taint_id taint) {
    xair_sym_expr_id valid = XAIR_SYM_INVALID_ID;
    size_t object_i, candidates = 0;
    xair_sym_status status;
    if (state == NULL || address >= state->context->expression_count || value >= state->context->expression_count ||
        state->context->expressions[value]->bits != 8 || taint > state->context->taint_count) return XAIR_SYM_ERR_BAD_ARG;
    status = xair_sym_memory_make_unique(state);
    if (status != XAIR_SYM_OK) return status;
    for (object_i = 0; object_i < state->memory->count; ++object_i) {
        xair_sym_object *object = &state->memory->objects[object_i];
        size_t offset;
        if ((object->permissions & 2u) == 0) continue;
        if (object->size > XAIR_SYM_SYMBOLIC_ADDRESS_LIMIT - candidates) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        candidates += object->size;
        for (offset = 0; offset < object->size; ++offset) {
            xair_sym_expr_id condition, old, selected = XAIR_SYM_INVALID_ID, combined = XAIR_SYM_INVALID_ID;
            status = load_expr(state, object->base + offset, &old, 0);
            if (status != XAIR_SYM_OK) continue;
            status = address_condition(state, address, object->base + offset, &condition);
            if (status == XAIR_SYM_OK) status = xair_sym_select(state->context, condition, value, old, &selected);
            if (status == XAIR_SYM_OK) status = store_expr(state, object->base + offset, selected, 1);
            if (status == XAIR_SYM_OK) {
                xair_sym_taint_id old_taint = XAIR_SYM_TAINT_NONE, guarded = XAIR_SYM_TAINT_NONE;
                xair_sym_taint_id preserved = XAIR_SYM_TAINT_NONE, combined_taint = XAIR_SYM_TAINT_NONE;
                xair_sym_page *taint_page = object->pages[offset >> XAIR_SYM_PAGE_SHIFT];
                if (taint_page != NULL)
                    old_taint = taint_page->taints[offset & (XAIR_SYM_PAGE_SIZE - 1u)];
                if (old_taint != XAIR_SYM_TAINT_NONE) {
                    xair_sym_expr_id zero, not_condition = XAIR_SYM_INVALID_ID;
                    status = xair_sym_const(state->context, 1, 0, &zero);
                    if (status == XAIR_SYM_OK) status = xair_sym_binary(
                        state->context, XAIR_OP_EQ, 1, condition, zero, &not_condition);
                    if (status == XAIR_SYM_OK) status = xair_sym_taint_transform(state->context,
                        old_taint, "symbolic_store_preserve_guard", not_condition, 0, &preserved);
                }
                if (status == XAIR_SYM_OK && taint != XAIR_SYM_TAINT_NONE)
                    status = xair_sym_taint_transform(state->context, taint,
                        "symbolic_store_guard", condition, 0, &guarded);
                if (status == XAIR_SYM_OK) status = xair_sym_taint_union(
                    state->context, preserved, guarded, &combined_taint);
                if (status == XAIR_SYM_OK) status = store_taint(
                    state, object->base + offset, combined_taint, 1);
            }
            if (status != XAIR_SYM_OK) return status;
            if (valid == XAIR_SYM_INVALID_ID) valid = condition;
            else {
                status = xair_sym_binary(state->context, XAIR_OP_OR, 1, valid, condition, &combined);
                if (status != XAIR_SYM_OK) return status;
                valid = combined;
            }
        }
    }
    if (valid == XAIR_SYM_INVALID_ID) return XAIR_SYM_ERR_RANGE;
    return xair_sym_state_assume(state, valid);
}

xair_sym_status xair_sym_memory_union_taint(xair_sym_state *state, uint32_t permission,
    xair_sym_taint_id taint, int update, xair_sym_taint_id *out_taint) {
    xair_sym_taint_id result = XAIR_SYM_TAINT_NONE;
    size_t object_i, candidates = 0;
    if (state == NULL || out_taint == NULL || taint > state->context->taint_count) return XAIR_SYM_ERR_BAD_ARG;
    for (object_i = 0; object_i < state->memory->count; ++object_i) {
        xair_sym_object *object = &state->memory->objects[object_i];
        size_t page_i, byte_i;
        if ((object->permissions & permission) == 0) continue;
        if (object->size > XAIR_SYM_SYMBOLIC_ADDRESS_LIMIT - candidates) return XAIR_SYM_ERR_RESOURCE_LIMIT;
        candidates += object->size;
        for (page_i = 0; page_i < object->page_count; ++page_i) {
            xair_sym_page *page = object->pages[page_i];
            if (page == NULL) continue;
            for (byte_i = 0; byte_i < XAIR_SYM_PAGE_SIZE &&
                (page_i << XAIR_SYM_PAGE_SHIFT) + byte_i < object->size; ++byte_i) {
                xair_sym_status status = xair_sym_taint_union(state->context, result, page->taints[byte_i], &result);
                if (status != XAIR_SYM_OK) return status;
            }
        }
    }
    (void)update; /* Symbolic stores never spray taint over unrelated objects. */
    if (update) result = taint;
    *out_taint = result;
    return XAIR_SYM_OK;
}

uint64_t xair_sym_memory_fingerprint(const xair_sym_memory *memory) {
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t object_i, page_i, byte_i;
    if (memory == NULL) return 0;
    for (object_i = 0; object_i < memory->count; ++object_i) {
        const xair_sym_object *object = &memory->objects[object_i];
        hash = (hash ^ object->base) * UINT64_C(1099511628211);
        hash = (hash ^ object->size) * UINT64_C(1099511628211);
        hash = (hash ^ object->permissions) * UINT64_C(1099511628211);
        hash = (hash ^ object->backing_size) * UINT64_C(1099511628211);
        hash = (hash ^ object->zero_fill) * UINT64_C(1099511628211);
        hash = (hash ^ (object->backing_ref != NULL ? object->backing_ref->hash : 0u)) * UINT64_C(1099511628211);
        for (page_i = 0; page_i < object->page_count; ++page_i) {
            const xair_sym_page *page = object->pages[page_i];
            if (page == NULL) continue;
            hash = (hash ^ page_i) * UINT64_C(1099511628211);
            for (byte_i = 0; byte_i < XAIR_SYM_PAGE_SIZE; ++byte_i) {
                if (page->bytes[byte_i] == XAIR_SYM_INVALID_ID && page->taints[byte_i] == XAIR_SYM_TAINT_NONE) continue;
                hash = (hash ^ byte_i) * UINT64_C(1099511628211);
                hash = (hash ^ page->bytes[byte_i]) * UINT64_C(1099511628211);
                hash = (hash ^ page->taints[byte_i]) * UINT64_C(1099511628211);
            }
        }
    }
    return hash;
}
