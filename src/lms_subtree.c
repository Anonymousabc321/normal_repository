#include "lms_subtree.h"
#include "lms_internal.h"

#include <string.h>

static uint64_t subtree_nodes_bytes(uint32_t sub_h, uint32_t n)
{
    uint64_t node_slots = ((uint64_t)2u << sub_h);
    return node_slots * n;
}

uint64_t lms_tree_updates_generated(uint32_t height, uint32_t subtree)
{
    uint32_t num_sublevels;

    if (subtree == 0u) {
        return 0u;
    }
    /* Special case: if the tree consists of 1 subtree, send an update each signature. */
    if (height <= subtree) {
        return (uint64_t)1u << height;
    }
    num_sublevels = (height + subtree - 1u) / subtree;
    /* An update for every node covered by the next-to-top subtree. */
    return (uint64_t)1u << ((num_sublevels - 1u) * subtree);
}

uint64_t lms_tree_updates_required(uint32_t height, uint32_t subtree)
{
    uint32_t num_sublevels;

    if (subtree == 0u) {
        return 0u;
    }
    num_sublevels = (height + subtree - 1u) / subtree;
    /* num_sublevels-1 for BUILDING subtrees + 1 for NEXT + 1 for parent. */
    return (uint64_t)num_sublevels + 1u;
}

uint64_t lms_tree_estimate_memory(uint32_t height,
                                  uint32_t subtree_size,
                                  uint32_t n,
                                  uint32_t *sublevels_out)
{
    uint32_t sublevels;
    uint32_t top_subtree_size;
    uint64_t memory_used = 0u;
    uint32_t s;

    if (subtree_size == 0u || n == 0u) {
        if (sublevels_out) {
            *sublevels_out = 0u;
        }
        return 0u;
    }

    sublevels = (height + subtree_size - 1u) / subtree_size;
    if (sublevels == 0u) {
        sublevels = 1u;
    }
    top_subtree_size = height - (sublevels - 1u) * subtree_size;

    for (s = 0u; s < sublevels; s++) {
        uint32_t sub_h = (s + 1u < sublevels) ? subtree_size : top_subtree_size;
        uint64_t nodes_bytes = subtree_nodes_bytes(sub_h, n);
        uint64_t stack_bytes = (uint64_t)sub_h * n;
        memory_used += nodes_bytes + stack_bytes;      /* ACTIVE */
        if (s + 1u < sublevels) {
            memory_used += nodes_bytes + stack_bytes;
        }
    }

    if (sublevels_out) {
        *sublevels_out = sublevels;
    }
    return memory_used;
}

int lms_tree_configure(uint32_t lms_type,
                       uint64_t memory_target,
                       lms_tree_config_t *config)
{
    lms_param_t param;
    uint32_t height;
    uint32_t n;
    uint32_t j;

    int found_overbudget = 0;
    int found_within = 0;
    uint64_t best_mem = 0u;
    uint32_t best_levels = 0u;
    uint32_t best_j = 0u;

    if (config == NULL) {
        return LMS_ERR_INVALID;
    }
    if (lms_get_lms_param(lms_type, &param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    height = param.height;
    n = param.n;
    if (height == 0u || n == 0u || height > LMS_MAX_HEIGHT) {
        return LMS_ERR_INVALID;
    }

    for (j = LMS_SUBTREE_MIN_J; j <= height; j++) {
        uint32_t sub_levels = 0u;
        uint64_t mem = lms_tree_estimate_memory(height, j, n, &sub_levels);

        if (mem > memory_target) {

            if ((found_overbudget || found_within) && mem > best_mem) {
                continue;
            }
            found_overbudget = 1;
        } else {

            if (found_within) {
                if (sub_levels > best_levels) {
                    continue;
                }
                if (sub_levels == best_levels && mem > best_mem) {
                    continue;
                }
            }
            found_within = 1;
        }

        best_j = j;
        best_mem = mem;
        best_levels = sub_levels;
    }

    if (!found_overbudget && !found_within) {

        return LMS_ERR_INVALID;
    }

    memset(config, 0, sizeof(*config));
    config->lms_type = lms_type;
    config->height = height;
    config->n = n;
    config->subtree_size = best_j;
    config->sublevels = best_levels;
    config->est_memory = best_mem;
    config->fit = found_within ? LMS_TREE_FIT_WITHIN_BUDGET : LMS_TREE_FIT_OVERBUDGET;
    return LMS_OK;
}

static void subtree_free_buffers(lms_subtree_t *sub,
                                 lms_tree_free_fn free_fn,
                                 void *alloc_ctx)
{
    if (sub == NULL || free_fn == NULL) {
        return;
    }
    if (sub->nodes != NULL) {
        free_fn(alloc_ctx, sub->nodes);
        sub->nodes = NULL;
    }
    if (sub->stack != NULL) {
        free_fn(alloc_ctx, sub->stack);
        sub->stack = NULL;
    }
}

static int subtree_init_buffers(lms_subtree_t *sub,
                                uint32_t sub_h,
                                uint32_t level,
                                uint32_t levels_below,
                                uint32_t tree_height,
                                uint64_t left_leaf,
                                uint32_t n,
                                int want_stack,
                                lms_tree_alloc_fn alloc,
                                lms_tree_free_fn free_fn,
                                void *alloc_ctx)
{
    uint64_t nodes_bytes;

    memset(sub, 0, sizeof(*sub));
    sub->height = sub_h;
    sub->level = level;
    sub->levels_below = levels_below;
    sub->tree_height = tree_height;
    sub->left_leaf = left_leaf;
    sub->current_index = 0u;

    nodes_bytes = subtree_nodes_bytes(sub_h, n);
    sub->nodes = (uint8_t *)alloc(alloc_ctx, (size_t)nodes_bytes);
    if (sub->nodes == NULL) {
        return LMS_ERR_INVALID;
    }
    memset(sub->nodes, 0, (size_t)nodes_bytes);

    if (want_stack && sub_h > 0u) {
        sub->stack = (uint8_t *)alloc(alloc_ctx, (size_t)sub_h * n);
        if (sub->stack == NULL) {
            subtree_free_buffers(sub, free_fn, alloc_ctx);
            return LMS_ERR_INVALID;
        }
        memset(sub->stack, 0, (size_t)sub_h * n);
    } else {
        sub->stack = NULL;
    }
    return LMS_OK;
}

int lms_tree_ctx_init(lms_tree_ctx_t *ctx,
                      const lms_tree_config_t *config,
                      const uint8_t I[LMS_I_LEN],
                      lms_subtree_ots_pub_fn ots_pub,
                      void *ots_pub_ctx,
                      lms_tree_alloc_fn alloc,
                      lms_tree_free_fn free_fn,
                      void *alloc_ctx)
{
    uint32_t sublevels;
    uint32_t j;
    uint32_t top;
    uint32_t n;
    uint32_t s;
    lms_param_t param;

    if (ctx == NULL || config == NULL || I == NULL || alloc == NULL || free_fn == NULL) {
        return LMS_ERR_INVALID;
    }
    sublevels = config->sublevels;
    j = config->subtree_size;
    n = config->n;
    if (sublevels == 0u || j < LMS_SUBTREE_MIN_J || n == 0u ||
        config->height == 0u || config->height > LMS_MAX_HEIGHT) {
        return LMS_ERR_INVALID;
    }
    top = config->height - (sublevels - 1u) * j;
    if (lms_get_lms_param(config->lms_type, &param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->lms_type = config->lms_type;
    ctx->height = config->height;
    ctx->n = n;
    ctx->subtree_size = j;
    ctx->sublevels = sublevels;
    ctx->top_subtree_size = top;
    ctx->hash_alg = (uint32_t)param.hash_alg;
    memcpy(ctx->I, I, LMS_I_LEN);
    ctx->ots_pub = ots_pub;
    ctx->ots_pub_ctx = ots_pub_ctx;
    ctx->leaf_fn = NULL;
    ctx->leaf_fn_ctx = NULL;
    ctx->alloc = alloc;
    ctx->free = free_fn;
    ctx->alloc_ctx = alloc_ctx;

    ctx->levels = (lms_sublevel_t *)alloc(alloc_ctx,
                                          (size_t)sublevels * sizeof(lms_sublevel_t));
    if (ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    memset(ctx->levels, 0, (size_t)sublevels * sizeof(lms_sublevel_t));

    for (s = 0u; s < sublevels; s++) {
        uint32_t sub_h = (s + 1u < sublevels) ? j : top;
        uint32_t root_level = s * j + sub_h;
        uint32_t levels_below = s * j;

        uint64_t left_leaf = 0u;
        int has_upcoming = (s + 1u < sublevels) ? 1 : 0;
        lms_sublevel_t *sl = &ctx->levels[s];

        if (subtree_init_buffers(&sl->active, sub_h, root_level, levels_below,
                                 config->height, left_leaf, n, 1 /* stack */,
                                 alloc, free_fn, alloc_ctx) != LMS_OK) {
            lms_tree_ctx_free(ctx);
            return LMS_ERR_INVALID;
        }
        sl->has_upcoming = has_upcoming;
        if (has_upcoming) {

            if (subtree_init_buffers(&sl->upcoming, sub_h, root_level, levels_below,
                                     config->height, left_leaf + ((uint64_t)1u << sub_h),
                                     n, 1, alloc, free_fn, alloc_ctx) != LMS_OK) {
                lms_tree_ctx_free(ctx);
                return LMS_ERR_INVALID;
            }
        }
    }
    return LMS_OK;
}

void lms_tree_ctx_free(lms_tree_ctx_t *ctx)
{
    uint32_t s;

    if (ctx == NULL) {
        return;
    }
    if (ctx->levels != NULL && ctx->free != NULL) {
        for (s = 0u; s < ctx->sublevels; s++) {
            lms_sublevel_t *sl = &ctx->levels[s];
            subtree_free_buffers(&sl->active, ctx->free, ctx->alloc_ctx);
            if (sl->has_upcoming) {
                subtree_free_buffers(&sl->upcoming, ctx->free, ctx->alloc_ctx);
            }
        }
        ctx->free(ctx->alloc_ctx, ctx->levels);
        ctx->levels = NULL;
    }
    ctx->sublevels = 0u;
}

uint64_t lms_tree_ctx_allocated_bytes(const lms_tree_ctx_t *ctx)
{
    uint64_t total = 0u;
    uint32_t s;

    if (ctx == NULL || ctx->levels == NULL) {
        return 0u;
    }
    total += (uint64_t)ctx->sublevels * sizeof(lms_sublevel_t);
    for (s = 0u; s < ctx->sublevels; s++) {
        const lms_sublevel_t *sl = &ctx->levels[s];
        uint32_t sub_h = sl->active.height;
        uint64_t nodes_bytes = subtree_nodes_bytes(sub_h, ctx->n);
        uint64_t stack_bytes = (sl->active.stack != NULL) ? (uint64_t)sub_h * ctx->n : 0u;
        total += nodes_bytes + stack_bytes;
        if (sl->has_upcoming) {
            total += nodes_bytes +
                     ((sl->upcoming.stack != NULL) ? (uint64_t)sub_h * ctx->n : 0u);
        }
    }
    return total;
}

void lms_subtree_set_leaf_fn(lms_tree_ctx_t *ctx, lms_subtree_leaf_fn fn, void *fn_ctx)
{
    if (ctx != NULL) {
        ctx->leaf_fn = fn;
        ctx->leaf_fn_ctx = fn_ctx;
    }
}

static int default_ots_pub(void *context,
                           const lms_private_key_t *priv,
                           uint32_t q,
                           uint8_t ots_pub[LMS_N])
{
    (void)context;
    return lmots_public_from_private(priv, q, ots_pub);
}

static uint32_t subtree_local_to_global(uint32_t h,
                                        uint32_t sub_h,
                                        uint32_t root_level,
                                        uint64_t left_leaf,
                                        uint32_t local)
{
    uint64_t k0 = left_leaf >> sub_h;
    uint32_t d = 0u;
    uint32_t k;
    uint32_t r;

    while ((1u << (d + 1u)) <= local) {
        d++;
    }
    k = local - (1u << d);
    r = root_level - d;
    return (uint32_t)((1u << (h - r)) + ((uint32_t)(k0 << d) + k));
}

static int subtree_build_internal(lms_tree_ctx_t *ctx, lms_subtree_t *sub)
{
    uint32_t local;

    for (local = (1u << sub->height) - 1u; local >= 1u; local--) {
        uint32_t node_num = subtree_local_to_global(ctx->height, sub->height,
                                                    sub->level, sub->left_leaf, local);
        if (lms_internal_node(ctx->I, (lms_hash_alg_t)ctx->hash_alg, node_num,
                              sub->nodes + (size_t)(local * 2u) * ctx->n,
                              sub->nodes + (size_t)(local * 2u + 1u) * ctx->n,
                              sub->nodes + (size_t)local * ctx->n) != LMS_OK) {
            return LMS_ERR_INVALID;
        }

    }
    return LMS_OK;
}

int lms_tree_build_active(lms_tree_ctx_t *ctx, const lms_private_key_t *priv)
{
    lms_subtree_ots_pub_fn ots_pub;
    uint8_t ots_pub_buf[LMS_N];
    uint32_t s;

    if (ctx == NULL || priv == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    if (priv->lms_type != ctx->lms_type) {
        return LMS_ERR_INVALID;
    }
    ots_pub = (ctx->ots_pub != NULL) ? ctx->ots_pub : default_ots_pub;

    if (ctx->sublevels != 1u) {
        return LMS_ERR_INVALID;
    }

    for (s = 0u; s < ctx->sublevels; s++) {
        lms_sublevel_t *sl = &ctx->levels[s];
        lms_subtree_t *active = &sl->active;
        uint32_t sub_h = active->height;
        uint32_t leaf_count = 1u << sub_h;
        uint32_t leaf_base_local = 1u << sub_h;
        uint32_t i;

        for (i = 0u; i < leaf_count; i++) {
            uint32_t local = leaf_base_local + i;
            uint32_t node_num = subtree_local_to_global(ctx->height, sub_h,
                                                        active->level,
                                                        active->left_leaf, local);
            uint32_t q = (uint32_t)(active->left_leaf + i);
            uint8_t prefix[LMS_I_LEN + 4 + 2];

            if (ots_pub(ctx->ots_pub_ctx, priv, q, ots_pub_buf) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            memcpy(prefix, ctx->I, LMS_I_LEN);
            lms_store_u32(prefix + LMS_I_LEN, node_num);
            lms_store_u16(prefix + LMS_I_LEN + 4, D_LEAF);
            if (lms_hash_parts(prefix, sizeof(prefix), ots_pub_buf, LMS_N,
                               NULL, 0, NULL, 0, (lms_hash_alg_t)ctx->hash_alg,
                               active->nodes + (size_t)local * ctx->n) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
        }

        if (subtree_build_internal(ctx, active) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }
    return LMS_OK;
}

int lms_tree_root(const lms_tree_ctx_t *ctx, uint8_t root[LMS_N])
{
    const lms_subtree_t *top;

    if (ctx == NULL || root == NULL || ctx->levels == NULL || ctx->sublevels == 0u) {
        return LMS_ERR_INVALID;
    }
    top = &ctx->levels[ctx->sublevels - 1u].active;
    memcpy(root, top->nodes + (size_t)1u * ctx->n, ctx->n);
    return LMS_OK;
}

int lms_tree_auth_path(const lms_tree_ctx_t *ctx, uint32_t q, uint8_t *path)
{
    uint32_t path_idx = 0u;
    uint64_t leaf_pos = q;
    uint32_t s;

    if (ctx == NULL || path == NULL || ctx->levels == NULL || ctx->sublevels == 0u) {
        return LMS_ERR_INVALID;
    }
    if ((uint64_t)q >= ((uint64_t)1u << ctx->height)) {
        return LMS_ERR_INVALID;
    }

    for (s = 0u; s < ctx->sublevels; s++) {
        const lms_subtree_t *active = &ctx->levels[s].active;
        uint32_t sub_h = active->height;
        uint32_t local = (1u << sub_h) + (uint32_t)(leaf_pos & ((1u << sub_h) - 1u));
        uint32_t d;

        for (d = 0u; d < sub_h; d++) {
            uint32_t sibling = local ^ 1u;
            memcpy(path + (size_t)path_idx * ctx->n,
                   active->nodes + (size_t)sibling * ctx->n, ctx->n);
            path_idx++;
            local /= 2u;
        }

        leaf_pos >>= sub_h;
    }
    return LMS_OK;
}

int lms_tree_add_next_node(lms_subtree_t *sub,
                           const uint8_t leaf_value[LMS_N],
                           const uint8_t I[LMS_I_LEN],
                           uint32_t hash_alg,
                           uint32_t n)
{
    uint32_t sub_h;
    uint64_t ci;
    uint32_t local;
    uint8_t cur[LMS_N];
    uint64_t leaf_seq;
    uint32_t i;

    if (sub == NULL || leaf_value == NULL || I == NULL || n == 0u || n > LMS_N) {
        return LMS_ERR_INVALID;
    }
    sub_h = sub->height;
    if (sub_h == 0u || sub_h > LMS_MAX_HEIGHT) {
        return LMS_ERR_INVALID;
    }
    ci = sub->current_index;
    if (ci >= ((uint64_t)1u << sub_h)) {
        return LMS_ERR_INVALID;
    }
    if (sub->nodes == NULL || sub->stack == NULL) {
        return LMS_ERR_INVALID;
    }

    local = (uint32_t)((1u << sub_h) + ci);
    memcpy(sub->nodes + (size_t)local * n, leaf_value, n);
    memcpy(cur, leaf_value, n);

    leaf_seq = ci;
    i = 0u;
    for (;;) {
        uint32_t cur_local = (uint32_t)((1u << (sub_h - i)) + (leaf_seq >> 0u));
        uint32_t node_num;

        if (cur_local == 1u) {

            break;
        }
        if ((leaf_seq & 1u) == 0u) {

            memcpy(sub->stack + (size_t)i * n, cur, n);
            break;
        }

        leaf_seq >>= 1u;
        {
            uint32_t parent_local = cur_local >> 1u;

            node_num = subtree_local_to_global(sub->tree_height, sub_h,
                                               sub->level, sub->left_leaf,
                                               parent_local);
            if (lms_internal_node(I, (lms_hash_alg_t)hash_alg, node_num,
                                  sub->stack + (size_t)i * n, cur,
                                  sub->nodes + (size_t)parent_local * n) != LMS_OK) {
                return LMS_ERR_INVALID;
            }
            memcpy(cur, sub->nodes + (size_t)parent_local * n, n);
        }
        i++;
    }

    sub->current_index = ci + 1u;

    return (sub->current_index >= ((uint64_t)1u << sub_h)) ? 1 : 0;
}

static int subtree_compute_leaf(lms_tree_ctx_t *ctx,
                                const lms_private_key_t *priv,
                                lms_subtree_ots_pub_fn ots_pub,
                                uint32_t q,
                                uint8_t leaf[LMS_N])
{
    uint8_t ots_pub_buf[LMS_N];
    uint8_t prefix[LMS_I_LEN + 4 + 2];
    uint32_t node_num = (uint32_t)((1u << ctx->height) + q);

    if (ctx->leaf_fn != NULL) {
        (void)ots_pub;
        return ctx->leaf_fn(ctx->leaf_fn_ctx, priv, q, leaf);
    }
    if (ots_pub(ctx->ots_pub_ctx, priv, q, ots_pub_buf) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    memcpy(prefix, ctx->I, LMS_I_LEN);
    lms_store_u32(prefix + LMS_I_LEN, node_num);
    lms_store_u16(prefix + LMS_I_LEN + 4, D_LEAF);
    return lms_hash_parts(prefix, sizeof(prefix), ots_pub_buf, LMS_N,
                          NULL, 0, NULL, 0, (lms_hash_alg_t)ctx->hash_alg, leaf);
}

static int subtree_push_leaf(lms_tree_ctx_t *ctx,
                             const lms_private_key_t *priv,
                             lms_subtree_ots_pub_fn ots_pub,
                             lms_subtree_t *sub,
                             uint32_t q,
                             uint8_t leaf[LMS_N])
{
    if (subtree_compute_leaf(ctx, priv, ots_pub, q, leaf) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    return lms_tree_add_next_node(sub, leaf, ctx->I, ctx->hash_alg, ctx->n);
}

static void subtree_reset_to(lms_subtree_t *sub, uint64_t left_leaf)
{
    sub->left_leaf = left_leaf;
    sub->current_index = 0u;
}

static int subtree_build_bottom(lms_tree_ctx_t *ctx,
                                const lms_private_key_t *priv,
                                lms_subtree_ots_pub_fn ots_pub,
                                lms_subtree_t *sub,
                                uint64_t left_leaf)
{
    uint32_t count = 1u << sub->height;
    uint32_t i;
    uint8_t leaf[LMS_N];
    int done = 0;

    subtree_reset_to(sub, left_leaf);
    for (i = 0u; i < count; i++) {
        done = subtree_push_leaf(ctx, priv, ots_pub, sub,
                                 (uint32_t)(left_leaf + i), leaf);
        if (done < 0) {
            return LMS_ERR_INVALID;
        }
    }
    return (done == 1) ? LMS_OK : LMS_ERR_INVALID;
}

static int subtree_build_upper(lms_tree_ctx_t *ctx,
                               lms_subtree_t *sub,
                               uint64_t left_leaf,
                               const uint8_t *lower_roots)
{
    uint32_t count = 1u << sub->height;
    uint32_t i;
    int done = 0;

    subtree_reset_to(sub, left_leaf);
    for (i = 0u; i < count; i++) {
        done = lms_tree_add_next_node(sub, lower_roots + (size_t)i * ctx->n,
                                      ctx->I, ctx->hash_alg, ctx->n);
        if (done < 0) {
            return LMS_ERR_INVALID;
        }
    }
    return (done == 1) ? LMS_OK : LMS_ERR_INVALID;
}

static int subtree_build_at(lms_tree_ctx_t *ctx,
                            const lms_private_key_t *priv,
                            lms_subtree_ots_pub_fn ots_pub,
                            uint32_t s,
                            uint64_t leaf_lo,
                            lms_subtree_t *scratch)
{
    uint32_t j = ctx->subtree_size;

    scratch->level = s * j + scratch->height;
    scratch->levels_below = s * j;
    scratch->tree_height = ctx->height;

    if (s == 0u) {
        return subtree_build_bottom(ctx, priv, ots_pub, scratch, leaf_lo);
    }
    {
        lms_subtree_t *lower_scratch = &ctx->levels[s - 1u].upcoming;
        uint32_t cnt = 1u << scratch->height;

        uint32_t lower_root_level = (s - 1u) * j + lower_scratch->height;
        uint64_t lower_span = (uint64_t)1u << lower_root_level;
        uint8_t *my_roots;
        uint32_t k;
        int rc;

        my_roots = (uint8_t *)ctx->alloc(ctx->alloc_ctx, (size_t)cnt * ctx->n);
        if (my_roots == NULL) {
            return LMS_ERR_INVALID;
        }
        rc = LMS_OK;
        for (k = 0u; k < cnt; k++) {
            if (subtree_build_at(ctx, priv, ots_pub, s - 1u,
                                 leaf_lo + (uint64_t)k * lower_span,
                                 lower_scratch) != LMS_OK) {
                rc = LMS_ERR_INVALID;
                break;
            }
            memcpy(my_roots + (size_t)k * ctx->n,
                   lower_scratch->nodes + (size_t)1u * ctx->n, ctx->n);
        }
        if (rc == LMS_OK) {

            rc = subtree_build_upper(ctx, scratch, leaf_lo >> (s * j), my_roots);
        }
        ctx->free(ctx->alloc_ctx, my_roots);
        return rc;
    }
}

int lms_tree_keygen_root(lms_tree_ctx_t *ctx,
                         const lms_private_key_t *priv,
                         uint8_t root[LMS_N])
{
    lms_subtree_ots_pub_fn ots_pub;
    uint64_t total_leaves;
    uint64_t q;
    uint8_t leaf[LMS_N];
    uint32_t s;

    if (ctx == NULL || priv == NULL || root == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    if (priv->lms_type != ctx->lms_type) {
        return LMS_ERR_INVALID;
    }
    ots_pub = (ctx->ots_pub != NULL) ? ctx->ots_pub : default_ots_pub;
    total_leaves = (uint64_t)1u << ctx->height;

    for (s = 0u; s < ctx->sublevels; s++) {
        subtree_reset_to(&ctx->levels[s].active, 0u);
        ctx->levels[s].upcoming.current_index = 0u;
    }

    for (q = 0u; q < total_leaves; q++) {
        lms_subtree_t *bot = &ctx->levels[0].active;
        int done = subtree_push_leaf(ctx, priv, ots_pub, bot, (uint32_t)q, leaf);
        if (done < 0) {
            return LMS_ERR_INVALID;
        }
        if (done == 1) {
            memcpy(leaf, bot->nodes + (size_t)1u * ctx->n, ctx->n);
            subtree_reset_to(bot, bot->left_leaf + ((uint64_t)1u << bot->height));
            for (s = 1u; s < ctx->sublevels; s++) {
                lms_subtree_t *up = &ctx->levels[s].active;
                int udone = lms_tree_add_next_node(up, leaf, ctx->I,
                                                   ctx->hash_alg, ctx->n);
                if (udone < 0) {
                    return LMS_ERR_INVALID;
                }
                if (udone != 1) {
                    break;
                }
                memcpy(leaf, up->nodes + (size_t)1u * ctx->n, ctx->n);
                subtree_reset_to(up, up->left_leaf + ((uint64_t)1u << up->height));
            }
        }
    }

    memcpy(root, ctx->levels[ctx->sublevels - 1u].active.nodes + (size_t)1u * ctx->n,
           ctx->n);
    return LMS_OK;
}

int lms_tree_sign_init(lms_tree_ctx_t *ctx, const lms_private_key_t *priv)
{
    lms_subtree_ots_pub_fn ots_pub;
    uint32_t s;

    if (ctx == NULL || priv == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    if (priv->lms_type != ctx->lms_type) {
        return LMS_ERR_INVALID;
    }
    ots_pub = (ctx->ots_pub != NULL) ? ctx->ots_pub : default_ots_pub;

    for (s = 0u; s < ctx->sublevels; s++) {
        if (subtree_build_at(ctx, priv, ots_pub, s, 0u,
                             &ctx->levels[s].active) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }
    return LMS_OK;
}

int lms_tree_sign_auth_path(const lms_tree_ctx_t *ctx, uint32_t q, uint8_t *path)
{
    if (ctx == NULL || path == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }

    return lms_tree_auth_path(ctx, q, path);
}

static uint64_t subtree_leaf_lo(const lms_subtree_t *sub)
{
    uint64_t k0 = sub->left_leaf >> sub->height;
    return k0 << sub->level;
}

static uint64_t subtree_leaf_span(const lms_subtree_t *sub)
{
    return (uint64_t)1u << sub->level;
}

int lms_tree_sign_advance(lms_tree_ctx_t *ctx,
                          const lms_private_key_t *priv,
                          uint32_t q)
{
    lms_subtree_ots_pub_fn ots_pub;
    uint32_t s;

    if (ctx == NULL || priv == NULL || ctx->levels == NULL) {
        return LMS_ERR_INVALID;
    }
    if (priv->lms_type != ctx->lms_type) {
        return LMS_ERR_INVALID;
    }
    if ((uint64_t)q >= ((uint64_t)1u << ctx->height)) {
        return LMS_ERR_INVALID;
    }
    ots_pub = (ctx->ots_pub != NULL) ? ctx->ots_pub : default_ots_pub;

    for (s = 0u; s + 1u < ctx->sublevels; s++) {
        lms_subtree_t *active = &ctx->levels[s].active;
        uint64_t lo = subtree_leaf_lo(active);
        uint64_t span = subtree_leaf_span(active);
        uint64_t new_lo;

        if ((uint64_t)q - lo < span) {
            continue;
        }

        new_lo = ((uint64_t)q / span) * span;
        if (subtree_build_at(ctx, priv, ots_pub, s, new_lo, active) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
    }
    return LMS_OK;
}

int lms_subtree_auth_path_backend(void *context,
                                  const lms_private_key_t *priv,
                                  uint32_t q,
                                  uint8_t *path)
{
    lms_tree_ctx_t *ctx = (lms_tree_ctx_t *)context;

    if (ctx == NULL || priv == NULL || path == NULL) {
        return LMS_ERR_INVALID;
    }

    if (lms_tree_sign_advance(ctx, priv, q) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    return lms_tree_sign_auth_path(ctx, q, path);
}
