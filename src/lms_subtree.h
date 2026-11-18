#ifndef LMS_SUBTREE_H
#define LMS_SUBTREE_H

#include "lms.h"

#include <stddef.h>
#include <stdint.h>

#define LMS_SUBTREE_MIN_J 2u

typedef enum {
    LMS_TREE_FIT_NONE = 0,
    LMS_TREE_FIT_OVERBUDGET,
    LMS_TREE_FIT_WITHIN_BUDGET
} lms_tree_fit_t;

typedef struct {
    uint32_t lms_type;
    uint32_t height;
    uint32_t n;
    uint32_t subtree_size;
    uint32_t sublevels;     /* ceil(h / j) */
    uint64_t est_memory;
    lms_tree_fit_t fit;
} lms_tree_config_t;

typedef void *(*lms_tree_alloc_fn)(void *context, size_t size);
typedef void (*lms_tree_free_fn)(void *context, void *ptr);

typedef struct {
    uint32_t height;
    uint32_t level;
    uint32_t levels_below;
    uint32_t tree_height;
    uint64_t left_leaf;
    uint64_t current_index;
    uint8_t *nodes;
    uint8_t *stack;
} lms_subtree_t;

typedef struct {
    lms_subtree_t active;
    lms_subtree_t upcoming;
    int has_upcoming;
} lms_sublevel_t;

typedef int (*lms_subtree_ots_pub_fn)(void *context,
                                      const lms_private_key_t *priv,
                                      uint32_t q,
                                      uint8_t ots_pub[LMS_N]);

typedef int (*lms_subtree_leaf_fn)(void *context,
                                    const lms_private_key_t *priv,
                                    uint32_t q,
                                    uint8_t leaf[LMS_N]);

typedef struct {
    uint32_t lms_type;
    uint32_t height;        /* h */
    uint32_t n;
    uint32_t subtree_size;
    uint32_t sublevels;     /* ceil(h / j) */
    uint32_t top_subtree_size;
    uint32_t hash_alg;
    uint8_t I[LMS_I_LEN];
    lms_sublevel_t *levels;

    lms_subtree_ots_pub_fn ots_pub;
    void *ots_pub_ctx;
    lms_subtree_leaf_fn leaf_fn;
    void *leaf_fn_ctx;
    lms_tree_alloc_fn alloc;
    lms_tree_free_fn free;
    void *alloc_ctx;
} lms_tree_ctx_t;

int lms_tree_configure(uint32_t lms_type,
                       uint64_t memory_target,
                       lms_tree_config_t *config);

uint64_t lms_tree_estimate_memory(uint32_t height,
                                  uint32_t subtree_size,
                                  uint32_t n,
                                  uint32_t *sublevels_out);

uint64_t lms_tree_updates_generated(uint32_t height, uint32_t subtree);
uint64_t lms_tree_updates_required(uint32_t height, uint32_t subtree);

int lms_tree_ctx_init(lms_tree_ctx_t *ctx,
                      const lms_tree_config_t *config,
                      const uint8_t I[LMS_I_LEN],
                      lms_subtree_ots_pub_fn ots_pub,
                      void *ots_pub_ctx,
                      lms_tree_alloc_fn alloc,
                      lms_tree_free_fn free,
                      void *alloc_ctx);

void lms_tree_ctx_free(lms_tree_ctx_t *ctx);

void lms_subtree_set_leaf_fn(lms_tree_ctx_t *ctx, lms_subtree_leaf_fn fn, void *fn_ctx);

uint64_t lms_tree_ctx_allocated_bytes(const lms_tree_ctx_t *ctx);

int lms_tree_build_active(lms_tree_ctx_t *ctx, const lms_private_key_t *priv);

int lms_tree_root(const lms_tree_ctx_t *ctx, uint8_t root[LMS_N]);

int lms_tree_auth_path(const lms_tree_ctx_t *ctx, uint32_t q, uint8_t *path);

int lms_tree_add_next_node(lms_subtree_t *sub,
                           const uint8_t leaf_value[LMS_N],
                           const uint8_t I[LMS_I_LEN],
                           uint32_t hash_alg,
                           uint32_t n);

int lms_tree_keygen_root(lms_tree_ctx_t *ctx,
                         const lms_private_key_t *priv,
                         uint8_t root[LMS_N]);

int lms_tree_sign_init(lms_tree_ctx_t *ctx, const lms_private_key_t *priv);

int lms_tree_sign_auth_path(const lms_tree_ctx_t *ctx, uint32_t q, uint8_t *path);

int lms_tree_sign_advance(lms_tree_ctx_t *ctx,
                          const lms_private_key_t *priv,
                          uint32_t q);

int lms_subtree_auth_path_backend(void *context,
                                  const lms_private_key_t *priv,
                                  uint32_t q,
                                  uint8_t *path);

#endif /* LMS_SUBTREE_H */
