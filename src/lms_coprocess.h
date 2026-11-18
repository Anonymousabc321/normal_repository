#ifndef LMS_COPROCESS_H
#define LMS_COPROCESS_H

#include "lms.h"

#include <stddef.h>
#include <stdint.h>

#define LMS_COPROCESS_MAX_HEIGHT 10u
#define LMS_COPROCESS_MAX_NODES ((1u << (LMS_COPROCESS_MAX_HEIGHT + 1u)) - 1u)

typedef int (*lms_coprocess_ots_pub_fn)(void *context,
                                        const lms_private_key_t *priv,
                                        uint32_t q,
                                        uint8_t ots_pub[LMS_N]);

typedef struct {
    uint32_t lms_type;
    uint32_t height;      /* h */
    uint32_t n;
    uint32_t leaf_count;  /* 2^h */
    uint8_t I[LMS_I_LEN];

    uint8_t nodes[LMS_COPROCESS_MAX_NODES + 1u][LMS_N];
} lms_coprocess_tree_t;

int lms_coprocess_tree_init(lms_coprocess_tree_t *tree,
                            uint32_t lms_type,
                            const uint8_t I[LMS_I_LEN]);

int lms_coprocess_build(lms_coprocess_tree_t *tree,
                        const lms_private_key_t *priv,
                        lms_coprocess_ots_pub_fn ots_pub,
                        void *ots_pub_context);

int lms_coprocess_root(const lms_coprocess_tree_t *tree, uint8_t root[LMS_N]);

int lms_coprocess_node(const lms_coprocess_tree_t *tree,
                       uint32_t node_num,
                       uint8_t out[LMS_N]);

int lms_coprocess_auth_path(const lms_coprocess_tree_t *tree,
                            uint32_t q,
                            uint8_t *path  );

int lms_coprocess_root_from_kv(const lms_coprocess_tree_t *tree,
                               uint32_t q,
                               const uint8_t kv[LMS_N],
                               const uint8_t *auth_path  ,
                               uint8_t root[LMS_N]);

int lms_coprocess_verify(const lms_coprocess_tree_t *tree,
                         uint32_t q,
                         const uint8_t kv[LMS_N],
                         const uint8_t *auth_path);

#endif /* LMS_COPROCESS_H */
