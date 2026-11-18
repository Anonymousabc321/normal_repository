#ifndef LMS_HASH_API_H
#define LMS_HASH_API_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    LMS_HASH_SHA256 = 1,
    LMS_HASH_SHAKE256 = 2,

    LMS_HASH_HARAKA = 4
} lms_hash_alg_t;

int lms_hash(lms_hash_alg_t alg,
             const uint8_t *input,
             size_t input_len,
             uint8_t *output,
             size_t output_len);

#endif
