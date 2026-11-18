#ifndef LMS_RND_H
#define LMS_RND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t lms_rnd32(void);

void lms_rnd(uint8_t *out, size_t len);

void lms_rnd_det_seed(const uint8_t *ctx, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LMS_RND_H */
