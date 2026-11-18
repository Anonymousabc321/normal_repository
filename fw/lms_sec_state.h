#ifndef LMS_SEC_STATE_H
#define LMS_SEC_STATE_H

#include <stdint.h>

#include "lms_mmio.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SEC_ST_ERROR_LOCKED   0u
#define SEC_ST_IDLE           1u
#define SEC_ST_RESERVED       2u
#define SEC_ST_KEYGEN_PENDING 3u
#define SEC_ST_EXHAUSTED      4u
#define SEC_ST_BOOTING        5u

#define SEC_STATE_REC_LEN 64u
#define SEC_STATE_TAG_LEN 16u

#define SEC_SUB_COMMIT      0x01u
#define SEC_SUB_READ_ACTIVE 0x02u
#define SEC_SUB_READ_SLOT   0x03u
#define SEC_SUB_INJECT_TAG  0x04u
#define SEC_SUB_BOOT        0x05u
#define SEC_SUB_FACTORY_INIT 0x06u
#define SEC_SUB_GET_STATE   0x07u
#define SEC_SUB_NVM_LOAD    0x08u
#define SEC_SUB_NVM_READ    0x09u
#define SEC_SUB_MC_LOAD     0x0au
#define SEC_SUB_WRAP_LOAD   0x0bu
#define SEC_SUB_WRAPPED_READ_LO 0x0cu
#define SEC_SUB_WRAPPED_READ_HI 0x0du
#define SEC_SUB_PROVISION       0x0eu  /* Trusted setup only: load keys/unwrap, remain BOOTING. */

#define SEC_OK                0u
#define SEC_RSP_BUSY          1u
#define SEC_ERR_LOCKED        2u
#define SEC_ERR_COMMIT        3u
#define SEC_ERR_AUTH          4u
#define SEC_ERR_PATH          5u
#define SEC_ERR_EXHAUSTED     6u
#define SEC_ERR_PARAM         7u
#define SEC_ERR_FACTORY_LOCKED 8u
#define SEC_ERR_UNSUPPORTED   9u
#define SEC_ERR_PHASE        10u

void sec_init(lms_mmio_client_t *client);

int sec_boot(const uint8_t I[LMS_I_LEN]);
int sec_keygen_key(uint8_t I[LMS_I_LEN]);

int sec_keygen_new(uint8_t I_new[LMS_I_LEN]);

int sec_handle_uart_cmd(uint8_t sub, const uint8_t *params, uint8_t response[32]);

uint16_t sec_hw_state(void);
uint32_t sec_last_committed_tx(void);

uint32_t sec_ctr_value(void);
uint8_t sec_key_ready(void);
uint8_t sec_keygen_pending_flag(void);

void sec_export_active(uint8_t out[SEC_STATE_REC_LEN]);

int sec_sign(uint32_t max_ctr,
             int (*do_sign)(uint32_t q, void *ctx), void *ctx,
             uint32_t *q_out);

#ifdef __cplusplus
}
#endif

#endif /* LMS_SEC_STATE_H */
