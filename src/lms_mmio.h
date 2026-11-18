#ifndef LMS_MMIO_H
#define LMS_MMIO_H

#include "lms.h"
#include "hash_api.h"

#include <stddef.h>
#include <stdint.h>

#define LMS_MMIO_VERSION_0_1 0x00000001u
#define LMS_MMIO_VERSION_0_2 0x00000002u
#define LMS_MMIO_VERSION_0_3 0x00000003u
#define LMS_MMIO_VERSION_0_4 0x00000004u
#define LMS_MMIO_VERSION_0_5 0x00000005u
#define LMS_MMIO_VERSION_0_6 0x00000006u
#define LMS_MMIO_VERSION_0_7 0x00000007u

#define LMS_MMIO_CAP_SHA256   (1u << 0)
#define LMS_MMIO_CAP_HASH_ONCE (1u << 1)
#define LMS_MMIO_CAP_CHAIN     (1u << 2)
#define LMS_MMIO_CAP_DERIVE_CHAIN (1u << 3)
#define LMS_MMIO_CAP_INSECURE_TEST_MODE (1u << 4)
#define LMS_MMIO_CAP_LMOTS_KEYGEN (1u << 5)
#define LMS_MMIO_CAP_LMOTS_SIGN (1u << 6)
#define LMS_MMIO_CAP_LMOTS_VERIFY (1u << 7)
#define LMS_MMIO_CAP_SIM_MC   (1u << 8)
#define LMS_MMIO_CAP_WRAP     (1u << 9)
#define LMS_MMIO_CAP_HMAC_KSTATE (1u << 10)
#define LMS_MMIO_CAP_LMOTS_KEYGEN_LEAF (1u << 11)
#define LMS_MMIO_CAP_SHAKE256  (1u << 12)
#define LMS_MMIO_CAP_D_INTR_CHAIN (1u << 13)
#define LMS_MMIO_CAP_MSG_Q_COEF (1u << 14)
#define LMS_MMIO_CAP_STATE_COMMIT (1u << 15)
#define LMS_MMIO_CAP_PROBE_REQUIRED LMS_MMIO_CAP_SHA256
#define LMS_MMIO_CAP_V0_REQUIRED \
    (LMS_MMIO_CAP_SHA256 | LMS_MMIO_CAP_HASH_ONCE | LMS_MMIO_CAP_CHAIN)

#define LMS_MMIO_REG_VERSION       0x000u
#define LMS_MMIO_REG_CAPABILITY    0x004u
#define LMS_MMIO_REG_COMMAND       0x008u
#define LMS_MMIO_REG_CONTROL       0x00cu
#define LMS_MMIO_REG_STATUS        0x010u
#define LMS_MMIO_REG_ERROR         0x014u
#define LMS_MMIO_REG_INPUT_LENGTH  0x018u
#define LMS_MMIO_REG_OUTPUT_LENGTH 0x01cu
#define LMS_MMIO_REG_CYCLE_COUNT   0x020u
#define LMS_MMIO_REG_ARG_Q         0x024u
#define LMS_MMIO_REG_ARG_I         0x028u
#define LMS_MMIO_REG_ARG_START     0x02cu
#define LMS_MMIO_REG_ARG_STEPS     0x030u
#define LMS_MMIO_REG_ARG_KEY       0x034u
#define LMS_MMIO_REG_TASK_ADDR     0x038u
#define LMS_MMIO_REG_TASK_DATA     0x03cu
#define LMS_MMIO_REG_IDENTIFIER    0x040u
#define LMS_MMIO_REG_SIM_MC        0x060u
#define LMS_MMIO_REG_ARG_LEAF_NODE 0x050u
#define LMS_MMIO_REG_SEED          0x080u
#define LMS_MMIO_REG_WRAPPED       0x0a0u
#define LMS_MMIO_REG_KWRAP         0x0e0u
#define LMS_MMIO_REG_INPUT         0x100u
#define LMS_MMIO_REG_OUTPUT        0x200u
/* KSD transaction controller. These registers never accept recovery or ACK. */
#define LMS_MMIO_REG_KSD_CONTROL    0x240u
#define LMS_MMIO_REG_KSD_STATE      0x244u
#define LMS_MMIO_REG_KSD_SIGNING_Q  0x248u
#define LMS_MMIO_REG_KSD_NEXT_Q     0x24cu
#define LMS_MMIO_REG_KSD_LAST_TX    0x250u
#define LMS_MMIO_REG_KSD_PROFILE    0x254u
#define LMS_MMIO_REG_KSD_MARKER     0x258u
#define LMS_MMIO_KSD_MARKER         0x4b534431u
#define LMS_MMIO_KSD_BEGIN          1u
#define LMS_MMIO_KSD_ABORT          2u
#define LMS_MMIO_KSD_RECOVERY_LOCKED 0u
#define LMS_MMIO_KSD_IDLE           1u
#define LMS_MMIO_KSD_RESERVE_PENDING 2u
#define LMS_MMIO_KSD_RESERVED_READY 3u
#define LMS_MMIO_KSD_SIGNING        4u
#define LMS_MMIO_KSD_DRAINING       5u
#define LMS_MMIO_KSD_FINALIZE_PENDING 6u
#define LMS_MMIO_KSD_EXHAUSTED      7u
#define LMS_MMIO_KSD_ERROR_LOCKED   8u
/* R6 Stage 1 result window (read-only y port; addresses relative to y). */
#define LMS_MMIO_REG_RESULT_EPOCH   0x300u
#define LMS_MMIO_REG_RESULT_COUNT   0x304u
#define LMS_MMIO_REG_RESULT_STATUS  0x308u
#define LMS_MMIO_REG_RESULT_LENGTH  0x30cu
#define LMS_MMIO_REG_RESULT_ADDR    0x310u
#define LMS_MMIO_REG_RESULT_DATA    0x314u
#define LMS_MMIO_REG_RESULT_RELEASE 0x318u
#define LMS_MMIO_REG_RESULT_ERROR   0x31cu

#define LMS_MMIO_RESULT_STATUS_ACTIVE (1u << 0)
#define LMS_MMIO_RESULT_STATUS_DONE   (1u << 1)
#define LMS_MMIO_RESULT_STATUS_ERROR  (1u << 2)
#define LMS_MMIO_RESULT_ERR_NOT_READY 0x00000010u

#define LMS_MMIO_CMD_HASH_ONCE 1u
#define LMS_MMIO_CMD_CHAIN     2u
#define LMS_MMIO_CMD_SEED_LOAD 3u
#define LMS_MMIO_CMD_DERIVE_CHAIN 4u
#define LMS_MMIO_CMD_DERIVE_RANDOMIZER 5u
#define LMS_MMIO_CMD_LMOTS_KEYGEN 6u
#define LMS_MMIO_CMD_LMOTS_SIGN 7u
#define LMS_MMIO_CMD_LMOTS_VERIFY 8u

#define LMS_MMIO_CMD_LMOTS_KEYGEN_LEAF 14u
#define LMS_MMIO_CMD_LMOTS_VERIFY_LEAF 15u

#define LMS_MMIO_CMD_MC_STEP 16u
#define LMS_MMIO_CMD_MC_LOAD 17u
#define LMS_MMIO_CMD_WRAP_SEED 18u
#define LMS_MMIO_CMD_UNWRAP_SEED 19u
#define LMS_MMIO_CMD_HMAC_KSTATE 20u
#define LMS_MMIO_CMD_STATE_COMMIT 21u

#define LMS_MMIO_CMD_D_INTR_CHAIN 24u
#define LMS_MMIO_CMD_HASH_ONCE_RAM 25u
#define LMS_MMIO_CMD_MSG_Q_COEF 26u

#define LMS_MMIO_CMD_SEED_WRITE_SAFE 28u  /* 0x1c */

#define LMS_MMIO_WRAPPED_LEN 48u
#define LMS_MMIO_KEY_SEED 0u
#define LMS_MMIO_KEY_KWRAP 1u
#define LMS_MMIO_KEY_KSTATE 2u

#define LMS_MMIO_CTRL_START (1u << 0)
#define LMS_MMIO_CTRL_CLEAR (1u << 1)

#define LMS_MMIO_STATUS_BUSY  (1u << 0)
#define LMS_MMIO_STATUS_DONE  (1u << 1)
#define LMS_MMIO_STATUS_ERROR (1u << 2)

#define LMS_MMIO_HW_ERR_NONE                0u
#define LMS_MMIO_HW_ERR_UNSUPPORTED_COMMAND 1u
#define LMS_MMIO_HW_ERR_BUSY                2u
#define LMS_MMIO_HW_ERR_INPUT_LENGTH        3u
#define LMS_MMIO_HW_ERR_OUTPUT_LENGTH       4u
#define LMS_MMIO_HW_ERR_CHAIN_INDEX         5u
#define LMS_MMIO_HW_ERR_CHAIN_RANGE         6u
#define LMS_MMIO_HW_ERR_CONTROL             7u
#define LMS_MMIO_HW_ERR_INTERNAL            15u
#define LMS_MMIO_HW_ERR_SIGN_CONTEXT        17u /* missing/changed hardware MQC coefficients */

#define LMS_MMIO_OUTPUT_LEN 32u
#define LMS_MMIO_MAX_INPUT  128u
#define LMS_MMIO_HASH_ONCE_RAM_MAX 2048u

#define LMS_MMIO_MAX_COEFFICIENTS LMS_MAX_OTS_P
#define LMS_MMIO_MAX_CHAIN_BYTES (LMS_MAX_OTS_P * LMS_N)
#define LMS_MMIO_TASK_CHAIN_WORD_BASE 32u

#define LMS_MMIO_REG_ARG_W      0x054u

#define LMS_MMIO_TASK_STREAM_BASE 32u

typedef enum {
    LMS_MMIO_OK = 0,
    LMS_MMIO_ERR_INVALID = -1,
    LMS_MMIO_ERR_PROTOCOL = -2,
    LMS_MMIO_ERR_HARDWARE = -3,
    LMS_MMIO_ERR_TIMEOUT = -4
} lms_mmio_status_t;

typedef struct {
    uint32_t state, signing_q, next_q, last_tx, profile;
} lms_mmio_ksd_status_t;

typedef struct {
    lms_hash_alg_t hash_alg;         /* LMS_HASH_SHA256 / LMS_HASH_SHAKE256 */
    uint32_t       version;
    uint32_t       probe_cap;
    uint32_t       max_input_bytes;
    const char    *name;
} lms_mmio_hash_desc_t;

extern const lms_mmio_hash_desc_t LMS_MMIO_HASH_DESC_SHA256;
extern const lms_mmio_hash_desc_t LMS_MMIO_HASH_DESC_SHAKE256;

typedef uint32_t (*lms_mmio_read32_fn)(void *context, uint32_t offset);
typedef void (*lms_mmio_write32_fn)(void *context, uint32_t offset, uint32_t value);

typedef struct {
    void *context;
    lms_mmio_read32_fn read32;
    lms_mmio_write32_fn write32;
} lms_mmio_bus_t;

typedef struct {
    lms_mmio_bus_t bus;
    uint32_t timeout_polls;
    uint32_t capabilities;
    uint32_t last_hw_error;
    uint32_t fallback_count;
    uint64_t hardware_chain_count;
    uint64_t hardware_chain_cycles;
    uint64_t hardware_derive_count;
    uint64_t hardware_derive_cycles;
    uint64_t hardware_keygen_count;
    uint64_t hardware_keygen_cycles;
    uint64_t hardware_sign_count;
    uint64_t hardware_sign_cycles;
    uint64_t hardware_verify_count;
    uint64_t hardware_verify_cycles;
    uint64_t hardware_hash_once_count;
    uint64_t hardware_hash_once_cycles;
    /* R6 Stage 2: streaming LM-OTS Sign state (result window). */
    uint32_t sign_stream_active;
    uint32_t sign_stream_words;
#if defined(LMS_MMIO_SOC_PROFILE)

    uint32_t prof_write_cycles;
    uint32_t prof_wait_cycles;
    uint32_t prof_read_cycles;
#endif
    uint32_t key_handle;
    int allow_fallback;
    int probed;
    int coef_ready;
    const lms_mmio_hash_desc_t *hash_desc;

    const uint8_t *randomizer_c_slot;
    int  (*trng_fill_c)(void *context, uint8_t out[LMS_N]);
    void *trng_context;
} lms_mmio_client_t;

int lms_mmio_ksd_read(lms_mmio_client_t *client, lms_mmio_ksd_status_t *status);
int lms_mmio_ksd_begin(lms_mmio_client_t *client, uint32_t expected_q);
int lms_mmio_ksd_finish(lms_mmio_client_t *client, uint32_t expected_next_q);
int lms_mmio_ksd_wait_recovery(lms_mmio_client_t *client);

void lms_mmio_bus_init_direct(lms_mmio_bus_t *bus, volatile void *base);
int lms_mmio_client_init(lms_mmio_client_t *client,
                         const lms_mmio_bus_t *bus,
                         uint32_t timeout_polls,
                         int allow_fallback);
int lms_mmio_probe(lms_mmio_client_t *client);
int lms_mmio_hash_once(lms_mmio_client_t *client,
                       const uint8_t *input,
                       size_t input_len,
                       uint8_t output[LMS_N],
                       uint32_t *cycles);

int lms_mmio_hash_once_ram(lms_mmio_client_t *client,
                           const uint8_t *input,
                           size_t input_len,
                           uint8_t output[LMS_N],
                           uint32_t *cycles);

int lms_mmio_msg_q_coef(lms_mmio_client_t *client,
                        const uint8_t I[LMS_I_LEN],
                        uint32_t q,
                        const uint8_t C[LMS_N],
                        const uint8_t *message,
                        size_t message_len,
                        uint32_t lmots_type,
                        uint8_t Q[LMS_N],
                        uint8_t coefficients[LMS_MAX_OTS_P],
                        uint32_t *cycles);
int lms_mmio_chain(lms_mmio_client_t *client,
                   const uint8_t I[LMS_I_LEN],
                   uint32_t q,
                   uint32_t i,
                   uint32_t start,
                   uint32_t steps,
                   uint8_t value[LMS_N],
                   uint32_t *cycles);
int lms_mmio_seed_load_test(lms_mmio_client_t *client,
                            uint32_t key_handle,
                            const uint8_t seed[LMS_SEED_LEN]);

int lms_mmio_seed_load_safe(lms_mmio_client_t *client,
                            const uint8_t seed[LMS_SEED_LEN]);
int lms_mmio_derive_chain(lms_mmio_client_t *client,
                          uint32_t key_handle,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t i,
                          uint32_t start,
                          uint32_t steps,
                          uint8_t output[LMS_N],
                          uint32_t *cycles);
int lms_mmio_derive_randomizer(lms_mmio_client_t *client,
                               uint32_t key_handle,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint8_t output[LMS_N],
                               uint32_t *cycles);
    int lms_mmio_lmots_keygen(lms_mmio_client_t *client,
                         uint32_t key_handle,
                         const uint8_t I[LMS_I_LEN],
                         uint32_t q,
                         uint32_t lmots_type,
                         uint8_t output[LMS_N],
                         uint32_t *cycles);

    int lms_mmio_lmots_keygen_leaf(lms_mmio_client_t *client,
                         uint32_t key_handle,
                         const uint8_t I[LMS_I_LEN],
                         uint32_t q,
                         uint32_t node_num,
                         uint32_t lmots_type,
                         uint8_t output[LMS_N],
                         uint32_t *cycles);
int lms_mmio_lmots_sign(lms_mmio_client_t *client,
                        uint32_t key_handle,
                        const uint8_t I[LMS_I_LEN],
                        uint32_t q,
                        uint32_t lmots_type,
                        const uint8_t coefficients[LMS_MAX_OTS_P],
                        uint8_t outputs[LMS_MAX_OTS_P * LMS_N],
                        uint32_t *cycles);
int lms_mmio_lmots_verify(lms_mmio_client_t *client,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t lmots_type,
                          const uint8_t coefficients[LMS_MAX_OTS_P],
                          const uint8_t inputs[LMS_MAX_OTS_P * LMS_N],
                          uint8_t output[LMS_N],
                          uint32_t *cycles);

int lms_mmio_lmots_sign_taskram(lms_mmio_client_t *client,
                                uint32_t key_handle,
                                const uint8_t I[LMS_I_LEN],
                                uint32_t q,
                                uint32_t lmots_type,
                                const uint8_t coefficients[LMS_MAX_OTS_P],
                                uint32_t *cycles);
/* R6 Stage 2: split LM-OTS Sign so the CPU can read committed y chains while
 * the engine is still computing later pairs.  start/poll/read/release keep the
 * same command issue sequence as lms_mmio_lmots_sign_taskram. */
int lms_mmio_lmots_sign_start(lms_mmio_client_t *client,
                              uint32_t key_handle,
                              const uint8_t I[LMS_I_LEN],
                              uint32_t q,
                              uint32_t lmots_type,
                              const uint8_t coefficients[LMS_MAX_OTS_P]);
int lms_mmio_lmots_sign_poll(lms_mmio_client_t *client,
                             uint32_t *count,
                             uint32_t *status);
int lms_mmio_lmots_sign_read_word(lms_mmio_client_t *client,
                                  uint32_t index,
                                  uint32_t *word);
/* Burst one 8-word chain after a single RESULT_ADDR write; requires the
 * Stage 1b RESULT_DATA auto-increment. */
int lms_mmio_lmots_sign_read_chain(lms_mmio_client_t *client,
                                   uint32_t chain,
                                   uint8_t output[LMS_N]);
int lms_mmio_lmots_sign_release(lms_mmio_client_t *client);
/* Full streaming consumer: start, poll committed chains, copy y, wait done,
 * capture cycles, release.  Returns LMS_MMIO_OK only with a complete y. */
int lms_mmio_lmots_sign_stream(lms_mmio_client_t *client,
                               uint32_t key_handle,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint32_t lmots_type,
                               const uint8_t coefficients[LMS_MAX_OTS_P],
                               uint8_t outputs[LMS_MAX_OTS_P * LMS_N],
                               uint32_t *cycles);
int lms_mmio_lmots_verify_taskram(lms_mmio_client_t *client,
                                  const uint8_t I[LMS_I_LEN],
                                  uint32_t q,
                                  uint32_t lmots_type,
                                  const uint8_t coefficients[LMS_MAX_OTS_P],
                                  uint8_t output[LMS_N],
                                  uint32_t *cycles);

int lms_mmio_lmots_verify_leaf(lms_mmio_client_t *client,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint32_t node_num,
                               uint32_t lmots_type,
                               const uint8_t coefficients[LMS_MAX_OTS_P],
                               const uint8_t inputs[LMS_MAX_OTS_P * LMS_N],
                               uint8_t output[LMS_N],
                               uint32_t *cycles);

int lms_mmio_lmots_verify_leaf_taskram(lms_mmio_client_t *client,
                                       const uint8_t I[LMS_I_LEN],
                                       uint32_t q,
                                       uint32_t node_num,
                                       uint32_t lmots_type,
                                       const uint8_t coefficients[LMS_MAX_OTS_P],
                                       uint8_t output[LMS_N],
                                       uint32_t *cycles);

int lms_mmio_lmots_keygen_enable(lms_mmio_client_t *client, uint32_t key_handle);
int lms_mmio_lmots_sign_enable(lms_mmio_client_t *client, uint32_t key_handle);
void lms_mmio_lmots_keygen_disable(void);
int lms_mmio_lmots_verify_enable(lms_mmio_client_t *client);
void lms_mmio_lmots_verify_disable(void);
void lms_mmio_lmots_sign_disable(void);

int lms_mmio_lmots_keygen_enable_insecure(lms_mmio_client_t *client);
int lms_mmio_lmots_sign_enable_insecure(lms_mmio_client_t *client);

int lms_mmio_mc_read(lms_mmio_client_t *client, uint32_t *value);
int lms_mmio_mc_step(lms_mmio_client_t *client, uint32_t *value);

int lms_mmio_state_commit(lms_mmio_client_t *client,
                          uint16_t new_state, uint32_t ctr, uint8_t aad,
                          uint32_t *tx_out, uint8_t tag[16]);
int lms_mmio_mc_load(lms_mmio_client_t *client, uint32_t value);

int lms_mmio_key_slot_load_test(lms_mmio_client_t *client,
                                uint32_t key_slot,
                                const uint8_t key[LMS_SEED_LEN]);

int lms_mmio_wrap_seed(lms_mmio_client_t *client,
                       uint8_t wrapped[LMS_MMIO_WRAPPED_LEN]);

int lms_mmio_unwrap_seed(lms_mmio_client_t *client,
                         const uint8_t wrapped[LMS_MMIO_WRAPPED_LEN]);

int lms_mmio_hmac_kstate(lms_mmio_client_t *client,
                         const uint8_t *input,
                         size_t input_len,
                         uint8_t output[LMS_N]);

#endif
