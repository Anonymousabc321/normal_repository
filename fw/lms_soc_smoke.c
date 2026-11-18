#include <stdint.h>
#include <string.h>

#include "lms.h"
#include "lms_internal.h"
#include "lms_mmio.h"
#include "lms_rnd.h"
#include "lms_uart_proto.h"
#include "lms_sec_state.h"
#include "lms_subtree.h"
#include "paper_bench_counters.h"

#if defined(FW_HASH_SHA256)
#define FW_HASH_ALG   LMS_HASH_SHA256
#define FW_LMOTS_W1   LMOTS_SHA256_N32_W1
#define FW_LMOTS_W2   LMOTS_SHA256_N32_W2
#define FW_LMOTS_W4   LMOTS_SHA256_N32_W4
#define FW_LMOTS_W8   LMOTS_SHA256_N32_W8
#elif defined(FW_HASH_SHAKE256)
#define FW_HASH_ALG   LMS_HASH_SHAKE256
#define FW_LMOTS_W1   LMOTS_SHAKE256_N32_W1
#define FW_LMOTS_W2   LMOTS_SHAKE256_N32_W2
#define FW_LMOTS_W4   LMOTS_SHAKE256_N32_W4
#define FW_LMOTS_W8   LMOTS_SHAKE256_N32_W8
#else
#error "No hash algorithm selected (define FW_HASH_SHA256 or FW_HASH_SHAKE256)"
#endif

#define MMIO32(address) (*(volatile uint32_t *)(uintptr_t)(address))

#define UART_TX           0x10000000u
#define UART_TX_READY     0x10000004u
#define UART_RX           0x10000008u
#define UART_RX_READY     0x1000000cu
#define SOC_CYCLE_COUNT   0x10000010u
#define GPIO_OUT          0x10000018u
#define LMS_BASE          0x16000000u
#define LMS_COMMAND       (LMS_BASE + 0x008u)
#define LMS_CONTROL       (LMS_BASE + 0x00cu)
#define LMS_STATUS        (LMS_BASE + 0x010u)
#define LMS_ERROR         (LMS_BASE + 0x014u)
#define LMS_INPUT_LENGTH  (LMS_BASE + 0x018u)
#define LMS_OUTPUT_LENGTH (LMS_BASE + 0x01cu)
#define LMS_CYCLE_COUNT   (LMS_BASE + 0x020u)

/* SW64: ordinary LMS command CPU timing. Preserve the existing measurement
 * boundaries; CSR reads include a compiler barrier and retry a low-word wrap.
 * Response (software build only): +20=total low, +40=0x53573634, +44=total high.
 * These are little-endian words in the unchanged 48-byte header. Accelerator
 * cycles/hits retain their existing fields. Other opcodes keep their layouts. */
#if LMS_FW_NO_HW_ACCEL || LMS_FW_PAPER_BENCH
typedef uint64_t fw_total_clock_t;
static uint32_t fw_total_cycles_hi;
static uint32_t fw_steady_cycles_hi;
static uint32_t fw_hardware_cycles_hi;
static inline uint64_t fw_total_read(void)
{
    uint32_t hi0, lo, hi1;
    do {
        __asm__ volatile("csrr %0, mcycleh\n"
                         "csrr %1, mcycle\n"
                         "csrr %2, mcycleh\n"
                         : "=r"(hi0), "=r"(lo), "=r"(hi1) : : "memory");
    } while (hi0 != hi1);
    return ((uint64_t)hi1 << 32) | lo;
}
static inline void fw_total_finish(uint32_t *low, fw_total_clock_t start)
{
    paper_split_elapsed(fw_total_read(), start, low, &fw_total_cycles_hi);
}
static inline void fw_steady_finish(uint32_t *low, fw_total_clock_t start)
{
    paper_split_elapsed(fw_total_read(), start, low, &fw_steady_cycles_hi);
}
#else
typedef uint32_t fw_total_clock_t;
#define fw_total_read() MMIO32(SOC_CYCLE_COUNT)
#define fw_total_finish(low, start) (*(low) = MMIO32(SOC_CYCLE_COUNT) - (start))
#define fw_steady_finish(low, start) (*(low) = MMIO32(SOC_CYCLE_COUNT) - (start))
#endif

#define LMS_ARG_Q         (LMS_BASE + 0x024u)
#define LMS_ARG_I         (LMS_BASE + 0x028u)
#define LMS_ARG_START     (LMS_BASE + 0x02cu)
#define LMS_ARG_STEPS     (LMS_BASE + 0x030u)
#define LMS_IDENTIFIER    (LMS_BASE + 0x040u)
#define LMS_INPUT         (LMS_BASE + 0x100u)
#define LMS_OUTPUT        (LMS_BASE + 0x200u)
#define LMS_DBG_ADDR      (LMS_BASE + 0x220u)
#define LMS_TIMEOUT0      (LMS_BASE + 0x228u)
#define LMS_TIMEOUT1      (LMS_BASE + 0x22cu)
#define LMS_DBG_DATA      (LMS_BASE + 0x224u)

#define LMS_STAGE(n) (*(volatile uint32_t *)(uintptr_t)(LMS_BASE + 0x180u + ((uint32_t)(n) << 2)))
static void stage_ping(uint32_t n) { LMS_STAGE(n) = 0x53544147u; }

static void uart_putc(uint8_t value);
#ifndef LMS_FW_KEYGEN_TRACE
#define LMS_FW_KEYGEN_TRACE 0
#endif
/* R6 Stage 2: 1 = LM-OTS Sign reads committed y from the result window while
 * the engine runs; 0 = R5 blocking task-RAM readback (A/B fallback). */
#ifndef LMS_SIGN_RESULT_STREAM
#define LMS_SIGN_RESULT_STREAM 0
#endif
static void keygen_trace(uint8_t n) {
#if LMS_FW_KEYGEN_TRACE
    uart_putc((uint8_t)(0xA0u | (n & 0x0Fu)));
#else
    (void)n;
#endif
}

#define LMS_CMD_HASH_ONCE 1u
#define LMS_CMD_CHAIN     2u
#define LMS_CMD_DERIVE_CHAIN 4u
#define LMS_CMD_DERIVE_RANDOMIZER 5u
#define LMS_CMD_D_INTR_CHAIN 0x18u
#define LMS_CTRL_START    1u
#define LMS_CTRL_CLEAR    2u
#define LMS_STATUS_BUSY   1u
#define LMS_STATUS_DONE   2u
#define LMS_TASK_ADDR     (LMS_BASE + 0x038u)
#define LMS_TASK_DATA     (LMS_BASE + 0x03cu)

#define LMS_CAP_CTL       (LMS_BASE + 0x230u)
#define LMS_CAP_IDX       (LMS_BASE + 0x234u)
#define LMS_CAP_DATA      (LMS_BASE + 0x238u)
#define LMS_ARG_LEAF_NODE (LMS_BASE + 0x050u)

#define TRNG_BASE     0x17000000u
#define TRNG_VERSION  (TRNG_BASE + 0x00u)
#define TRNG_CAP      (TRNG_BASE + 0x04u)
#define TRNG_CTRL     (TRNG_BASE + 0x08u)
#define TRNG_STAT     (TRNG_BASE + 0x0cu)
#define TRNG_RND      (TRNG_BASE + 0x10u)
#define TRNG_APT      (TRNG_BASE + 0x14u)

#define FLASH_BASE     0x19000000u
#define FLASH_VERSION  (FLASH_BASE + 0x00u)
#define FLASH_CTRL     (FLASH_BASE + 0x04u)
#define FLASH_STATUS   (FLASH_BASE + 0x08u)
#define FLASH_RESP0    (FLASH_BASE + 0x0cu)   /* B4  */
#define FLASH_RESP1    (FLASH_BASE + 0x10u)   /* K12 */
#define FLASH_RESP2    (FLASH_BASE + 0x14u)   /* J14 */
#define FLASH_RESP3    (FLASH_BASE + 0x18u)   /* K15 */
#define FLASH_RESP4    (FLASH_BASE + 0x1cu)   /* L13 */
#define FLASH_OP       (FLASH_BASE + 0x20u)
#define FLASH_ADDR     (FLASH_BASE + 0x24u)
#define FLASH_BYTE     (FLASH_BASE + 0x28u)

#define BRIDGE_BASE   0x18000000u
#define BRIDGE_CTRL   (BRIDGE_BASE + 0x00u)
#define BRIDGE_ADDR   (BRIDGE_BASE + 0x04u)
#define BRIDGE_LEN    (BRIDGE_BASE + 0x08u)
#define BRIDGE_START  1u
#define BRIDGE_CLEAR  2u
#define BRIDGE_DIR_RX 0u
#define BRIDGE_DIR_TX 2u
#define BRIDGE_BUSY   1u
#define BRIDGE_DONE   2u
#define BRIDGE_ERROR  4u
#define BRIDGE_Y_ADDR 32u

#define LMS_062_FORCE_SW_Y 0

#define UART_REQUEST_HASH LMS_OP_HASH
#define UART_REQUEST_CHAIN LMS_OP_CHAIN
#define UART_REQUEST_VERIFY LMS_OP_LMS_VERIFY
#define UART_REQUEST_SIGN_TEST LMS_OP_LMS_SIGN
#define UART_REQUEST_KEYGEN_TEST LMS_OP_LMS_KEYGEN
#define UART_REQUEST_LMOTS_KEYGEN_TEST LMS_OP_OTS_KEYGEN
#define UART_REQUEST_LMOTS_SIGN_TEST LMS_OP_OTS_SIGN
#define UART_REQUEST_LMOTS_VERIFY_TEST LMS_OP_OTS_VERIFY
#define UART_REQUEST_SEED_LOAD_TEST LMS_OP_SEED_LOAD

#define UART_REQUEST_C_LOAD LMS_OP_C_LOAD

static uint8_t seed_echo[32];

static uint8_t s_sign_c[LMS_N];
static uint8_t s_sign_coef[LMS_MAX_OTS_P];

static uint8_t sign_dump[100];

#define UART_REQUEST_SEC_LMS_SIGN LMS_OP_SEC_LMS_SIGN
#define UART_REQUEST_SEC_LMS_KEYGEN LMS_OP_SEC_LMS_KEYGEN

#define UART_REQUEST_SEC_LMS_KEYGEN_NEW LMS_OP_SEC_LMS_KEYGEN_NEW
#define UART_RESPONSE     0x52u

#define UART_REQUEST_NVM_SYNC LMS_OP_NVM_SYNC
#define NVM_SYNC_SUB_PUSH_LO  0x01u
#define NVM_SYNC_SUB_PUSH_HI  0x02u
#define NVM_SYNC_SUB_READ     0x03u
#define NVM_SYNC_SUB_READ_HI  0x04u
#define NVM_SYNC_SUB_READ_MID 0x05u
#define NVM_STATE_LEN         64u
#define NVM_CHUNK_LEN         32u
#define NVM_CRC_LEN           2u

#define UART_REQUEST_SEC_STATE LMS_OP_SEC_STATE

#define UART_REQUEST_SEC_SIGN LMS_OP_SEC_SIGN

#define UART_REQUEST_TRNG_READ LMS_OP_TRNG_READ
#define UART_REQUEST_TRNG_STATUS LMS_OP_TRNG_STATUS

#define UART_REQUEST_TRNG_READ_ACK LMS_OP_TRNG_ACK

#define UART_REQUEST_FLASH_PROBE LMS_OP_FLASH_PROBE

#define UART_REQUEST_FLASH_PROG LMS_OP_FLASH_PROG

#define UART_REQUEST_FLASH_CMD LMS_OP_FLASH_CMD

#define UART_REQUEST_DERIVE_RANDOMIZER LMS_OP_DERIVE_RANDOMIZER

#define UART_REQUEST_PRF_CHAIN LMS_OP_PRF_CHAIN

#define UART_REQUEST_DERIVE_XQ LMS_OP_DERIVE_XQ
#define VERIFY_MESSAGE_MAX 2048u
#define VERIFY_SIGNATURE_LEN 2348u /* W4/H5:4(q)+4(ots)+32(C)+2144(y)+4(lms)+5*32(path) */
#define LMOTS_W4_SIGNATURE_LEN (4u + LMS_N + 67u * LMS_N)

#define LMS_MAX_OTS_SIG_LEN (4u + LMS_N + LMS_MAX_OTS_P * LMS_N)

static uint32_t lmots_sig_len_type(uint32_t lmots_type)
{
    lmots_param_t param;

    if (lms_get_lmots_param(lmots_type, &param) != LMS_OK) {
        return 0u;
    }
    return 4u + param.n + param.p * param.n;
}

static uint32_t lmots_y_len_type(uint32_t lmots_type)
{
    lmots_param_t param;

    if (lms_get_lmots_param(lmots_type, &param) != LMS_OK) {
        return 0u;
    }
    return param.p * param.n;
}

static uint32_t mqc_msg_base(uint32_t y_len)
{
    uint32_t base = 32u + y_len / 4u;
    return (base >= 2152u) ? 568u : base;
}

static uint32_t lmots_sig_len_priv(const lms_private_key_t *priv)
{
    return lmots_sig_len_type(priv->lmots_type);
}

static int lmots_hw_supported(uint32_t lmots_type)
{
    lmots_param_t param;

    if (lms_get_lmots_param(lmots_type, &param) != LMS_OK) {
        return 0;
    }
    return param.w == 1u || param.w == 2u || param.w == 4u || param.w == 8u;
}

static uint32_t hardware_hits;
static lms_mmio_client_t verify_client;

#if LMS_FW_PAPER_BENCH
/* Algorithm-command accounting: all six library counter families, including
 * MQC and cache initialization. Seed transfer and pre-command selftest have
 * no library algorithm counter and remain excluded from hw (included in total
 * where they occur inside that operation). */
static uint64_t paper_hw_cycles(void)
{
    return verify_client.hardware_chain_cycles + verify_client.hardware_derive_cycles
         + verify_client.hardware_keygen_cycles + verify_client.hardware_sign_cycles
         + verify_client.hardware_verify_cycles + verify_client.hardware_hash_once_cycles;
}
static uint64_t paper_hw_hits(void)
{
    return verify_client.hardware_chain_count + verify_client.hardware_derive_count
         + verify_client.hardware_keygen_count + verify_client.hardware_sign_count
         + verify_client.hardware_verify_count + verify_client.hardware_hash_once_count;
}
static int paper_request(uint32_t r)
{
    return r == LMS_OP_LMS_KEYGEN || r == LMS_OP_LMS_SIGN || r == LMS_OP_LMS_VERIFY
        || r == LMS_OP_OTS_KEYGEN || r == LMS_OP_OTS_SIGN || r == LMS_OP_OTS_VERIFY;
}
#endif

static uint8_t s_uart_msg[VERIFY_MESSAGE_MAX];
static uint8_t s_uart_sig[LMS_MAX_SIGNATURE_LEN];
static uint8_t s_uart_auth_tail[4u + LMS_MAX_HEIGHT * LMS_N];

#ifndef LMS_FW_OTS_SNAPSHOT
#define LMS_FW_OTS_SNAPSHOT 0
#endif
#define DBG_SNAP_BYTES (67u * LMS_N)   /* 2144:W4 p=67 */
static uint8_t dbg_y[DBG_SNAP_BYTES];
static uint8_t dbg_ep[DBG_SNAP_BYTES];
static uint8_t dbg_coef[36];
static uint8_t dbg_kq[LMS_N];
static uint8_t dbg_meta[16];
static uint8_t dbg_valid;
static uint32_t dbg_run;
static uint32_t sign_y_in_taskram;
static uint32_t fw_selftest_fail_count;
static uint32_t lmots_out_sig_len;
static uint32_t sign_y_len;

static uint8_t s_seed_slot_valid;
static uint8_t s_seed_slot[LMS_SEED_LEN];

static volatile uint32_t g_keygen_stage;

static uint8_t s_c_slot[LMS_N];
static uint8_t s_c_slot_valid;

static int fw_seed_load(const uint8_t seed[LMS_SEED_LEN])
{

    (void)s_seed_slot_valid;
    int rc = lms_mmio_seed_load_test(&verify_client, 0u, seed);
    if (rc != LMS_MMIO_OK) {
        s_seed_slot_valid = 0u;
        return rc;
    }
    memcpy(s_seed_slot, seed, LMS_SEED_LEN);
    s_seed_slot_valid = 1u;
    return LMS_MMIO_OK;
}
#if defined(LMS_MMIO_SOC_PROFILE)

static uint32_t prof_sec_enable_cycles;
static uint32_t prof_sec_sign_cycles;
static uint32_t prof_sec_tail_cycles;

extern uint32_t sec_prof_commit1_cycles;
extern uint32_t sec_prof_dosign_cycles;
extern uint32_t sec_prof_commit2_cycles;
extern uint32_t sec_prof_stc_cycles;
extern uint32_t sec_prof_enc_cycles;
#endif

static uint8_t nvm_state[NVM_STATE_LEN];
static uint16_t nvm_crc[NVM_STATE_LEN / NVM_CHUNK_LEN];
static uint8_t nvm_valid[NVM_STATE_LEN / NVM_CHUNK_LEN];

static uint8_t uart_getc(void)
{
    while (MMIO32(UART_RX_READY) == 0u) {
    }
    return (uint8_t)MMIO32(UART_RX);
}

static void uart_putc(uint8_t value)
{
    /* Paper r2: backpressure must preserve every response byte.  This output
     * wait occurs after the algorithm timing window.  The host may pause while
     * the USB FIFO is full; resume the same byte when UART accepts it again. */
    while (MMIO32(UART_TX_READY) == 0u) {
    }
    MMIO32(UART_TX) = value;
}

static void uart_put_u32(uint32_t value)
{
    uart_putc((uint8_t)value);
    uart_putc((uint8_t)(value >> 8));
    uart_putc((uint8_t)(value >> 16));
    uart_putc((uint8_t)(value >> 24));
}

static int __attribute__((unused))
bridge_run(uint32_t dir, uint32_t addr, uint32_t len)
{
    MMIO32(BRIDGE_ADDR) = addr;
    MMIO32(BRIDGE_LEN) = len;

    (void)MMIO32(BRIDGE_CTRL);
    MMIO32(BRIDGE_CTRL) = BRIDGE_START | dir;
    while ((MMIO32(BRIDGE_CTRL) & BRIDGE_BUSY) != 0u) {
    }
    if ((MMIO32(BRIDGE_CTRL) & BRIDGE_ERROR) != 0u) {
        MMIO32(BRIDGE_CTRL) = BRIDGE_CLEAR;
        return -1;
    }
    MMIO32(BRIDGE_CTRL) = BRIDGE_CLEAR;
    return 0;
}

static uint32_t uart_get_u32(void)
{
    uint32_t value = uart_getc();
    value |= (uint32_t)uart_getc() << 8;
    value |= (uint32_t)uart_getc() << 16;
    value |= (uint32_t)uart_getc() << 24;
    return value;
}

static uint32_t uart_get_u16(void)
{
    return ((uint32_t)uart_getc() << 8) | (uint32_t)uart_getc();
}

static uint8_t crc8_update(uint8_t crc, uint8_t byte)
{
    uint8_t bit;
    crc ^= byte;
    for (bit = 0u; bit < 8u; bit++) {
        crc = (crc & 0x80u) != 0u ? (uint8_t)((crc << 1) ^ 0x07u) : (uint8_t)(crc << 1);
    }
    return crc;
}

static uint8_t crc8_block(const uint8_t *data, uint32_t length)
{
    uint8_t crc = 0u;
    uint32_t index;
    for (index = 0u; index < length; index++) {
        crc = crc8_update(crc, data[index]);
    }
    return crc;
}

static void uart_read_bytes(uint8_t *output, uint32_t length)
{
    uint32_t index;
    for (index = 0; index < length; index++) {
        output[index] = uart_getc();
    }
}

static void uart_discard(uint32_t length)
{
    while (length-- > 0u) {
        (void)uart_getc();
    }
}

static void uart_read_window(uint32_t base, uint32_t length)
{
    uint32_t offset;
    uint32_t word = 0u;
    for (offset = 0; offset < length; offset++) {
        word |= (uint32_t)uart_getc() << (8u * (offset & 3u));
        if ((offset & 3u) == 3u || offset + 1u == length) {
            MMIO32(base + (offset & ~3u)) = word;
            word = 0u;
        }
    }
}

static int s_msg_in_ram;
#if !LMS_FW_NO_HW_ACCEL
static void task_read_words(uint32_t word_base, uint8_t *bytes, uint32_t length);
#endif

static uint32_t hash_once_from_uart(uint32_t input_length, uint32_t *cycles)
{
    uint32_t offset;

    if (input_length > 128u) {
        for (offset = 0; offset < input_length; offset++) {
            (void)uart_getc();
        }
        *cycles = 0u;
        return 0u;
    }

    MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
    MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
    MMIO32(LMS_INPUT_LENGTH) = input_length;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;

    uart_read_window(LMS_INPUT, input_length);

    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
    hardware_hits++;
    return MMIO32(LMS_STATUS);
}

static uint32_t derive_randomizer_from_uart(uint32_t *cycles)
{
    uint32_t q;
#if LMS_TVLA_RANDOM_DELAY

    {
        volatile uint32_t wait;
        uint32_t rnd = MMIO32(TRNG_RND);
        for (wait = (rnd & 0x3ffu); wait != 0u; wait--) {
            __asm__ volatile ("" ::: "memory");
        }
    }
#endif

#if LMS_FW_NO_HW_ACCEL

    uint8_t prefix[16u + 4u + 2u];
    uint8_t digest[LMS_N];
    uint32_t idx;
    for (idx = 0u; idx < 16u; idx++) {
        prefix[idx] = uart_getc();
    }
    q = uart_get_u32();
    lms_store_u32(prefix + 16u, q);
    prefix[20u] = 0x85u;
    prefix[21u] = 0x85u;
    if (s_seed_slot_valid == 0u) {
        return 0u;
    }

    {
        uint32_t zi;
        MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
        MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
        MMIO32(LMS_INPUT_LENGTH) = 32u;
        MMIO32(LMS_OUTPUT_LENGTH) = 32u;
        for (zi = 0u; zi < 8u; zi++) {
            MMIO32(LMS_INPUT + 4u * zi) = 0u;
        }
        MMIO32(LMS_CONTROL) = LMS_CTRL_START;
        while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
        }
    }
    (void)lms_hash_parts(prefix, sizeof(prefix), s_seed_slot, LMS_SEED_LEN,
                         NULL, 0u, NULL, 0u, FW_HASH_ALG, digest);
    memcpy(s_uart_msg, digest, LMS_N);
    *cycles = 0u;
    return LMS_STATUS_DONE;
#else
    MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
    MMIO32(LMS_COMMAND) = LMS_CMD_DERIVE_RANDOMIZER;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    uart_read_window(LMS_IDENTIFIER, 16u);
    q = uart_get_u32();
    MMIO32(LMS_ARG_Q) = q;
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
    hardware_hits++;
    return MMIO32(LMS_STATUS);
#endif
}

static uint32_t derive_xq_from_uart(uint32_t *cycles)
{
    uint32_t q;
    uint16_t i;
#if LMS_FW_NO_HW_ACCEL

    uint8_t prefix[16u + 4u + 2u + 1u];
    uint8_t digest[LMS_N];
    uint32_t idx;
    for (idx = 0u; idx < 16u; idx++) {
        prefix[idx] = uart_getc();
    }
    q = uart_get_u32();
    i = uart_get_u16();
    lms_store_u32(prefix + 16u, q);
    prefix[20u] = (uint8_t)(i >> 8u);
    prefix[21u] = (uint8_t)(i & 0xffu);
    prefix[22u] = 0xffu;                     /* u8str(0xff) */
    if (s_seed_slot_valid == 0u) {
        return 0u;
    }

    {
        uint32_t zi;
        MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
        MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
        MMIO32(LMS_INPUT_LENGTH) = 32u;
        MMIO32(LMS_OUTPUT_LENGTH) = 32u;
        for (zi = 0u; zi < 8u; zi++) {
            MMIO32(LMS_INPUT + 4u * zi) = 0u;
        }
        MMIO32(LMS_CONTROL) = LMS_CTRL_START;
        while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
        }
    }
    (void)lms_hash_parts(prefix, sizeof(prefix), s_seed_slot, LMS_SEED_LEN,
                         NULL, 0u, NULL, 0u, FW_HASH_ALG, digest);
    (void)digest;
    *cycles = 0u;
    return LMS_STATUS_DONE;
#else

    MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
    MMIO32(LMS_COMMAND) = LMS_CMD_DERIVE_CHAIN;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    uart_read_window(LMS_IDENTIFIER, 16u);
    q = uart_get_u32();
    i = uart_get_u16();
    MMIO32(LMS_ARG_Q) = q;
    MMIO32(LMS_ARG_I) = (uint32_t)i;
    MMIO32(LMS_ARG_START) = 0u;
    MMIO32(LMS_ARG_STEPS) = 0u;
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
    hardware_hits++;
    return MMIO32(LMS_STATUS);
#endif
}

static uint32_t prf_chain_from_uart(uint32_t *cycles)
{
    uint8_t prefix[16u + 4u + 2u];
    uint8_t digest[LMS_N];
    uint32_t q;
    uint32_t m;
    uint32_t idx;
    uint32_t k;

    for (idx = 0u; idx < 16u; idx++) {
        prefix[idx] = uart_getc();
    }
    q = uart_get_u32();
    m = uart_get_u32();
    if (m == 0u || m > 16u) {
        m = 4u;
    }
    if (s_seed_slot_valid == 0u) {
        return 0u;
    }

    {
        uint32_t zi;
        MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
        MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
        MMIO32(LMS_INPUT_LENGTH) = 32u;
        MMIO32(LMS_OUTPUT_LENGTH) = 32u;
        for (zi = 0u; zi < 8u; zi++) {
            MMIO32(LMS_INPUT + 4u * zi) = 0u;
        }
        MMIO32(LMS_CONTROL) = LMS_CTRL_START;
        while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
        }
    }
    prefix[20u] = 0x85u;
    prefix[21u] = 0x85u;
    for (k = 0u; k < m; k++) {
        lms_store_u32(prefix + 16u, q + k);
        (void)lms_hash_parts(prefix, sizeof(prefix), s_seed_slot, LMS_SEED_LEN,
                             NULL, 0u, NULL, 0u, FW_HASH_ALG, digest);
    }
    memcpy(s_uart_msg, digest, LMS_N);
    *cycles = 0u;
    return LMS_STATUS_DONE;
}

static uint32_t chain_from_uart(uint32_t *cycles)
{
    uint32_t q;
    uint32_t i;
    uint32_t start;
    uint32_t steps;

    MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
    MMIO32(LMS_COMMAND) = LMS_CMD_CHAIN;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    uart_read_window(LMS_IDENTIFIER, 16u);
    q = uart_get_u32();
    i = uart_getc();
    i |= (uint32_t)uart_getc() << 8;
    start = uart_getc();
    steps = uart_getc();
    uart_read_window(LMS_INPUT, 32u);
    MMIO32(LMS_ARG_Q) = q;
    MMIO32(LMS_ARG_I) = i;
    MMIO32(LMS_ARG_START) = start;
    MMIO32(LMS_ARG_STEPS) = steps;
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
    hardware_hits++;
    return MMIO32(LMS_STATUS);
}

#if !LMS_FW_NO_HW_ACCEL

static void set_hw_lmots(int enable);

static int hw_verify_leaf(void *context,
                          const uint8_t I[LMS_I_LEN],
                          lms_hash_alg_t hash_alg,
                          uint32_t q,
                          uint32_t lmots_type,
                          const uint8_t *coefficients,
                          const uint8_t *inputs,
                          uint32_t node_num,
                          uint8_t leaf[LMS_N]);
static int hw_verify_leaf_taskram(void *context,
                                  const uint8_t I[LMS_I_LEN],
                                  lms_hash_alg_t hash_alg,
                                  uint32_t q,
                                  uint32_t lmots_type,
                                  const uint8_t *coefficients,
                                  const uint8_t *inputs,
                                  uint32_t node_num,
                                  uint8_t leaf[LMS_N]);
#endif /* !LMS_FW_NO_HW_ACCEL */

static uint32_t verify_from_uart(uint32_t *cycles, uint32_t *total_cycles)
{
    uint8_t public_key_bytes[LMS_PUBLIC_KEY_LEN];
    uint8_t signature_hdr[40];

    lms_public_key_t public_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    fw_total_clock_t total_start;
    uint32_t message_length;
    uint32_t signature_length;
    uint32_t y_len;
    uint32_t path_len;
    uint32_t ots_type;
    uint32_t lms_type;
    int y_in_taskram = 0;
    int status;

    uart_read_bytes(public_key_bytes, sizeof(public_key_bytes));
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length + LMS_MAX_SIGNATURE_LEN);
        *cycles = 0u;
        *total_cycles = 0u;
        verify_client.last_hw_error = 0u;
        return 0u;
    }
    s_msg_in_ram = 0;
#if !LMS_FW_NO_HW_ACCEL
    if (message_length > 74u) {

        const uint32_t pad = (message_length + 3u) & ~3u;
        if (bridge_run(BRIDGE_DIR_RX, 582u, pad) == 0) {
            s_msg_in_ram = 1;
        } else {
            uart_read_bytes(s_uart_msg, message_length);
        }
    } else
#endif
    {
        uart_read_bytes(s_uart_msg, message_length);
    }

    uart_read_bytes(signature_hdr, sizeof(signature_hdr));

    ots_type = ((uint32_t)signature_hdr[4] << 24) |
               ((uint32_t)signature_hdr[5] << 16) |
               ((uint32_t)signature_hdr[6] << 8) |
               (uint32_t)signature_hdr[7];
    y_len = lmots_y_len_type(ots_type);
    if (y_len == 0u) {

        uart_discard(LMS_MAX_SIGNATURE_LEN - 40u);
        *cycles = 0u;
        *total_cycles = 0u;
        verify_client.last_hw_error = 0u;
        return 0u;
    }
#if !LMS_FW_NO_HW_ACCEL

    set_hw_lmots(lmots_hw_supported(ots_type));
    if (s_msg_in_ram && !lmots_hw_supported(ots_type)) {
        task_read_words(582u, s_uart_msg, message_length);
        s_msg_in_ram = 0;
    }
#if defined(FW_HASH_SHAKE256)
    if (32u + y_len / 4u <= ((message_length <= 74u) ? mqc_msg_base(y_len) : 568u)) {
#else

    if (message_length <= 74u && 32u + y_len / 4u <= mqc_msg_base(y_len)) {
#endif

        if (bridge_run(BRIDGE_DIR_RX, BRIDGE_Y_ADDR, y_len) != 0) {
            *cycles = 0u;
            *total_cycles = 0u;
            return 0u;
        }
        y_in_taskram = 1;
    } else {

        memcpy(s_uart_sig, signature_hdr, sizeof(signature_hdr));
        uart_read_bytes(s_uart_sig + sizeof(signature_hdr), y_len);
    }
#else

    memcpy(s_uart_sig, signature_hdr, sizeof(signature_hdr));
    uart_read_bytes(s_uart_sig + sizeof(signature_hdr), y_len);
#endif

    uart_read_bytes(s_uart_auth_tail, 4u);
    lms_type = ((uint32_t)s_uart_auth_tail[0] << 24) |
               ((uint32_t)s_uart_auth_tail[1] << 16) |
               ((uint32_t)s_uart_auth_tail[2] << 8) |
               (uint32_t)s_uart_auth_tail[3];
    signature_length = lms_signature_len(lms_type, ots_type);
    if (signature_length < 40u + y_len + 4u + LMS_N ||
        signature_length > LMS_MAX_SIGNATURE_LEN) {

        uart_discard(LMS_MAX_SIGNATURE_LEN);
        *cycles = 0u;
        *total_cycles = 0u;
        verify_client.last_hw_error = 0u;
        return 0u;
    }
    path_len = signature_length - (40u + y_len + 4u);
    uart_read_bytes(s_uart_auth_tail + 4u, path_len);

    if (y_in_taskram) {
        memcpy(s_uart_sig, signature_hdr, sizeof(signature_hdr));
    }
    memcpy(s_uart_sig + sizeof(signature_hdr) + y_len, s_uart_auth_tail,
           4u + path_len);

    total_start = fw_total_read();
    count_before = verify_client.hardware_verify_count;
    cycles_before = verify_client.hardware_verify_cycles;
    hash_count_before = verify_client.hardware_hash_once_count;
    hash_cycles_before = verify_client.hardware_hash_once_cycles;
    verify_client.last_hw_error = 0u;
#if !LMS_FW_NO_HW_ACCEL

    if (lmots_hw_supported(ots_type) && y_in_taskram) {
        lmots_verify_leaf_backend_set(hw_verify_leaf_taskram, &verify_client);
    }
#endif
    status = lms_public_key_parse(&public_key, public_key_bytes, sizeof(public_key_bytes));
    if (status == LMS_OK) {
        status = lms_verify(&public_key, s_uart_msg, message_length,
                            s_uart_sig, signature_length);
    }
#if !LMS_FW_NO_HW_ACCEL
    if (lmots_hw_supported(ots_type)) {
        lmots_verify_leaf_backend_set(hw_verify_leaf, &verify_client);
    }
#endif
    hardware_hits += (uint32_t)(verify_client.hardware_verify_count - count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_verify_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_hash_once_cycles - hash_cycles_before);
    fw_total_finish(total_cycles, total_start);
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t sign_from_uart(uint8_t signature[LMS_MAX_SIGNATURE_LEN],
                               uint32_t *signature_length,
                               uint32_t *next_q,
                               uint32_t *cycles,
                               uint32_t *total_cycles,
                               uint32_t *steady_total_cycles,
                               uint32_t *parse_cycles);

#if !LMS_FW_NO_HW_ACCEL

static uint8_t s_tree_arena[3u * sizeof(lms_sublevel_t) + 16384u];
static uint32_t s_tree_arena_used;
static uint8_t *s_tree_pool_last_ptr;
static uint32_t s_tree_pool_last_size;

static void *tree_pool_alloc(void *context, size_t size)
{
    uint32_t aligned;
    void *ptr;
    (void)context;
    aligned = (uint32_t)((size + 3u) & ~((size_t)3u));
    if (s_tree_arena_used + aligned > (uint32_t)sizeof(s_tree_arena)) {
        return NULL;
    }
    ptr = s_tree_arena + s_tree_arena_used;
    s_tree_arena_used += aligned;
    s_tree_pool_last_ptr = (uint8_t *)ptr;
    s_tree_pool_last_size = aligned;
    return ptr;
}

static void tree_pool_free(void *context, void *ptr)
{
    (void)context;
    if (ptr != NULL && (uint8_t *)ptr == s_tree_pool_last_ptr) {
        s_tree_arena_used -= s_tree_pool_last_size;
        s_tree_pool_last_ptr = NULL;
        s_tree_pool_last_size = 0u;
    }
}

static void tree_pool_reset(void)
{
    s_tree_arena_used = 0u;
    s_tree_pool_last_ptr = NULL;
    s_tree_pool_last_size = 0u;
}

static lms_tree_ctx_t s_tree_ctx;
static uint8_t s_tree_key_fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];
static int s_tree_cache_valid;

static void tree_cache_invalidate(void)
{
    lms_auth_path_backend_set(NULL, NULL);
    lms_tree_ctx_free(&s_tree_ctx);
    s_tree_cache_valid = 0;
}

static int hw_keygen_leaf(void *context,
                          const lms_private_key_t *priv,
                          uint32_t q,
                          uint8_t leaf[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    lms_param_t lparam;
    uint32_t node_num;

    if (lms_get_lms_param(priv->lms_type, &lparam) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    node_num = (1u << lparam.height) + q;
    return lms_mmio_lmots_keygen_leaf(client, 0u, priv->I, q, node_num,
                                      priv->lmots_type, leaf, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

static uint8_t hw_msg_hash_buf_small[128];
static uint8_t hw_msg_hash_buf_large[2048];

static int hw_message_hash_backend(void *context,
                                   const uint8_t I[LMS_I_LEN],
                                   lms_hash_alg_t hash_alg,
                                   uint32_t q,
                                   const uint8_t C[LMS_N],
                                   const uint8_t *message,
                                   size_t message_len,
                                   uint8_t Q[LMS_N + 2])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    uint8_t digest[LMS_N];
    (void)hash_alg;

    if (message_len <= 74u) {
        uint8_t *buf = hw_msg_hash_buf_small;
        size_t total = 54u + message_len;
        memcpy(buf, I, LMS_I_LEN);
        lms_store_u32(buf + LMS_I_LEN, q);
        lms_store_u16(buf + LMS_I_LEN + 4, D_MESG);
        memcpy(buf + LMS_I_LEN + 6, C, LMS_N);
        if (message_len > 0u) {
            memcpy(buf + 54, message, message_len);
        }
        if (lms_mmio_hash_once(client, buf, (uint32_t)total,
                               digest, NULL) == LMS_MMIO_OK) {
            memcpy(Q, digest, LMS_N);
            return LMS_OK;
        }

    }

    if (message_len <= 1994u) {
        uint8_t *buf = hw_msg_hash_buf_large;
        size_t total = 54u + message_len;
        memcpy(buf, I, LMS_I_LEN);
        lms_store_u32(buf + LMS_I_LEN, q);
        lms_store_u16(buf + LMS_I_LEN + 4, D_MESG);
        memcpy(buf + LMS_I_LEN + 6, C, LMS_N);
        if (message_len > 0u) {
            memcpy(buf + 54, message, message_len);
        }
        if (lms_mmio_hash_once_ram(client, buf, (uint32_t)total,
                                   digest, NULL) == LMS_MMIO_OK) {
            memcpy(Q, digest, LMS_N);
            return LMS_OK;
        }

    }

    {
        uint8_t prefix[LMS_I_LEN + 4 + 2 + LMS_N];
        memcpy(prefix, I, LMS_I_LEN);
        lms_store_u32(prefix + LMS_I_LEN, q);
        lms_store_u16(prefix + LMS_I_LEN + 4, D_MESG);
        memcpy(prefix + LMS_I_LEN + 6, C, LMS_N);
        if (lms_hash_parts(prefix, sizeof(prefix),
                           message, message_len,
                           NULL, 0, NULL, 0,
                           FW_HASH_ALG, digest) != LMS_OK) {
            return LMS_ERR_INVALID;
        }
        memcpy(Q, digest, LMS_N);
        return LMS_OK;
    }
}

/* Aligned word stores into byte buffers, without violating C aliasing rules. */
typedef uint32_t fw_alias_word_t __attribute__((__may_alias__));

/* W1/W2/W4/W8 each have 32 bytes of Q and nine packed coefficient words.
 * Read real outputs directly and unpack with constant widths for every mode.
 * The last word contains only 9/5/3/2 coefficients (p=265/133/67/34); do not
 * write padding past p. Coefficient addresses do not auto-increment. */
static void hw_coef_read_direct(uint32_t lmots_type,
                                uint8_t Q[LMS_N], uint8_t *coefficients)
{
    uint32_t i;
    if (((uintptr_t)Q & 3u) == 0u) {
        fw_alias_word_t *words = (fw_alias_word_t *)(void *)Q;
        for (i = 0u; i < LMS_N / 4u; i++) {
            words[i] = MMIO32(LMS_OUTPUT + 4u * i);
        }
    } else {
        for (i = 0u; i < LMS_N; i += 4u) {
            uint32_t word = MMIO32(LMS_OUTPUT + i);
            Q[i] = (uint8_t)word;
            Q[i + 1u] = (uint8_t)(word >> 8);
            Q[i + 2u] = (uint8_t)(word >> 16);
            Q[i + 3u] = (uint8_t)(word >> 24);
        }
    }
    if (lmots_type == FW_LMOTS_W1) {
        for (i = 0u; i < 8u; i++) {
            uint32_t word;
            MMIO32(LMS_TASK_ADDR) = i;
            word = MMIO32(LMS_TASK_DATA);
            coefficients[0] = (uint8_t)(word & 1u);
            coefficients[1] = (uint8_t)((word >> 1) & 1u);
            coefficients[2] = (uint8_t)((word >> 2) & 1u);
            coefficients[3] = (uint8_t)((word >> 3) & 1u);
            coefficients[4] = (uint8_t)((word >> 4) & 1u);
            coefficients[5] = (uint8_t)((word >> 5) & 1u);
            coefficients[6] = (uint8_t)((word >> 6) & 1u);
            coefficients[7] = (uint8_t)((word >> 7) & 1u);
            coefficients[8] = (uint8_t)((word >> 8) & 1u);
            coefficients[9] = (uint8_t)((word >> 9) & 1u);
            coefficients[10] = (uint8_t)((word >> 10) & 1u);
            coefficients[11] = (uint8_t)((word >> 11) & 1u);
            coefficients[12] = (uint8_t)((word >> 12) & 1u);
            coefficients[13] = (uint8_t)((word >> 13) & 1u);
            coefficients[14] = (uint8_t)((word >> 14) & 1u);
            coefficients[15] = (uint8_t)((word >> 15) & 1u);
            coefficients[16] = (uint8_t)((word >> 16) & 1u);
            coefficients[17] = (uint8_t)((word >> 17) & 1u);
            coefficients[18] = (uint8_t)((word >> 18) & 1u);
            coefficients[19] = (uint8_t)((word >> 19) & 1u);
            coefficients[20] = (uint8_t)((word >> 20) & 1u);
            coefficients[21] = (uint8_t)((word >> 21) & 1u);
            coefficients[22] = (uint8_t)((word >> 22) & 1u);
            coefficients[23] = (uint8_t)((word >> 23) & 1u);
            coefficients[24] = (uint8_t)((word >> 24) & 1u);
            coefficients[25] = (uint8_t)((word >> 25) & 1u);
            coefficients[26] = (uint8_t)((word >> 26) & 1u);
            coefficients[27] = (uint8_t)((word >> 27) & 1u);
            coefficients[28] = (uint8_t)((word >> 28) & 1u);
            coefficients[29] = (uint8_t)((word >> 29) & 1u);
            coefficients[30] = (uint8_t)((word >> 30) & 1u);
            coefficients[31] = (uint8_t)(word >> 31);
            coefficients += 32;
        }
        MMIO32(LMS_TASK_ADDR) = 8u;
        {
            uint32_t word = MMIO32(LMS_TASK_DATA);
            coefficients[0] = (uint8_t)(word & 1u);
            coefficients[1] = (uint8_t)((word >> 1) & 1u);
            coefficients[2] = (uint8_t)((word >> 2) & 1u);
            coefficients[3] = (uint8_t)((word >> 3) & 1u);
            coefficients[4] = (uint8_t)((word >> 4) & 1u);
            coefficients[5] = (uint8_t)((word >> 5) & 1u);
            coefficients[6] = (uint8_t)((word >> 6) & 1u);
            coefficients[7] = (uint8_t)((word >> 7) & 1u);
            coefficients[8] = (uint8_t)((word >> 8) & 1u);
        }
        return;
    }
    if (lmots_type == FW_LMOTS_W2) {
        for (i = 0u; i < 8u; i++) {
            uint32_t word;
            MMIO32(LMS_TASK_ADDR) = i;
            word = MMIO32(LMS_TASK_DATA);
            coefficients[0] = (uint8_t)(word & 3u);
            coefficients[1] = (uint8_t)((word >> 2) & 3u);
            coefficients[2] = (uint8_t)((word >> 4) & 3u);
            coefficients[3] = (uint8_t)((word >> 6) & 3u);
            coefficients[4] = (uint8_t)((word >> 8) & 3u);
            coefficients[5] = (uint8_t)((word >> 10) & 3u);
            coefficients[6] = (uint8_t)((word >> 12) & 3u);
            coefficients[7] = (uint8_t)((word >> 14) & 3u);
            coefficients[8] = (uint8_t)((word >> 16) & 3u);
            coefficients[9] = (uint8_t)((word >> 18) & 3u);
            coefficients[10] = (uint8_t)((word >> 20) & 3u);
            coefficients[11] = (uint8_t)((word >> 22) & 3u);
            coefficients[12] = (uint8_t)((word >> 24) & 3u);
            coefficients[13] = (uint8_t)((word >> 26) & 3u);
            coefficients[14] = (uint8_t)((word >> 28) & 3u);
            coefficients[15] = (uint8_t)(word >> 30);
            coefficients += 16;
        }
        MMIO32(LMS_TASK_ADDR) = 8u;
        {
            uint32_t word = MMIO32(LMS_TASK_DATA);
            coefficients[0] = (uint8_t)(word & 3u);
            coefficients[1] = (uint8_t)((word >> 2) & 3u);
            coefficients[2] = (uint8_t)((word >> 4) & 3u);
            coefficients[3] = (uint8_t)((word >> 6) & 3u);
            coefficients[4] = (uint8_t)((word >> 8) & 3u);
        }
        return;
    }
    if (lmots_type == FW_LMOTS_W8) {
        for (i = 0u; i < 8u; i++) {
            uint32_t word;
            MMIO32(LMS_TASK_ADDR) = i;
            word = MMIO32(LMS_TASK_DATA);
            coefficients[0] = (uint8_t)word;
            coefficients[1] = (uint8_t)(word >> 8);
            coefficients[2] = (uint8_t)(word >> 16);
            coefficients[3] = (uint8_t)(word >> 24);
            coefficients += 4;
        }
        MMIO32(LMS_TASK_ADDR) = 8u;
        {
            uint32_t word = MMIO32(LMS_TASK_DATA);
            coefficients[0] = (uint8_t)word;
            coefficients[1] = (uint8_t)(word >> 8);
        }
        return;
    }
    /* The caller selects this routine only for W1/W2/W4/W8. Keep the existing
     * fixed-width W4 unpack after the three additional dispatch cases. */
    for (i = 0u; i < 8u; i++) {
        uint32_t word;
        MMIO32(LMS_TASK_ADDR) = i;
        word = MMIO32(LMS_TASK_DATA);
        coefficients[0] = (uint8_t)(word & 15u);
        coefficients[1] = (uint8_t)((word >> 4) & 15u);
        coefficients[2] = (uint8_t)((word >> 8) & 15u);
        coefficients[3] = (uint8_t)((word >> 12) & 15u);
        coefficients[4] = (uint8_t)((word >> 16) & 15u);
        coefficients[5] = (uint8_t)((word >> 20) & 15u);
        coefficients[6] = (uint8_t)((word >> 24) & 15u);
        coefficients[7] = (uint8_t)(word >> 28);
        coefficients += 8;
    }
    MMIO32(LMS_TASK_ADDR) = 8u;
    {
        uint32_t word = MMIO32(LMS_TASK_DATA);
        coefficients[0] = (uint8_t)(word & 15u);
        coefficients[1] = (uint8_t)((word >> 4) & 15u);
        coefficients[2] = (uint8_t)((word >> 8) & 15u);
    }
}

static int hw_coef_backend(void *context,
                           const uint8_t I[LMS_I_LEN],
                           lms_hash_alg_t hash_alg,
                           uint32_t q,
                           const uint8_t C[LMS_N],
                           const uint8_t *message,
                           size_t message_len,
                           uint32_t lmots_type,
                           uint8_t Q[LMS_N],
                           uint8_t coefficients[LMS_MAX_OTS_P])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    const uint8_t *msg = message;
    int direct = (lmots_type == FW_LMOTS_W1 || lmots_type == FW_LMOTS_W2 ||
                  lmots_type == FW_LMOTS_W4 || lmots_type == FW_LMOTS_W8);
    if (!Q || !coefficients || hash_alg != client->hash_desc->hash_alg) {
        client->coef_ready = 0;
        return LMS_ERR_INVALID;
    }
    /* Fulfil the backend contract: successful calls fill both Q and coefficients.
     * Keep the same coefficients resident for the immediately following command. */
    client->coef_ready = 0;
    if (s_msg_in_ram && message_len > 74u) {
        msg = NULL;
    }
    if (lms_mmio_msg_q_coef(client, I, q, C, msg, message_len, lmots_type,
                            direct ? NULL : Q,
                            direct ? NULL : coefficients, NULL) == LMS_MMIO_OK) {
        if (direct) {
            hw_coef_read_direct(lmots_type, Q, coefficients);
        }
        s_msg_in_ram = 0;
        client->coef_ready = 1;
        return LMS_OK;
    }

    if (msg == NULL) {
        task_read_words(582u, (uint8_t *)message, (uint32_t)message_len);
    }
    s_msg_in_ram = 0;
    return LMS_ERR_INVALID;
}

static int hw_intr_backend(void *context,
                           const uint8_t I[LMS_I_LEN],
                           lms_hash_alg_t hash_alg,
                           uint32_t node_num,
                           const uint8_t left[LMS_N],
                           const uint8_t right[LMS_N],
                           uint8_t out[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    uint8_t msg[LMS_I_LEN + 4 + 2 + 2 * LMS_N]; /* 16+4+2+32+32 = 86B */
    (void)hash_alg;
    memcpy(msg, I, LMS_I_LEN);
    lms_store_u32(msg + LMS_I_LEN, node_num);
    lms_store_u16(msg + LMS_I_LEN + 4, D_INTR);
    memcpy(msg + LMS_I_LEN + 6, left, LMS_N);
    memcpy(msg + LMS_I_LEN + 6 + LMS_N, right, LMS_N);
    return lms_mmio_hash_once(client, msg, sizeof(msg), out, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

static int hw_verify_leaf(void *context,
                          const uint8_t I[LMS_I_LEN],
                          lms_hash_alg_t hash_alg,
                          uint32_t q,
                          uint32_t lmots_type,
                          const uint8_t *coefficients,
                          const uint8_t *inputs,
                          uint32_t node_num,
                          uint8_t leaf[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (client->coef_ready) {

        client->coef_ready = 0;
        return lms_mmio_lmots_verify_leaf(client, I, q, node_num, lmots_type,
                                          NULL, inputs, leaf, NULL)
            == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_verify_leaf(client, I, q, node_num, lmots_type,
                                      coefficients, inputs, leaf, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

static int hw_verify_leaf_taskram(void *context,
                                  const uint8_t I[LMS_I_LEN],
                                  lms_hash_alg_t hash_alg,
                                  uint32_t q,
                                  uint32_t lmots_type,
                                  const uint8_t *coefficients,
                                  const uint8_t *inputs,
                                  uint32_t node_num,
                                  uint8_t leaf[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    (void)inputs;
    if (client->coef_ready) {

        client->coef_ready = 0;
        return lms_mmio_lmots_verify_leaf_taskram(client, I, q, node_num, lmots_type,
                                                  NULL, leaf, NULL)
            == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_verify_leaf_taskram(client, I, q, node_num, lmots_type,
                                              coefficients, leaf, NULL)
        == LMS_MMIO_OK ? LMS_OK : LMS_ERR_INVALID;
}

static void task_write_words(uint32_t word_base, const uint8_t *bytes, uint32_t length)
{
    uint32_t i;
    uint32_t word;
    MMIO32(LMS_TASK_ADDR) = word_base;
    (void)MMIO32(LMS_STATUS);
    if ((((uintptr_t)bytes | length) & 3u) == 0u) {
        const fw_alias_word_t *words = (const fw_alias_word_t *)(const void *)bytes;
        for (i = 0u; i < length / 4u; i++) MMIO32(LMS_TASK_DATA) = words[i];
        return;
    }
    for (i = 0u; i < length; i += 4u) {
        word = (uint32_t)bytes[i] | ((uint32_t)bytes[i + 1u] << 8) |
               ((uint32_t)bytes[i + 2u] << 16) | ((uint32_t)bytes[i + 3u] << 24);
        MMIO32(LMS_TASK_DATA) = word;
    }
}

static void task_read_words(uint32_t word_base, uint8_t *bytes, uint32_t length)
{
    uint32_t i;
    if ((((uintptr_t)bytes | length) & 3u) == 0u) {
        fw_alias_word_t *words = (fw_alias_word_t *)(void *)bytes;
        for (i = 0u; i < length / 4u; i++) {
            MMIO32(LMS_TASK_ADDR) = word_base + i;
            (void)MMIO32(LMS_STATUS);
            words[i] = MMIO32(LMS_TASK_DATA);
        }
        return;
    }
    for (i = 0u; i < length; i += 4u) {
        MMIO32(LMS_TASK_ADDR) = word_base + i / 4u;
        (void)MMIO32(LMS_STATUS);
        {
            uint32_t word = MMIO32(LMS_TASK_DATA);
            uint32_t j;
            for (j = 0u; j < 4u && i + j < length; j++) {
                bytes[i + j] = (uint8_t)(word >> (8u * j));
            }
        }
    }
}

static int hw_dintr_authpath(void *context,
                             const uint8_t I[LMS_I_LEN],
                             lms_hash_alg_t hash_alg,
                             uint32_t node_num,
                             const uint8_t *leaf,
                             const uint8_t *path,
                             uint32_t height,
                             uint8_t root[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    uint32_t i;
    (void)hash_alg;

    task_write_words(32u, leaf, (uint32_t)LMS_N);
    task_write_words(40u, path, height * (uint32_t)LMS_N);

    for (i = 0u; i < (uint32_t)LMS_I_LEN; i += 4u) {
        MMIO32(LMS_IDENTIFIER + i) = (uint32_t)I[i] | ((uint32_t)I[i + 1u] << 8) |
                                     ((uint32_t)I[i + 2u] << 16) | ((uint32_t)I[i + 3u] << 24);
    }
    MMIO32(LMS_ARG_LEAF_NODE) = node_num;
    MMIO32(LMS_ARG_STEPS) = height;
    MMIO32(LMS_COMMAND) = LMS_CMD_D_INTR_CHAIN;
    MMIO32(LMS_OUTPUT_LENGTH) = (uint32_t)LMS_N;
    (void)MMIO32(LMS_STATUS);
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;
    {
        uint32_t busy_guard = 2000000u;
        while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
            if (--busy_guard == 0u) {
                client->last_hw_error = 0xEEu;
                return LMS_ERR_INVALID;
            }
        }
    }
    if ((MMIO32(LMS_STATUS) & LMS_STATUS_DONE) == 0u || MMIO32(LMS_ERROR) != 0u) {
        client->last_hw_error = (uint8_t)MMIO32(LMS_ERROR);
        return LMS_ERR_INVALID;
    }

    client->hardware_hash_once_count++;
    client->hardware_hash_once_cycles += (uint64_t)MMIO32(LMS_CYCLE_COUNT);
    for (i = 0u; i < (uint32_t)LMS_N; i += 4u) {
        uint32_t w = MMIO32(LMS_OUTPUT + i);
        root[i] = (uint8_t)w;
        root[i + 1u] = (uint8_t)(w >> 8);
        root[i + 2u] = (uint8_t)(w >> 16);
        root[i + 3u] = (uint8_t)(w >> 24);
    }
    return LMS_OK;
}

/* Ordinary Sign uses the established C source priority, with deterministic
 * hardware derivation when no C_LOAD slot or TRNG callback is configured. */
static int hw_sign_randomizer(void *context,
                              const uint8_t I[LMS_I_LEN],
                              lms_hash_alg_t hash_alg,
                              uint32_t q,
                              uint8_t output[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (client->randomizer_c_slot != NULL) {
        memcpy(output, client->randomizer_c_slot, LMS_N);
        return LMS_OK;
    }
    if (client->trng_fill_c != NULL) {
        return client->trng_fill_c(client->trng_context, output) == 0
            ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_derive_randomizer(client, client->key_handle, I, q,
                                     output, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

/* Read the completed signature into CPU memory before any other command can
 * reuse task RAM. VERSION 7+ auto-increments DATA reads at addresses >=32.
 * All copies remain inside the ordinary Sign total/steady timing windows. */
static void hw_sign_read_y(uint8_t *outputs, uint32_t length)
{
    uint32_t i;
    MMIO32(LMS_TASK_ADDR) = BRIDGE_Y_ADDR;
    if (((uintptr_t)outputs & 3u) == 0u) {
        fw_alias_word_t *words = (fw_alias_word_t *)(void *)outputs;
        uint32_t count = length / 4u;
        while (count >= 4u) {
            words[0] = MMIO32(LMS_TASK_DATA);
            words[1] = MMIO32(LMS_TASK_DATA);
            words[2] = MMIO32(LMS_TASK_DATA);
            words[3] = MMIO32(LMS_TASK_DATA);
            words += 4;
            count -= 4u;
        }
        while (count != 0u) {
            *words++ = MMIO32(LMS_TASK_DATA);
            count--;
        }
    } else {
        for (i = 0u; i < length; i += 4u) {
            uint32_t word = MMIO32(LMS_TASK_DATA);
            outputs[i] = (uint8_t)word;
            outputs[i + 1u] = (uint8_t)(word >> 8);
            outputs[i + 2u] = (uint8_t)(word >> 16);
            outputs[i + 3u] = (uint8_t)(word >> 24);
        }
    }
}

/* Full-buffer SIGN backend, with direct sequential task-RAM word readback. */
static int hw_sign(void *context,
                   const uint8_t I[LMS_I_LEN],
                   lms_hash_alg_t hash_alg,
                   uint32_t q,
                   uint32_t lmots_type,
                   const uint8_t *coefficients,
                   uint8_t *outputs)
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    lmots_param_t param;
    int status;
    const uint8_t *command_coefficients = client->coef_ready ? NULL : coefficients;
    client->coef_ready = 0;
    if (!outputs || hash_alg != client->hash_desc->hash_alg ||
        lms_get_lmots_param(lmots_type, &param) != LMS_OK ||
        param.hash_alg != hash_alg || param.n != LMS_N) {
        return LMS_ERR_INVALID;
    }
#if LMS_SIGN_RESULT_STREAM
    /* R6 Stage 2: read committed y chains from the result window while the
     * engine is still computing later pairs; returns only with a full y. */
    status = lms_mmio_lmots_sign_stream(client, client->key_handle, I, q,
                                        lmots_type, command_coefficients,
                                        outputs, NULL);
    if (status != LMS_MMIO_OK) {
        return LMS_ERR_INVALID;
    }
    return LMS_OK;
#else
    status = lms_mmio_lmots_sign_taskram(client, client->key_handle, I, q,
                                        lmots_type, command_coefficients, NULL);
    if (status != LMS_MMIO_OK) {
        return LMS_ERR_INVALID;
    }
    hw_sign_read_y(outputs, (uint32_t)param.p * (uint32_t)param.n);
    return LMS_OK;
#endif
}

static int hw_sign_taskram(void *context,
                           const uint8_t I[LMS_I_LEN],
                           lms_hash_alg_t hash_alg,
                           uint32_t q,
                           uint32_t lmots_type,
                           const uint8_t *coefficients,
                           uint8_t *outputs)
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    lmots_param_t sign_param;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (lms_get_lmots_param(lmots_type, &sign_param) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    if (lms_mmio_lmots_sign_taskram(client, client->key_handle, I, q, lmots_type,
                                    client->coef_ready ? NULL : coefficients, NULL)
        != LMS_MMIO_OK) {
        client->coef_ready = 0;
        return LMS_ERR_INVALID;
    }
    client->coef_ready = 0;

    task_read_words(BRIDGE_Y_ADDR, outputs, (uint32_t)sign_param.p * (uint32_t)sign_param.n);
    return LMS_OK;
}

#if !LMS_FW_NO_HW_ACCEL
static int s_hw_lmots_enabled = 1;

static void set_hw_lmots(int enable)
{
    if (!enable) {

        lms_mmio_lmots_keygen_disable();

    lmots_sign_backend_set(NULL, NULL);
    lmots_sign_derive_backend_set(NULL, NULL);
    lmots_sign_randomizer_backend_set(NULL, NULL);

    lmots_keygen_backend_set(NULL, NULL);
    lmots_keygen_derive_backend_set(NULL, NULL);
        lms_mmio_lmots_verify_disable();
        lmots_verify_leaf_backend_set(NULL, NULL);
        lmots_coef_backend_set(NULL, NULL);
        s_hw_lmots_enabled = 0;
        return;
    }

    lmots_sign_backend_set(NULL, NULL);
    lmots_sign_derive_backend_set(NULL, NULL);
    lmots_sign_randomizer_backend_set(NULL, NULL);

    lmots_keygen_derive_backend_set(NULL, NULL);

    lmots_keygen_backend_set(NULL, NULL);

    if (enable == s_hw_lmots_enabled) {
        return;
    }
    if (lms_mmio_lmots_keygen_enable_insecure(&verify_client) == LMS_MMIO_OK &&
        lms_mmio_lmots_verify_enable(&verify_client) == LMS_MMIO_OK &&
        lms_mmio_lmots_sign_enable_insecure(&verify_client) == LMS_MMIO_OK) {
        lmots_verify_leaf_backend_set(hw_verify_leaf, &verify_client);
        lmots_coef_backend_set(hw_coef_backend, &verify_client);

        lmots_sign_backend_set(NULL, NULL);
        lmots_sign_derive_backend_set(NULL, NULL);
        lmots_sign_randomizer_backend_set(NULL, NULL);

        lmots_keygen_derive_backend_set(NULL, NULL);
        lmots_keygen_backend_set(NULL, NULL);
        s_hw_lmots_enabled = 1;
    }
}
#endif /* !LMS_FW_NO_HW_ACCEL */

/* Bind the ordinary tree cache: 1=ready, 0=unavailable, -1=runtime failure.
 * This candidate rejects either failure instead of using recursive software. */

#define TREE_MEMORY_TARGET 12288u
/* Single-core measurement candidate: ordinary trees must use fused LEAF.
 * No fallback is accepted; standalone OTS KeyGen also uses one fused command. */
#define LMS_HW_KEYGEN_LEAF_ENABLE 1

#define LMS_SIGN_USE_TASKRAM 0

static int tree_cache_hit(const lms_private_key_t *priv)
{
    uint8_t fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];

    memcpy(fingerprint, priv->I, LMS_I_LEN);
    memcpy(fingerprint + LMS_I_LEN, priv->seed, LMS_SEED_LEN);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN, priv->lms_type);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN + 4u, priv->lmots_type);
    return s_tree_cache_valid &&
           memcmp(s_tree_key_fingerprint, fingerprint, sizeof(fingerprint)) == 0;
}

static int tree_cache_ensure(const lms_private_key_t *priv)
{
    lms_tree_config_t cfg;
    uint8_t fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];

    /* 0 means unavailable; -1 means initialization or execution failed. */
    if (!LMS_HW_KEYGEN_LEAF_ENABLE || !lmots_hw_supported(priv->lmots_type) ||
        !(verify_client.capabilities & LMS_MMIO_CAP_LMOTS_KEYGEN_LEAF)) {
        return 0;
    }

    keygen_trace(6u);  /* 0xA6: tree_cache_ensure entry */

    memcpy(fingerprint, priv->I, LMS_I_LEN);
    memcpy(fingerprint + LMS_I_LEN, priv->seed, LMS_SEED_LEN);

    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN, priv->lms_type);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN + 4u, priv->lmots_type);

    if (s_tree_cache_valid &&
        memcmp(s_tree_key_fingerprint, fingerprint, sizeof(fingerprint)) == 0) {
        return 1;
    }

    tree_cache_invalidate();
    if (lms_tree_configure(priv->lms_type, TREE_MEMORY_TARGET, &cfg) != LMS_OK ||
        cfg.subtree_size != 5u ||
        cfg.est_memory +
            (uint64_t)cfg.sublevels * (uint64_t)sizeof(lms_sublevel_t) >
            (uint64_t)sizeof(s_tree_arena)) {
        return 0;
    }
    tree_pool_reset();
    if (lms_tree_ctx_init(&s_tree_ctx, &cfg, priv->I, NULL, NULL,
                          tree_pool_alloc, tree_pool_free, NULL) != LMS_OK) {
        return -1;
    }
    /* The capability was checked above; each true leaf is one fused command. */
    lms_subtree_set_leaf_fn(&s_tree_ctx, hw_keygen_leaf, &verify_client);
    lms_intr_backend_set(hw_intr_backend, &verify_client);
    keygen_trace(7u);  /* 0xA7: before lms_tree_sign_init */
    if (lms_tree_sign_init(&s_tree_ctx, priv) != LMS_OK) {
        tree_cache_invalidate();
        return -1;
    }
    keygen_trace(8u);  /* 0xA8: lms_tree_sign_init done */
    memcpy(s_tree_key_fingerprint, fingerprint, sizeof(fingerprint));
    s_tree_cache_valid = 1;
    lms_auth_path_backend_set(lms_subtree_auth_path_backend, &s_tree_ctx);
    return 1;
}

#if LMS_FW_PAPER_ROOT_ONLY
/* Root-only KeyGen uses the same fused leaf/internal-hash callbacks and j=5
 * workspace, but does not build or retain signing caches. */
static int paper_keygen_root(const lms_private_key_t *priv, uint8_t root[LMS_N])
{
    lms_tree_config_t cfg;
    int rc;
    tree_cache_invalidate();
    if (lms_tree_configure(priv->lms_type, TREE_MEMORY_TARGET, &cfg) != LMS_OK ||
        cfg.subtree_size != 5u || cfg.est_memory +
        (uint64_t)cfg.sublevels * sizeof(lms_sublevel_t) > sizeof(s_tree_arena))
        return LMS_ERR_INVALID;
    tree_pool_reset();
    if (lms_tree_ctx_init(&s_tree_ctx, &cfg, priv->I, NULL, NULL,
                         tree_pool_alloc, tree_pool_free, NULL) != LMS_OK)
        return LMS_ERR_INVALID;
    lms_subtree_set_leaf_fn(&s_tree_ctx, hw_keygen_leaf, &verify_client);
    lms_intr_backend_set(hw_intr_backend, &verify_client);
    rc = lms_tree_keygen_root(&s_tree_ctx, priv, root);
    tree_cache_invalidate();
    return rc;
}
#endif

static lms_tree_ctx_t s_sec_tree_ctx;
static uint8_t s_sec_tree_fingerprint[LMS_I_LEN + 8u]; /* I + lms_type + lmots_type */
static int s_sec_tree_valid;

static void sec_tree_cache_invalidate(void)
{
    lms_tree_ctx_free(&s_sec_tree_ctx);
    s_sec_tree_valid = 0;
}

static int sec_tree_cache_ensure(const lms_private_key_t *priv)
{
    lms_tree_config_t cfg;
    uint8_t fingerprint[LMS_I_LEN + 8u];

    memcpy(fingerprint, priv->I, LMS_I_LEN);
    lms_store_u32(fingerprint + LMS_I_LEN, priv->lms_type);
    lms_store_u32(fingerprint + LMS_I_LEN + 4u, priv->lmots_type);

    if (s_sec_tree_valid &&
        memcmp(s_sec_tree_fingerprint, fingerprint, sizeof(fingerprint)) == 0) {
        return 1;
    }

    sec_tree_cache_invalidate();
    if (lms_tree_configure(priv->lms_type, TREE_MEMORY_TARGET, &cfg) != LMS_OK ||
        cfg.subtree_size != 5u ||
        cfg.est_memory +
            (uint64_t)cfg.sublevels * (uint64_t)sizeof(lms_sublevel_t) >
            (uint64_t)sizeof(s_tree_arena)) {
        return 0;
    }
    tree_pool_reset();
    if (lms_tree_ctx_init(&s_sec_tree_ctx, &cfg, priv->I, NULL, NULL,
                          tree_pool_alloc, tree_pool_free, NULL) != LMS_OK) {
        return 0;
    }

    if (lmots_hw_supported(priv->lmots_type)) {
        lms_subtree_set_leaf_fn(&s_sec_tree_ctx, hw_keygen_leaf, &verify_client);
    } else {
        sec_tree_cache_invalidate();
        return 0;
    }
    lms_intr_backend_set(hw_intr_backend, &verify_client);
    if (lms_tree_sign_init(&s_sec_tree_ctx, priv) != LMS_OK) {
        sec_tree_cache_invalidate();
        return 0;
    }
    memcpy(s_sec_tree_fingerprint, fingerprint, sizeof(fingerprint));
    s_sec_tree_valid = 1;
    return 1;
}
#endif

#if LMS_FW_NO_HW_ACCEL

#define TREE_MEMORY_TARGET 12288u
static lms_tree_ctx_t s_sw_tree_ctx;
static uint8_t s_sw_tree_fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];
static int s_sw_tree_valid;

static uint8_t s_sw_arena[3u * sizeof(lms_sublevel_t) + 16384u];
static uint32_t s_sw_arena_used;
static uint8_t *s_sw_pool_last_ptr;
static uint32_t s_sw_pool_last_size;

static void *sw_pool_alloc(void *context, size_t size)
{
    uint32_t aligned;
    void *ptr;
    (void)context;
    aligned = (uint32_t)((size + 3u) & ~((size_t)3u));
    if (s_sw_arena_used + aligned > (uint32_t)sizeof(s_sw_arena)) {
        return NULL;
    }
    ptr = s_sw_arena + s_sw_arena_used;
    s_sw_arena_used += aligned;
    s_sw_pool_last_ptr = (uint8_t *)ptr;
    s_sw_pool_last_size = aligned;
    return ptr;
}

static void sw_pool_free(void *context, void *ptr)
{
    (void)context;
    if (ptr != NULL && (uint8_t *)ptr == s_sw_pool_last_ptr) {
        s_sw_arena_used -= s_sw_pool_last_size;
        s_sw_pool_last_ptr = NULL;
        s_sw_pool_last_size = 0u;
    }
}

static void sw_pool_reset(void)
{
    s_sw_arena_used = 0u;
    s_sw_pool_last_ptr = NULL;
    s_sw_pool_last_size = 0u;
}

static int tree_cache_ensure(const lms_private_key_t *priv)
{
    lms_tree_config_t cfg;
    uint8_t fingerprint[LMS_I_LEN + LMS_SEED_LEN + 8u];

    keygen_trace(6u);  /* 0xA6: tree_cache_ensure entry */

    memcpy(fingerprint, priv->I, LMS_I_LEN);
    memcpy(fingerprint + LMS_I_LEN, priv->seed, LMS_SEED_LEN);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN, priv->lms_type);
    lms_store_u32(fingerprint + LMS_I_LEN + LMS_SEED_LEN + 4u, priv->lmots_type);

    if (s_sw_tree_valid &&
        memcmp(s_sw_tree_fingerprint, fingerprint, sizeof(fingerprint)) == 0) {
        return 1;
    }
    lms_auth_path_backend_set(NULL, NULL);
    lms_tree_ctx_free(&s_sw_tree_ctx);
    s_sw_tree_valid = 0;
    if (lms_tree_configure(priv->lms_type, TREE_MEMORY_TARGET, &cfg) != LMS_OK ||
        cfg.subtree_size != 5u ||
        cfg.est_memory +
            (uint64_t)cfg.sublevels * (uint64_t)sizeof(lms_sublevel_t) >
            (uint64_t)sizeof(s_sw_arena)) {
        return 0;
    }
    sw_pool_reset();
    if (lms_tree_ctx_init(&s_sw_tree_ctx, &cfg, priv->I, NULL, NULL,
                          sw_pool_alloc, sw_pool_free, NULL) != LMS_OK) {
        return 0;
    }
    if (lms_tree_sign_init(&s_sw_tree_ctx, priv) != LMS_OK) {
        lms_tree_ctx_free(&s_sw_tree_ctx);
        s_sw_tree_valid = 0;
        return 0;
    }
    memcpy(s_sw_tree_fingerprint, fingerprint, sizeof(fingerprint));
    s_sw_tree_valid = 1;
    lms_auth_path_backend_set(lms_subtree_auth_path_backend, &s_sw_tree_ctx);
    return 1;
}
#endif

static uint32_t sign_from_uart(uint8_t signature[LMS_MAX_SIGNATURE_LEN],
                               uint32_t *signature_length,
                               uint32_t *next_q,
                               uint32_t *cycles,
                               uint32_t *total_cycles,
                               uint32_t *steady_total_cycles,
                               uint32_t *parse_cycles)
{
    uint8_t private_key_bytes[LMS_PRIVATE_KEY_LEN];

    lms_private_key_t private_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t sign_count_before;
    uint64_t sign_cycles_before;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    fw_total_clock_t total_start;
    fw_total_clock_t steady_start;
    uint32_t parse_start;
    uint32_t expected_sig_len;
    uint32_t message_length;
    size_t written = 0u;
    int status;

    uart_read_bytes(private_key_bytes, sizeof(private_key_bytes));
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length);
        *signature_length = 0u;
        *next_q = 0u;
        *cycles = 0u;
        *total_cycles = 0u;
        *steady_total_cycles = 0u;
        *parse_cycles = 0u;
        verify_client.last_hw_error = 0u;
        return 0u;
    }
    s_msg_in_ram = 0;
#if !LMS_FW_NO_HW_ACCEL
    if (message_length > 74u) {

        const uint32_t pad = (message_length + 3u) & ~3u;
        if (bridge_run(BRIDGE_DIR_RX, 582u, pad) == 0) {
            s_msg_in_ram = 1;
        } else {
            uart_read_bytes(s_uart_msg, message_length);
        }
    } else
#endif
    {
        uart_read_bytes(s_uart_msg, message_length);
    }

#if LMS_FW_NO_HW_ACCEL

    if (s_seed_slot_valid) {
        memcpy(private_key_bytes + 24u, s_seed_slot, LMS_SEED_LEN);
    }
#endif

    total_start = fw_total_read();
    verify_client.last_hw_error = 0u;
    *next_q = 0u;
    parse_start = MMIO32(SOC_CYCLE_COUNT);
    status = lms_private_key_parse(&private_key, private_key_bytes, sizeof(private_key_bytes));
    *parse_cycles = MMIO32(SOC_CYCLE_COUNT) - parse_start;
    if (status == LMS_OK) {
#if !LMS_FW_NO_HW_ACCEL

        set_hw_lmots(lmots_hw_supported(private_key.lmots_type));

        if (s_msg_in_ram &&
            (!lmots_hw_supported(private_key.lmots_type) ||
             !tree_cache_hit(&private_key))) {
            task_read_words(582u, s_uart_msg, message_length);
            s_msg_in_ram = 0;
        }

        if (fw_seed_load(private_key.seed) != LMS_MMIO_OK) {
            g_keygen_stage = 0xe0u;
            *signature_length = 0u;
            *next_q = 0u;
            *cycles = 0u;
            *steady_total_cycles = 0u;
            fw_total_finish(total_cycles, total_start);
            return 0u;
        }

        {
            int tree_rc = tree_cache_ensure(&private_key);
            if (tree_rc != 1) {
                g_keygen_stage = tree_rc == 0 ? 0xe1u : 0xe2u;
                *signature_length = 0u;
                *next_q = 0u;
                *cycles = 0u;
                *steady_total_cycles = 0u;
                fw_total_finish(total_cycles, total_start);
                return 0u;
            }
        }
#else

#if !LMS_FW_NO_TREE_CACHE
        if (tree_cache_ensure(&private_key) != 1) {
            g_keygen_stage = 0xe2u;
            *signature_length = 0u;
            *next_q = 0u;
            *cycles = 0u;
            *steady_total_cycles = 0u;
            fw_total_finish(total_cycles, total_start);
            return 0u;
        }
#endif
#endif
        expected_sig_len = (uint32_t)lms_signature_len(private_key.lms_type,
                                                       private_key.lmots_type);
#if LMS_FW_NO_HW_ACCEL

        {
            uint32_t tzi;
            MMIO32(LMS_CONTROL) = LMS_CTRL_CLEAR;
            MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
            MMIO32(LMS_INPUT_LENGTH) = 32u;
            MMIO32(LMS_OUTPUT_LENGTH) = 32u;
            for (tzi = 0u; tzi < 8u; tzi++) {
                MMIO32(LMS_INPUT + 4u * tzi) = 0u;
            }
            MMIO32(LMS_CONTROL) = LMS_CTRL_START;
            while ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) != 0u) {
            }
        }
#endif
        steady_start = fw_total_read();
        count_before = verify_client.hardware_chain_count;
        cycles_before = verify_client.hardware_chain_cycles;
        derive_count_before = verify_client.hardware_derive_count;
        derive_cycles_before = verify_client.hardware_derive_cycles;
        sign_count_before = verify_client.hardware_sign_count;
        sign_cycles_before = verify_client.hardware_sign_cycles;
        keygen_count_before = verify_client.hardware_keygen_count;
        keygen_cycles_before = verify_client.hardware_keygen_cycles;
        hash_count_before = verify_client.hardware_hash_once_count;
        hash_cycles_before = verify_client.hardware_hash_once_cycles;
        /* Keep the complete signature in CPU memory before auth-path updates.
         * The standard MMIO backend uses sequential task-RAM word readback. */
        sign_y_in_taskram = 0u;
#if !LMS_FW_NO_HW_ACCEL
        if (lmots_hw_supported(private_key.lmots_type)) {
            lmots_sign_backend_set(hw_sign, &verify_client);
            lmots_sign_randomizer_backend_set(hw_sign_randomizer, &verify_client);
        } else {
            lmots_sign_backend_set(NULL, NULL);
            lmots_sign_randomizer_backend_set(NULL, NULL);
        }

        if (s_msg_in_ram) {
            task_read_words(582u, s_uart_msg, message_length);
            s_msg_in_ram = 0;
        }
#endif /* !LMS_FW_NO_HW_ACCEL: software receives its message directly. */
        status = lms_sign(&private_key, s_uart_msg, message_length,
                          signature, LMS_MAX_SIGNATURE_LEN, &written);
#if !LMS_FW_NO_HW_ACCEL
        lmots_sign_backend_set(NULL, NULL);
        lmots_sign_randomizer_backend_set(NULL, NULL);
#endif
        *next_q = private_key.q;
        fw_steady_finish(steady_total_cycles, steady_start);
    } else {
        expected_sig_len = 0u;
        count_before = verify_client.hardware_chain_count;
        cycles_before = verify_client.hardware_chain_cycles;
        derive_count_before = verify_client.hardware_derive_count;
        derive_cycles_before = verify_client.hardware_derive_cycles;
        sign_count_before = verify_client.hardware_sign_count;
        sign_cycles_before = verify_client.hardware_sign_cycles;
        keygen_count_before = verify_client.hardware_keygen_count;
        keygen_cycles_before = verify_client.hardware_keygen_cycles;
        hash_count_before = verify_client.hardware_hash_once_count;
        hash_cycles_before = verify_client.hardware_hash_once_cycles;
        *steady_total_cycles = 0u;
    }
    hardware_hits += (uint32_t)(verify_client.hardware_chain_count - count_before)
                   + (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_sign_count - sign_count_before)
                   + (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_chain_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before)
            + (uint32_t)(verify_client.hardware_sign_cycles - sign_cycles_before)
            + (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before)
            + (uint32_t)(verify_client.hardware_hash_once_cycles - hash_cycles_before);
    fw_total_finish(total_cycles, total_start);
    *signature_length = (uint32_t)written;
    return status == LMS_OK && written == (size_t)expected_sig_len ? LMS_STATUS_DONE : 0u;
}

static uint32_t keygen_from_uart(uint8_t public_key_bytes[LMS_PUBLIC_KEY_LEN],
                                 uint32_t *public_key_length,
                                 uint32_t *cycles,
                                 uint32_t *total_cycles)
{
    uint8_t private_key_bytes[LMS_PRIVATE_KEY_LEN];
    lms_private_key_t private_key;
    lms_public_key_t public_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    fw_total_clock_t total_start;
    int status;

    keygen_trace(10u);  /* 0xAA: keygen_from_uart entry */
    uart_read_bytes(private_key_bytes, sizeof(private_key_bytes));
    keygen_trace(11u);  /* 0xAB: private-key read done */
#if LMS_FW_NO_HW_ACCEL

    if (s_seed_slot_valid) {
        memcpy(private_key_bytes + 24u, s_seed_slot, LMS_SEED_LEN);
    }
#endif
    total_start = fw_total_read();
    count_before = verify_client.hardware_chain_count;
    cycles_before = verify_client.hardware_chain_cycles;
    derive_count_before = verify_client.hardware_derive_count;
    derive_cycles_before = verify_client.hardware_derive_cycles;
    keygen_count_before = verify_client.hardware_keygen_count;
    keygen_cycles_before = verify_client.hardware_keygen_cycles;
    hash_count_before = verify_client.hardware_hash_once_count;
    hash_cycles_before = verify_client.hardware_hash_once_cycles;
    verify_client.last_hw_error = 0u;
    *public_key_length = 0u;
    status = lms_private_key_parse(&private_key, private_key_bytes, sizeof(private_key_bytes));
    keygen_trace(12u);  /* 0xAC: private-key parse returned */
    if (status == LMS_OK) {
#if !LMS_FW_NO_HW_ACCEL

        set_hw_lmots(lmots_hw_supported(private_key.lmots_type));
        g_keygen_stage = 20u;
        keygen_trace(0u);

        if (fw_seed_load(private_key.seed) != LMS_MMIO_OK) {
            g_keygen_stage = 0xe0u;
            *cycles = 0u;
            fw_total_finish(total_cycles, total_start);
            return 0u;
        }
        g_keygen_stage = 21u;
        keygen_trace(1u);
        /* Strict fused tree build; failure never enters software recursion. */
        g_keygen_stage = 22u;
        keygen_trace(2u);
#if LMS_FW_PAPER_ROOT_ONLY
        int tree_rc = paper_keygen_root(&private_key, public_key.root) == LMS_OK ? 1 : -1;
#else
        int tree_rc = tree_cache_ensure(&private_key);
#endif
        if (tree_rc == 1) {
            g_keygen_stage = 23u;
            keygen_trace(3u);
#if !LMS_FW_PAPER_ROOT_ONLY
            lms_sublevel_t *top = &s_tree_ctx.levels[s_tree_ctx.sublevels - 1u];
            memcpy(public_key.root,
                   top->active.nodes + (size_t)1u * LMS_N, LMS_N);
#endif

            public_key.lms_type = private_key.lms_type;
            public_key.lmots_type = private_key.lmots_type;
            memcpy(public_key.I, private_key.I, LMS_I_LEN);
            status = LMS_OK;
        } else {
            g_keygen_stage = tree_rc == 0 ? 0xe1u : 0xe2u;
            keygen_trace(4u);
            status = LMS_ERR_INVALID;
        }
        if (status == LMS_OK) g_keygen_stage = 25u;
        keygen_trace(5u);
#else

#if !LMS_FW_NO_TREE_CACHE
        if (tree_cache_ensure(&private_key)) {
            lms_sublevel_t *top = &s_sw_tree_ctx.levels[s_sw_tree_ctx.sublevels - 1u];
            memcpy(public_key.root,
                   top->active.nodes + (size_t)1u * LMS_N, LMS_N);
            public_key.lms_type = private_key.lms_type;
            public_key.lmots_type = private_key.lmots_type;
            memcpy(public_key.I, private_key.I, LMS_I_LEN);
            status = LMS_OK;
        } else {
            g_keygen_stage = 0xe2u;
            status = LMS_ERR_INVALID;
        }
#else
        status = lms_public_key_generate(&private_key, &public_key);
#endif
#endif
    }
    if (status == LMS_OK) {
        status = lms_public_key_serialize(&public_key, public_key_bytes, LMS_PUBLIC_KEY_LEN);
    }
    hardware_hits += (uint32_t)(verify_client.hardware_chain_count - count_before)
                   + (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_chain_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before)
            + (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before)
            + (uint32_t)(verify_client.hardware_hash_once_cycles - hash_cycles_before);
    fw_total_finish(total_cycles, total_start);
    if (status == LMS_OK) {
        *public_key_length = LMS_PUBLIC_KEY_LEN;
        return LMS_STATUS_DONE;
    }
    return 0u;
}

static uint32_t lmots_keygen_from_uart(uint8_t public_key[LMS_N], uint32_t *cycles,
                                       uint32_t *total_cycles)
{
    uint8_t private_key_bytes[LMS_PRIVATE_KEY_LEN];
    lms_private_key_t private_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    fw_total_clock_t total_start;
    int status;

    uart_read_bytes(private_key_bytes, sizeof(private_key_bytes));
    stage_ping(1);
    total_start = fw_total_read();
    count_before = verify_client.hardware_chain_count;
    cycles_before = verify_client.hardware_chain_cycles;
    derive_count_before = verify_client.hardware_derive_count;
    derive_cycles_before = verify_client.hardware_derive_cycles;
    keygen_count_before = verify_client.hardware_keygen_count;
    keygen_cycles_before = verify_client.hardware_keygen_cycles;
    verify_client.last_hw_error = 0u;
    status = lms_private_key_parse(&private_key, private_key_bytes, sizeof(private_key_bytes));
    if (status == LMS_OK) {
        stage_ping(2);
#if !LMS_FW_NO_HW_ACCEL

        set_hw_lmots(lmots_hw_supported(private_key.lmots_type));
        stage_ping(3);

        if (fw_seed_load(private_key.seed) != LMS_MMIO_OK) {
            g_keygen_stage = 0xe0u;
            memset(public_key, 0, LMS_N);
            *cycles = 0u;
            fw_total_finish(total_cycles, total_start);
            return 0u;
        }
        stage_ping(4);
#endif
        stage_ping(5);
#if !LMS_FW_NO_HW_ACCEL
        /* One fused OTS command, independent of set_hw_lmots fallback callbacks. */
        g_keygen_stage = 26u;
        status = lms_mmio_lmots_keygen(&verify_client, 0u, private_key.I,
                                     private_key.q, private_key.lmots_type,
                                     public_key, NULL) == LMS_MMIO_OK
            ? LMS_OK : LMS_ERR_INVALID;
        g_keygen_stage = status == LMS_OK ? 27u : 0xe3u;
#else
        status = lmots_public_from_private(&private_key, private_key.q, public_key);
#endif
        stage_ping(status == LMS_OK ? 6u : 7u);
    }
    stage_ping(8);
    hardware_hits += (uint32_t)(verify_client.hardware_chain_count - count_before)
                   + (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before);
    *cycles = (uint32_t)(verify_client.hardware_chain_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before)
            + (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before);
    fw_total_finish(total_cycles, total_start);
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t lmots_sign_from_uart(uint8_t signature[LMS_MAX_OTS_SIG_LEN],
                                     uint32_t *cycles, uint32_t *total_cycles,
                                     uint32_t *parse_cycles, uint32_t *sign_cycles,
                                     uint32_t *steady_total_cycles)
{
    uint8_t private_key_bytes[LMS_PRIVATE_KEY_LEN];

#if !LMS_FW_NO_HW_ACCEL
    uint8_t C[LMS_N];
    uint8_t coefficients[LMS_MAX_OTS_P];
#endif
    lms_private_key_t private_key;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t sign_count_before;
    uint64_t sign_cycles_before;
    fw_total_clock_t total_start;
    fw_total_clock_t steady_start;
    uint32_t parse_start;
    uint32_t sign_start;
    uint32_t message_length;
    int status;

    uart_read_bytes(private_key_bytes, sizeof(private_key_bytes));
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length);
        *cycles = 0u;
        *total_cycles = 0u;
        *parse_cycles = 0u;
        *sign_cycles = 0u;
        *steady_total_cycles = 0u;
        sign_y_in_taskram = 0u;
        lmots_out_sig_len = 0u;
        return 0u;
    }
    uart_read_bytes(s_uart_msg, message_length);
    total_start = fw_total_read();
    count_before = verify_client.hardware_chain_count;
    cycles_before = verify_client.hardware_chain_cycles;
    derive_count_before = verify_client.hardware_derive_count;
    derive_cycles_before = verify_client.hardware_derive_cycles;
    sign_count_before = verify_client.hardware_sign_count;
    sign_cycles_before = verify_client.hardware_sign_cycles;
    verify_client.last_hw_error = 0u;
    parse_start = MMIO32(SOC_CYCLE_COUNT);
    status = lms_private_key_parse(&private_key, private_key_bytes, sizeof(private_key_bytes));
    *parse_cycles = MMIO32(SOC_CYCLE_COUNT) - parse_start;
    if (status == LMS_OK) {
#if !LMS_FW_NO_HW_ACCEL

        set_hw_lmots(lmots_hw_supported(private_key.lmots_type));

        if (fw_seed_load(private_key.seed) != LMS_MMIO_OK) {
            g_keygen_stage = 0xe0u;
            sign_y_in_taskram = 0u;
            lmots_out_sig_len = 0u;
            *cycles = 0u;
            *sign_cycles = 0u;
            *steady_total_cycles = 0u;
            fw_total_finish(total_cycles, total_start);
            return 0u;
        }
#endif
        /* Steady starts after parse/seed_load and includes preparation plus
         * the complete signature in CPU memory, as in LMS Sign. Total also
         * includes parse/seed_load; UART transmission is outside both windows. */
        steady_start = fw_total_read();
        sign_start = MMIO32(SOC_CYCLE_COUNT);
        sign_y_in_taskram = 0u;
        /* Both hardware and software paths return the complete type+C+y
         * buffer. Keep sign_y_in_taskram clear so UART sends that CPU buffer. */
        if (lmots_hw_supported(private_key.lmots_type)) {
#if !LMS_FW_NO_HW_ACCEL
            /* Hardware preparation and SIGN reuse resident coefficients.
             * Read the resulting y into the CPU buffer before stopping either
             * timer; the output endpoint matches the LMS Sign path. */
            /* Match LMS Sign: derive C in hardware unless an explicit C source
             * is configured. Scope the callback to this operation; set_hw_lmots
             * deliberately clears it, including on an already-enabled backend. */
            lmots_sign_randomizer_backend_set(hw_sign_randomizer, &verify_client);
            status = lmots_sign_prepare(&private_key, private_key.q,
                                        s_uart_msg, message_length, C, coefficients);
            lmots_sign_randomizer_backend_set(NULL, NULL);
            if (status == LMS_OK) {
                signature[0] = (uint8_t)(private_key.lmots_type >> 24);
                signature[1] = (uint8_t)(private_key.lmots_type >> 16);
                signature[2] = (uint8_t)(private_key.lmots_type >> 8);
                signature[3] = (uint8_t)private_key.lmots_type;
                memcpy(signature + 4, C, LMS_N);
#if LMS_SIGN_RESULT_STREAM
                /* R6 Stage 2: OTS sign also consumes committed y chains from
                 * the result window while the engine computes later pairs. */
                status = lms_mmio_lmots_sign_stream(&verify_client, 0u,
                                                    private_key.I, private_key.q,
                                                    private_key.lmots_type,
                                                    verify_client.coef_ready ? NULL : coefficients,
                                                    signature + 4u + LMS_N, cycles);
                verify_client.coef_ready = 0;
#else
                status = lms_mmio_lmots_sign_taskram(&verify_client, 0u,
                                                     private_key.I, private_key.q,
                                                     private_key.lmots_type,
                                                     verify_client.coef_ready ? NULL : coefficients, cycles);
                verify_client.coef_ready = 0;
                if (status == LMS_MMIO_OK) {
                    uint32_t y_len = lmots_y_len_type(private_key.lmots_type);
                    hw_sign_read_y(signature + 4u + LMS_N, y_len);
                }
#endif
            }
            lmots_out_sig_len = lmots_sig_len_priv(&private_key);
#else
            lmots_out_sig_len = lmots_sig_len_priv(&private_key);
            status = lmots_sign(&private_key, private_key.q, s_uart_msg, message_length,
                                signature, lmots_out_sig_len);
#endif
        } else {

            lmots_out_sig_len = lmots_sig_len_priv(&private_key);
            status = lmots_sign(&private_key, private_key.q, s_uart_msg, message_length,
                                signature, lmots_out_sig_len);
        }
        *sign_cycles = MMIO32(SOC_CYCLE_COUNT) - sign_start;
        fw_steady_finish(steady_total_cycles, steady_start);
    } else {
        sign_y_in_taskram = 0u;
        lmots_out_sig_len = 0u;
        *sign_cycles = 0u;
        *steady_total_cycles = 0u;
    }
    hardware_hits += (uint32_t)(verify_client.hardware_chain_count - count_before)
                   + (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_sign_count - sign_count_before);
    *cycles = (uint32_t)(verify_client.hardware_chain_cycles - cycles_before)
            + (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before)
            + (uint32_t)(verify_client.hardware_sign_cycles - sign_cycles_before);
    fw_total_finish(total_cycles, total_start);
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

void lms_dbg_put(char c)
{
    uart_putc(c);
}

static uint32_t lmots_verify_from_uart(uint32_t *cycles, uint32_t *total_cycles)
{
    uint8_t I[LMS_I_LEN];
    uint8_t expected_public[LMS_N];
    uint8_t recovered_public[LMS_N];

    uint8_t C[LMS_N];

#if !LMS_FW_NO_HW_ACCEL
    uint8_t coefficients[LMS_MAX_OTS_P];
    uint64_t cycles_before;
#endif
    uint64_t count_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    fw_total_clock_t total_start;
    uint32_t sig_len;
    uint32_t y_len;
#if LMS_FW_OTS_SNAPSHOT
    uint32_t k;
#endif
    uint32_t q;
    uint32_t message_length;
    uint32_t signature_type;
    int y_in_taskram = 0;
    int status;

    dbg_valid = 0u;
    uart_read_bytes(I, sizeof(I));
    q = uart_get_u32();
    uart_read_bytes(expected_public, sizeof(expected_public));
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length + LMS_MAX_OTS_SIG_LEN);
        *cycles = 0u;
        *total_cycles = 0u;
        return 0u;
    }
    uart_read_bytes(s_uart_msg, message_length);

    signature_type = ((uint32_t)uart_getc() << 24) |
                     ((uint32_t)uart_getc() << 16) |
                     ((uint32_t)uart_getc() << 8) |
                     (uint32_t)uart_getc();
    uart_read_bytes(C, sizeof(C));
    y_len = lmots_y_len_type(signature_type);
    sig_len = 36u + y_len;
    if (y_len == 0u) {

        uart_discard(LMS_MAX_OTS_SIG_LEN - 36u);
        *cycles = 0u;
        *total_cycles = 0u;
        return 0u;
    }
#if !LMS_FW_NO_HW_ACCEL

    set_hw_lmots(lmots_hw_supported(signature_type));
#endif
#if !LMS_FW_NO_HW_ACCEL
    if (!LMS_062_FORCE_SW_Y && lmots_hw_supported(signature_type) &&
        32u + y_len / 4u <= ((message_length <= 74u) ? mqc_msg_base(y_len) : 568u)) {

        if (bridge_run(BRIDGE_DIR_RX, BRIDGE_Y_ADDR, y_len) != 0) {
            *cycles = 0u;
            *total_cycles = 0u;
            return 0u;
        }
        y_in_taskram = 1;
    } else
#endif
    {

        s_uart_sig[0] = (uint8_t)(signature_type >> 24);
        s_uart_sig[1] = (uint8_t)(signature_type >> 16);
        s_uart_sig[2] = (uint8_t)(signature_type >> 8);
        s_uart_sig[3] = (uint8_t)signature_type;
        memcpy(s_uart_sig + 4, C, LMS_N);
        uart_read_bytes(s_uart_sig + 36u, y_len);
    }

    total_start = fw_total_read();
    count_before = verify_client.hardware_verify_count;
    hash_count_before = verify_client.hardware_hash_once_count;
    hash_cycles_before = verify_client.hardware_hash_once_cycles;
    verify_client.last_hw_error = 0u;
#if !LMS_FW_NO_HW_ACCEL
    if (lmots_hw_supported(signature_type)) {
        cycles_before = verify_client.hardware_verify_cycles;
        status = lmots_public_from_signature_prepare(I, FW_HASH_ALG, q, signature_type,
                                                     s_uart_msg, message_length, C,
                                                     coefficients);
        if (status != LMS_OK) {
            *cycles = 0u;
            *total_cycles = 0u;
            return 0u;
        }

        if (!y_in_taskram) {
            task_write_words(32u, s_uart_sig + 36u, y_len);
        }
#if LMS_FW_OTS_SNAPSHOT
        if (y_len <= sizeof(dbg_y)) {
            task_read_words(32u, dbg_y, y_len);
        }
#endif
        status = lms_mmio_lmots_verify_taskram(&verify_client, I, q,
                                               signature_type,
                                               verify_client.coef_ready ? NULL : coefficients,
                                               recovered_public, cycles);
        verify_client.coef_ready = 0;
        *cycles = (uint32_t)(verify_client.hardware_verify_cycles - cycles_before)
                + (uint32_t)(verify_client.hardware_hash_once_cycles - hash_cycles_before);
#if LMS_FW_OTS_SNAPSHOT
        if (y_len <= sizeof(dbg_y) && status == LMS_MMIO_OK) {
            task_read_words(32u, dbg_ep, y_len);
            task_read_words(0u, dbg_coef, sizeof(dbg_coef));
            memcpy(dbg_kq, recovered_public, LMS_N);
            dbg_meta[0] = 1u;
            dbg_meta[1] = (uint8_t)status;
            dbg_meta[2] = (uint8_t)verify_client.last_hw_error;
            dbg_meta[3] = 0u;
            for (k = 0u; k < 4u; k++) {
                dbg_meta[4u + k] = (uint8_t)(*cycles >> (8u * k));
                dbg_meta[8u + k] = (uint8_t)(((verify_client.hardware_verify_count - count_before)
                    + (verify_client.hardware_hash_once_count - hash_count_before)) >> (8u * k));
                dbg_meta[12u + k] = (uint8_t)(dbg_run >> (8u * k));
            }
            dbg_run++;
            dbg_valid = 1u;
        }
#endif
    } else
#endif
    {

        status = lmots_public_from_signature(I, FW_HASH_ALG, q, signature_type,
                                             s_uart_msg, message_length,
                                             s_uart_sig, sig_len, recovered_public);
        *cycles = 0u;
    }
    if (status == LMS_OK && memcmp(recovered_public, expected_public, LMS_N) != 0) {
        status = LMS_ERR_VERIFY;
    }
    if (dbg_valid) {
        dbg_meta[1] = (uint8_t)status;
    }
    hardware_hits += (uint32_t)(verify_client.hardware_verify_count - count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    fw_total_finish(total_cycles, total_start);
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t seed_load_from_uart(uint32_t *cycles, uint32_t *total_cycles)
{
    uint8_t seed[LMS_SEED_LEN];
    uint32_t total_start;
    int status;

    uart_read_bytes(seed, sizeof(seed));
    total_start = MMIO32(SOC_CYCLE_COUNT);
    verify_client.last_hw_error = 0u;
#if !LMS_FW_NO_HW_ACCEL
    status = lms_mmio_seed_load_test(&verify_client, 0u, seed);
    if (status == LMS_MMIO_OK) {

        memcpy(s_seed_slot, seed, LMS_SEED_LEN);
        s_seed_slot_valid = 1u;
    }
    *cycles = MMIO32(LMS_CYCLE_COUNT);
#else
    status = LMS_MMIO_OK;
    memcpy(s_seed_slot, seed, LMS_SEED_LEN);
    s_seed_slot_valid = 1u;
    *cycles = 0u;
#endif
    memset(seed, 0, sizeof(seed));
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    return status == LMS_MMIO_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t c_load_from_uart(uint32_t *error)
{
    uint8_t c[LMS_N];
    uint32_t index;

    uart_read_bytes(c, sizeof(c));
    *error = 0u;
#ifdef LMS_FW_SEC_TEST_MODE
    for (index = 0u; index < sizeof(c); index++) {
        s_c_slot[index] = c[index];
    }
    s_c_slot_valid = 1u;

    verify_client.randomizer_c_slot = s_c_slot;
    memset(c, 0, sizeof(c));
    return LMS_STATUS_DONE;
#else
    (void)c;
    *error = 0x0au;   /* ERR_INSECURE_DISABLED */
    return 0u;
#endif
}

static uint16_t crc16_ccitt(const uint8_t *data, uint32_t length)
{
    uint16_t crc = 0xffffu;
    uint32_t index;
    uint32_t bit;
    for (index = 0u; index < length; index++) {
        crc ^= (uint16_t)data[index] << 8;
        for (bit = 0u; bit < 8u; bit++) {
            crc = (crc & 0x8000u) != 0u ? (uint16_t)((crc << 1) ^ 0x1021u)
                                        : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static void nvm_sync_from_uart(uint8_t response[48])
{
    uint8_t op = uart_getc();
    uint8_t chunk[NVM_CHUNK_LEN];
    uint32_t index;
    uint32_t half;
    uint16_t got_crc;
    uint16_t calc_crc;

    response[0] = op;
    response[1] = 0u;
    response[2] = 0u;
    response[3] = (uint8_t)(nvm_valid[0] | (uint8_t)(nvm_valid[1] << 1));
    if (op == NVM_SYNC_SUB_PUSH_LO || op == NVM_SYNC_SUB_PUSH_HI) {
        half = op == NVM_SYNC_SUB_PUSH_HI ? 1u : 0u;
        uart_read_bytes(chunk, NVM_CHUNK_LEN);
        got_crc = (uint16_t)uart_getc();
        got_crc |= (uint16_t)uart_getc() << 8;
        calc_crc = crc16_ccitt(chunk, NVM_CHUNK_LEN);
        if (calc_crc != got_crc) {
            response[2] = 2u;
        } else {
            for (index = 0u; index < NVM_CHUNK_LEN; index++) {
                nvm_state[half * NVM_CHUNK_LEN + index] = chunk[index];
            }
            nvm_crc[half] = got_crc;
            nvm_valid[half] = 1u;
        }
    } else if (op == NVM_SYNC_SUB_READ) {

        if (nvm_valid[0] == 0u || nvm_valid[1] == 0u) {
            response[2] = 1u;
        } else {
            for (index = 0u; index < 28u; index++) {
                response[4u + index] = nvm_state[index];
            }
        }
    } else if (op == NVM_SYNC_SUB_READ_HI) {

        if (nvm_valid[0] == 0u || nvm_valid[1] == 0u) {
            response[2] = 1u;
        } else {
            for (index = 0u; index < 28u; index++) {
                response[4u + index] = nvm_state[36u + index];
            }
        }
    } else if (op == NVM_SYNC_SUB_READ_MID) {

        if (nvm_valid[0] == 0u || nvm_valid[1] == 0u) {
            response[2] = 1u;
        } else {
            for (index = 0u; index < 28u; index++) {
                response[4u + index] = nvm_state[28u + index];
            }
        }
    } else {
        uart_discard(NVM_CHUNK_LEN + NVM_CRC_LEN);
        response[2] = 3u;
    }
    response[3] = (uint8_t)(nvm_valid[0] | (uint8_t)(nvm_valid[1] << 1));
}

static void sec_state_from_uart(uint8_t response[48])
{
    uint8_t sub = uart_getc();
    uint8_t params[65];
    uint32_t index;
    uint32_t plen = 0u;
    uint8_t resp32[32];

    if (sub == SEC_SUB_COMMIT) {
        plen = 12u;
    } else if (sub == SEC_SUB_READ_SLOT) {
        plen = 1u;
    } else if (sub == SEC_SUB_NVM_READ) {
        plen = 1u;
    } else if (sub == SEC_SUB_NVM_LOAD) {
        plen = 65u;
    } else if (sub == SEC_SUB_MC_LOAD) {
        plen = 4u;
    } else if (sub == SEC_SUB_WRAP_LOAD) {
        plen = 48u;
    } else if (sub == SEC_SUB_BOOT || sub == SEC_SUB_PROVISION) {
        plen = 16u;
    } else if (sub == SEC_SUB_FACTORY_INIT) {
        plen = 16u;
    }
    for (index = 0u; index < plen; index++) {
        params[index] = uart_getc();
    }
    (void)sec_handle_uart_cmd(sub, params, resp32);
    for (index = 0u; index < 32u; index++) {
        response[index] = resp32[index];
    }

    if ((sub == SEC_SUB_COMMIT && resp32[2] == 0u) ||
        (sub == SEC_SUB_BOOT && resp32[2] == 0u)) {
        sec_export_active(nvm_state);
        nvm_valid[0] = 1u;
        nvm_valid[1] = 1u;
    }
}

#if !defined(LMS_FW_NO_HW_ACCEL) && !defined(LMS_FW_SEC_TEST_MODE)
static int fw_trng_fill_c(void *context, uint8_t out[LMS_N])
{
    uint32_t index;
    uint32_t stat;
    (void)context;
    if ((MMIO32(TRNG_STAT) & 1u) != 0u) {
        return 1;
    }
    for (index = 0u; index < LMS_N / 4u; index++) {

        stat = 0u;
        while ((stat & 0x100u) == 0u) {
            stat = MMIO32(TRNG_STAT);
            if ((stat & 1u) != 0u) {
                return 1;
            }
        }
        {
            uint32_t word = MMIO32(TRNG_RND);
            out[index * 4u]     = (uint8_t)word;
            out[index * 4u + 1u] = (uint8_t)(word >> 8);
            out[index * 4u + 2u] = (uint8_t)(word >> 16);
            out[index * 4u + 3u] = (uint8_t)(word >> 24);
        }
    }
    return 0;
}
#endif

static uint32_t trng_read_from_uart(uint8_t response[48], uint8_t *out_words, uint8_t with_ack)
{
    uint32_t count = uart_getc();
    uint32_t index;
    uint8_t seq = 0u;

    if (with_ack != 0u) {
        seq = uart_getc();
    }
    response[2] = (MMIO32(TRNG_STAT) & 1u) != 0u ? 1u : 0u;
    if (response[2] != 0u) {
        return 0u;
    }
    if (count > 16u) {
        count = 16u;
    }
    for (index = 0u; index < count; index++) {
        uint32_t word = MMIO32(TRNG_RND);
        out_words[index * 4u] = (uint8_t)word;
        out_words[index * 4u + 1u] = (uint8_t)(word >> 8);
        out_words[index * 4u + 2u] = (uint8_t)(word >> 16);
        out_words[index * 4u + 3u] = (uint8_t)(word >> 24);
    }
    response[20] = (uint8_t)count;
    response[21] = (uint8_t)(count >> 8);
    response[22] = (uint8_t)(count >> 16);
    response[23] = (uint8_t)(count >> 24);
    response[24] = seq;
    return count * 4u;
}

static void trng_status_from_uart(uint8_t response[48])
{
    uint32_t stat = MMIO32(TRNG_STAT);
    uint32_t ctrl = MMIO32(TRNG_CTRL);
    uint32_t apt = MMIO32(TRNG_APT);
    uint32_t version = MMIO32(TRNG_VERSION);
    uint32_t cap = MMIO32(TRNG_CAP);

    response[2] = 0u;

    response[16] = (uint8_t)version;
    response[17] = (uint8_t)(version >> 8);
    response[18] = (uint8_t)cap;
    response[19] = (uint8_t)(cap >> 8);
    response[20] = (uint8_t)stat;
    response[21] = (uint8_t)(stat >> 8);
    response[22] = (uint8_t)(stat >> 16);
    response[23] = (uint8_t)(stat >> 24);
    response[24] = (uint8_t)ctrl;
    response[25] = (uint8_t)(ctrl >> 8);
    response[26] = (uint8_t)(ctrl >> 16);
    response[27] = (uint8_t)(ctrl >> 24);
    response[28] = (uint8_t)apt;
    response[29] = (uint8_t)(apt >> 8);
    response[30] = (uint8_t)(apt >> 16);
    response[31] = (uint8_t)(apt >> 24);
}

static void flash_probe_from_uart(uint8_t response[48])
{
    uint32_t spin = 0u;
    uint32_t stat;
    uint32_t word;
    uint8_t resp[5][4];
    uint32_t cand;
    uint32_t byte;

    MMIO32(FLASH_CTRL) = 1u;
    do {
        stat = MMIO32(FLASH_STATUS);
        spin++;
    } while ((stat & 2u) == 0u && spin < 2000000u);
    response[2] = ((stat & 2u) != 0u) ? 0u : 1u;

    word = MMIO32(FLASH_RESP0); resp[0][0] = (uint8_t)word; resp[0][1] = (uint8_t)(word >> 8); resp[0][2] = (uint8_t)(word >> 16);
    word = MMIO32(FLASH_RESP1); resp[1][0] = (uint8_t)word; resp[1][1] = (uint8_t)(word >> 8); resp[1][2] = (uint8_t)(word >> 16);
    word = MMIO32(FLASH_RESP2); resp[2][0] = (uint8_t)word; resp[2][1] = (uint8_t)(word >> 8); resp[2][2] = (uint8_t)(word >> 16);
    word = MMIO32(FLASH_RESP3); resp[3][0] = (uint8_t)word; resp[3][1] = (uint8_t)(word >> 8); resp[3][2] = (uint8_t)(word >> 16);
    word = MMIO32(FLASH_RESP4); resp[4][0] = (uint8_t)word; resp[4][1] = (uint8_t)(word >> 8); resp[4][2] = (uint8_t)(word >> 16);
    for (cand = 0u; cand < 5u; cand++) {
        for (byte = 0u; byte < 3u; byte++) {
            response[16u + cand * 3u + byte] = resp[cand][byte];
        }
    }
    response[31] = (uint8_t)stat;
}

static void flash_prog_from_uart(uint8_t response[48])
{
    uint32_t addr;
    uint32_t spin = 0u;
    uint32_t stat;
    uint32_t index;
    uint8_t data;

    addr = ((uint32_t)uart_getc() << 16) | ((uint32_t)uart_getc() << 8) |
           (uint32_t)uart_getc();
    data = (uint8_t)uart_getc();
    MMIO32(FLASH_OP) = 1u;
    MMIO32(FLASH_ADDR) = addr;
    MMIO32(FLASH_BYTE) = data;
    MMIO32(FLASH_CTRL) = 1u;
    do {
        stat = MMIO32(FLASH_STATUS);
        spin++;
    } while ((stat & 2u) == 0u && spin < 2000000u);
    response[2] = ((stat & 2u) != 0u) ? 0u : 1u;

    for (index = 0u; index < 400000u; index++) {
        (void)MMIO32(FLASH_STATUS);
    }
    response[16] = (uint8_t)(addr >> 16);
    response[17] = (uint8_t)(addr >> 8);
    response[18] = (uint8_t)addr;
    response[19] = data;
    response[31] = (uint8_t)stat;
}

static void flash_cmd_from_uart(uint8_t response[48])
{
    uint32_t spin = 0u;
    uint32_t stat;
    uint8_t byte;

    byte = (uint8_t)uart_getc();
    MMIO32(FLASH_OP) = 2u;
    MMIO32(FLASH_BYTE) = byte;
    MMIO32(FLASH_CTRL) = 1u;
    do {
        stat = MMIO32(FLASH_STATUS);
        spin++;
    } while ((stat & 2u) == 0u && spin < 2000000u);
    response[2] = ((stat & 2u) != 0u) ? 0u : 1u;
    response[16] = byte;
    response[31] = (uint8_t)stat;
}

typedef struct {
    lms_private_key_t private_key;
    const uint8_t *message;
    uint32_t message_length;
    uint8_t *signature;
    int sign_rc;
} sec_sign_ctx_t;

static uint8_t sec_sign_message[VERIFY_MESSAGE_MAX];

static int sec_sign_do(uint32_t q, void *vctx)
{
    sec_sign_ctx_t *ctx = (sec_sign_ctx_t *)vctx;
    ctx->private_key.q = q;
    ctx->sign_rc = lmots_sign(&ctx->private_key, q, ctx->message, ctx->message_length,
                              ctx->signature, lmots_sig_len_priv(&ctx->private_key));
    return ctx->sign_rc;
}

static void sec_sign_from_uart(uint8_t response[48],
                               uint8_t signature[LMS_MAX_OTS_SIG_LEN],
                               uint32_t *signature_length,
                               uint32_t *cycles,
                               uint32_t *total_cycles)
{
    sec_sign_ctx_t ctx;
    uint64_t count_before;
    uint64_t cycles_before;
    uint64_t sign_count_before;
    uint64_t sign_cycles_before;
    uint32_t total_start;
    uint32_t q_out;
    int rc;

    uart_read_bytes(ctx.private_key.I, LMS_I_LEN);
    ctx.private_key.lms_type = uart_get_u32();
    ctx.private_key.lmots_type = uart_get_u32();
    ctx.message_length = uart_get_u16();
    if (ctx.message_length > VERIFY_MESSAGE_MAX) {
        uart_discard(ctx.message_length);
        *signature_length = 0u;
        *cycles = 0u;
        *total_cycles = 0u;
        response[2] = (uint8_t)SEC_ERR_PATH;
        return;
    }

    uart_read_bytes(sec_sign_message, ctx.message_length);
    ctx.message = sec_sign_message;
    ctx.signature = signature;

    total_start = MMIO32(SOC_CYCLE_COUNT);
    count_before = verify_client.hardware_derive_count;
    cycles_before = verify_client.hardware_derive_cycles;
    sign_count_before = verify_client.hardware_sign_count;
    sign_cycles_before = verify_client.hardware_sign_cycles;
    verify_client.last_hw_error = 0u;

    {
        lms_param_t lparam;
        uint32_t max_ctr = 32u;
        if (lms_get_lms_param(ctx.private_key.lms_type, &lparam) == LMS_OK) {
            max_ctr = 1u << lparam.height;
        }
        rc = lms_mmio_lmots_sign_enable(&verify_client, 0u);
        if (rc == LMS_MMIO_OK) {
            rc = sec_sign(max_ctr, sec_sign_do, &ctx, &q_out);
        } else {
            rc = SEC_ERR_AUTH;
        }
    }
    lms_mmio_lmots_sign_disable();
    (void)lms_mmio_lmots_sign_enable_insecure(&verify_client);

    hardware_hits += (uint32_t)(verify_client.hardware_derive_count - count_before);
    hardware_hits += (uint32_t)(verify_client.hardware_sign_count - sign_count_before);
    *cycles = (uint32_t)(verify_client.hardware_derive_cycles - cycles_before +
                         verify_client.hardware_sign_cycles - sign_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;

    response[2] = (uint8_t)rc;
    response[3] = (uint8_t)(ctx.sign_rc & 0xffu);

    response[4] = (uint8_t)(*total_cycles);
    response[5] = (uint8_t)(*total_cycles >> 8);
    response[6] = (uint8_t)(*total_cycles >> 16);
    response[7] = (uint8_t)(*total_cycles >> 24);
    response[20] = (uint8_t)(q_out >> 24);
    response[21] = (uint8_t)(q_out >> 16);
    response[22] = (uint8_t)(q_out >> 8);
    response[23] = (uint8_t)q_out;

    *signature_length = (rc == SEC_OK) ? lmots_sig_len_priv(&ctx.private_key) : 0u;

    if (sec_key_ready() != 0u) {
        sec_export_active(nvm_state);
        nvm_valid[0] = 1u;
        nvm_valid[1] = 1u;
    }
}

#if !LMS_FW_NO_HW_ACCEL

static int sec_lms_sign_impl(const lms_private_key_t *private_key,
                             const uint8_t *message,
                             uint32_t message_length,
                             uint8_t *signature,
                             size_t signature_len,
                             size_t *written,
                             uint32_t *q_out,
                             uint32_t *steady_total_cycles)
{
    lms_param_t lparam;
    lmots_param_t oparam;
    sec_sign_ctx_t ctx;
    uint32_t qo;
    size_t needed;
    size_t sig_len;
    uint8_t *path;
    int rc;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t0;
    uint32_t prof_t1;
    uint32_t prof_t2;
#endif

    if (lms_get_lms_param(private_key->lms_type, &lparam) != LMS_OK ||
        lms_get_lmots_param(private_key->lmots_type, &oparam) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    needed = lms_signature_len(private_key->lms_type, private_key->lmots_type);
    if (signature_len < needed) {
        return LMS_ERR_BUFFER_TOO_SMALL;
    }

    if (sec_tree_cache_ensure(private_key) == 0) {
        return LMS_ERR_INVALID;
    }
    if (steady_total_cycles != NULL) {
        *steady_total_cycles = MMIO32(SOC_CYCLE_COUNT);
    }
#if defined(LMS_MMIO_SOC_PROFILE)
    prof_t0 = MMIO32(SOC_CYCLE_COUNT);
#endif

    ctx.private_key = *private_key;
    ctx.message = message;
    ctx.message_length = message_length;
    ctx.signature = signature + 4u;
    ctx.sign_rc = 0;
    if (lms_mmio_lmots_sign_enable(&verify_client, 0u) != LMS_MMIO_OK) {
        return LMS_ERR_INVALID;
    }

    lmots_sign_backend_set(hw_sign_taskram, &verify_client);
    sign_y_in_taskram = 1u;
    sign_y_len = lmots_y_len_type(private_key->lmots_type);
#if defined(LMS_MMIO_SOC_PROFILE)
    prof_t1 = MMIO32(SOC_CYCLE_COUNT);
#endif

    rc = sec_sign(1u << lparam.height, sec_sign_do, &ctx, &qo);
#if defined(LMS_MMIO_SOC_PROFILE)
    prof_t2 = MMIO32(SOC_CYCLE_COUNT);
#endif
    lms_mmio_lmots_sign_disable();
    (void)lms_mmio_lmots_sign_enable_insecure(&verify_client);
    if (rc != SEC_OK) {
        return LMS_ERR_INVALID;
    }

    sig_len = 4u + oparam.n + oparam.p * oparam.n;
    lms_store_u32(signature, qo);
    lms_store_u32(signature + 4u + sig_len, private_key->lms_type);
    path = signature + 4u + sig_len + 4u;
    if (lms_subtree_auth_path_backend(&s_sec_tree_ctx, private_key, qo, path) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
#if defined(LMS_MMIO_SOC_PROFILE)
    prof_sec_enable_cycles = prof_t1 - prof_t0;
    prof_sec_sign_cycles = prof_t2 - prof_t1;
    prof_sec_tail_cycles = MMIO32(SOC_CYCLE_COUNT) - prof_t2;
#endif
    if (steady_total_cycles != NULL) {
        *steady_total_cycles = MMIO32(SOC_CYCLE_COUNT) - *steady_total_cycles;
    }
    if (q_out) {
        *q_out = qo;
    }
    if (written) {
        *written = needed;
    }
    return LMS_OK;
}

static int sec_lms_keygen_impl(const lms_private_key_t *private_key,
                               uint8_t public_key_bytes[LMS_PUBLIC_KEY_LEN])
{
    lms_public_key_t public_key;

    if (sec_tree_cache_ensure(private_key) == 0) {
        return LMS_ERR_INVALID;
    }
    {
        lms_sublevel_t *top = &s_sec_tree_ctx.levels[s_sec_tree_ctx.sublevels - 1u];
        memcpy(public_key.root, top->active.nodes + (size_t)1u * LMS_N, LMS_N);
    }
    public_key.lms_type = private_key->lms_type;
    public_key.lmots_type = private_key->lmots_type;
    memcpy(public_key.I, private_key->I, LMS_I_LEN);
    return lms_public_key_serialize(&public_key, public_key_bytes, LMS_PUBLIC_KEY_LEN);
}

static uint32_t sec_lms_sign_from_uart(uint8_t signature[LMS_MAX_SIGNATURE_LEN],
                                       uint32_t *signature_length,
                                       uint32_t *next_q,
                                       uint32_t *cycles,
                                       uint32_t *total_cycles,
                                       uint32_t *steady_total_cycles)
{
    lms_private_key_t private_key;

    uint32_t message_length;
    uint64_t derive_count_before;
    uint64_t derive_cycles_before;
    uint64_t sign_count_before;
    uint64_t sign_cycles_before;
    uint32_t total_start;
    size_t written = 0u;
    int status;

    memset(&private_key, 0, sizeof(private_key));
    uart_read_bytes(private_key.I, LMS_I_LEN);
    private_key.lms_type = uart_get_u32();
    private_key.lmots_type = uart_get_u32();
    message_length = uart_get_u16();
    if (message_length > sizeof(s_uart_msg)) {
        uart_discard(message_length);
        *signature_length = 0u;
        *next_q = 0u;
        *cycles = 0u;
        *total_cycles = 0u;
        *steady_total_cycles = 0u;
        return 0u;
    }
    uart_read_bytes(s_uart_msg, message_length);

    total_start = MMIO32(SOC_CYCLE_COUNT);
    verify_client.last_hw_error = 0u;
    *next_q = 0u;
    derive_count_before = verify_client.hardware_derive_count;
    derive_cycles_before = verify_client.hardware_derive_cycles;
    sign_count_before = verify_client.hardware_sign_count;
    sign_cycles_before = verify_client.hardware_sign_cycles;
    status = sec_lms_sign_impl(&private_key, s_uart_msg, message_length,
                               signature, LMS_MAX_SIGNATURE_LEN, &written, next_q,
                               steady_total_cycles);
    hardware_hits += (uint32_t)(verify_client.hardware_derive_count - derive_count_before)
                   + (uint32_t)(verify_client.hardware_sign_count - sign_count_before);
    *cycles = (uint32_t)(verify_client.hardware_derive_cycles - derive_cycles_before +
                         verify_client.hardware_sign_cycles - sign_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    *signature_length = (status == LMS_OK) ? (uint32_t)written : 0u;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t sec_lms_keygen_from_uart(uint8_t public_key[LMS_PUBLIC_KEY_LEN],
                                         uint32_t *public_key_length,
                                         uint32_t *cycles,
                                         uint32_t *total_cycles)
{
    lms_private_key_t private_key;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    uint32_t total_start;
    int status;

    memset(&private_key, 0, sizeof(private_key));

    private_key.lms_type = uart_get_u32();
    private_key.lmots_type = uart_get_u32();

    total_start = MMIO32(SOC_CYCLE_COUNT);
    verify_client.last_hw_error = 0u;
    keygen_count_before = verify_client.hardware_keygen_count;
    keygen_cycles_before = verify_client.hardware_keygen_cycles;
    hash_count_before = verify_client.hardware_hash_once_count;
    hash_cycles_before = verify_client.hardware_hash_once_cycles;
    status = sec_keygen_key(private_key.I);
    if (status == SEC_OK) {
        status = sec_lms_keygen_impl(&private_key, public_key);
    }
    hardware_hits += (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before +
                         verify_client.hardware_hash_once_cycles - hash_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    *public_key_length = (status == LMS_OK) ? LMS_PUBLIC_KEY_LEN : 0u;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}

static uint32_t sec_lms_keygen_new_from_uart(uint8_t public_key[LMS_PUBLIC_KEY_LEN],
                                             uint32_t *public_key_length,
                                             uint32_t *cycles,
                                             uint32_t *total_cycles)
{
    lms_private_key_t private_key;
    uint64_t keygen_count_before;
    uint64_t keygen_cycles_before;
    uint64_t hash_count_before;
    uint64_t hash_cycles_before;
    uint32_t total_start;
    int status;

    memset(&private_key, 0, sizeof(private_key));
    uart_read_bytes(private_key.I, LMS_I_LEN);
    private_key.lms_type = uart_get_u32();
    private_key.lmots_type = uart_get_u32();

    total_start = MMIO32(SOC_CYCLE_COUNT);
    verify_client.last_hw_error = 0u;
    keygen_count_before = verify_client.hardware_keygen_count;
    keygen_cycles_before = verify_client.hardware_keygen_cycles;
    hash_count_before = verify_client.hardware_hash_once_count;
    hash_cycles_before = verify_client.hardware_hash_once_cycles;
    status = sec_keygen_new(private_key.I);
    if (status == SEC_OK) {
        status = sec_lms_keygen_impl(&private_key, public_key);
    }
    hardware_hits += (uint32_t)(verify_client.hardware_keygen_count - keygen_count_before)
                   + (uint32_t)(verify_client.hardware_hash_once_count - hash_count_before);
    *cycles = (uint32_t)(verify_client.hardware_keygen_cycles - keygen_cycles_before +
                         verify_client.hardware_hash_once_cycles - hash_cycles_before);
    *total_cycles = MMIO32(SOC_CYCLE_COUNT) - total_start;
    *public_key_length = (status == LMS_OK) ? LMS_PUBLIC_KEY_LEN : 0u;
    return status == LMS_OK ? LMS_STATUS_DONE : 0u;
}
#endif

#define LMS_FW_SELFTEST_ERR 0xE0u
#define LMS_FW_MASK_ERR     0xE1u
static int fw_mask_selftest_once(void)
{
#if defined(FW_HASH_SHA256)
    static const uint32_t golden[8] = {
        0xbf1678bau, 0xeacf018fu, 0xde404141u, 0x2322ae5du,
        0xa36103b0u, 0x9c7a1796u, 0x61ff10b4u, 0xad1500f2u
    };
    static const uint32_t golden_cycles = 68u;
#else

    static const uint32_t golden[8] = {
        0x60663348u, 0x77a86013u, 0x0863681cu, 0x4d11c40cu,
        0x3045b48du, 0xeee1f1f8u, 0x37ea944fu, 0x39578be7u
    };
    static const uint32_t golden_cycles = 12u;
#endif
    uint32_t poll;
    uint32_t index;

    MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
    MMIO32(LMS_INPUT_LENGTH) = 3u;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    MMIO32(LMS_INPUT) = 0x00636261u;   /* "abc" */
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;

    for (poll = 0u; poll < 1024u; poll++) {
        if ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) == 0u) {
            break;
        }
    }
    if (poll == 1024u) {
        return 1;
    }
    if (MMIO32(LMS_STATUS) != LMS_STATUS_DONE || MMIO32(LMS_ERROR) != 0u) {
        return 2;
    }
    if (MMIO32(LMS_CYCLE_COUNT) != golden_cycles) {
        return 3;
    }
    for (index = 0u; index < 8u; index++) {
        if (MMIO32(LMS_OUTPUT + index * 4u) != golden[index]) {
            return 4;
        }
    }
    return 0;
}

static uint32_t fw_mask_status(void)
{
    MMIO32(LMS_DBG_ADDR) = 1u;
    return MMIO32(LMS_DBG_DATA);
}

static int fw_mask_wait_ready(void)
{
    uint32_t i;
    uint32_t s = fw_mask_status();
    if ((s & 0x80000000u) == 0u) {
        return 0;
    }
    for (i = 0u; i < 2000000u; i++) {
        if ((s & 0x3u) != 0u) {
            return -1;                   /* rnd_fail / rnd_block_missing */
        }
        if ((s & 0x18u) == 0x18u) {
            return 0;
        }
        s = fw_mask_status();
    }
    return -1;
}

static void serve_uart(void)
{
    uint32_t cycles;
    uint32_t total_cycles;
    uint32_t steady_total_cycles;
    uint32_t parse_cycles;
    uint32_t sign_cycles;
    uint32_t index;
    uint32_t status;
    uint32_t error;
    uint32_t input_length;
    uint32_t request;
    uint32_t return_digest;
    uint32_t response_value;
    uint32_t signature_length;
    uint32_t public_key_length;
    uint8_t keygen_public_key[LMS_PUBLIC_KEY_LEN];
    uint8_t lmots_public_key[LMS_N];

    uint8_t nvm_response[48];
    uint8_t trng_read_bytes[64];
    uint32_t trng_read_len = 0u;

    for (;;) {
        request = uart_getc();
        /* TEMP DEBUG 0x30: read mask status without going through fw_mask_wait_ready. */
        if (request == 0x30u) {
            uint32_t ms = fw_mask_status();
            uart_putc(UART_RESPONSE);
            uart_putc(0u);
            uart_putc(0u);
            uart_putc(0u);
            uart_put_u32(ms);
            for (index = 0u; index < 8u; index++) uart_put_u32(0u);
            continue;
        }
        return_digest = 1u;
        response_value = 0u;
        signature_length = 0u;
        public_key_length = 0u;
        cycles = 0u;
        total_cycles = 0u;
#if LMS_FW_NO_HW_ACCEL || LMS_FW_PAPER_BENCH
        fw_total_cycles_hi = 0u;
        fw_steady_cycles_hi = 0u;
        fw_hardware_cycles_hi = 0u;
#endif
#if LMS_FW_PAPER_BENCH
        const uint64_t paper_cycles_start = paper_hw_cycles();
        const uint64_t paper_hits_start = paper_hw_hits();
        const uint32_t paper_accumulated_hits = hardware_hits;
#endif
        steady_total_cycles = 0u;
        parse_cycles = 0u;
        sign_cycles = 0u;
        if (request == LMS_OP_DIAG_7F) {

            for (index = 0; index < 128u; index++) {
                uint32_t w = MMIO32(LMS_INPUT + (index & ~3u));
                uart_putc((uint8_t)(w >> ((index & 3u) * 8u)));
            }
            continue;
        }
        if (request == LMS_OP_DIAG_7E) {

            for (index = 0; index < 48u; index++) {
                uint32_t w = MMIO32(LMS_OUTPUT + (index & ~3u));
                uart_putc((uint8_t)(w >> ((index & 3u) * 8u)));
            }
            continue;
        }
        if (request == LMS_OP_OTS_SNAPSHOT) {

            uart_putc(UART_RESPONSE);
            uart_putc(0u);
            uart_putc(dbg_valid ? 0u : 1u);
            uart_putc(0u);
            uart_put_u32(dbg_run);
            uart_put_u32(0u);
            uart_put_u32(0u);
            for (index = 0u; index < sizeof(dbg_meta); index++) uart_putc(dbg_meta[index]);
            for (index = 0u; index < sizeof(dbg_y); index++) uart_putc(dbg_y[index]);
            for (index = 0u; index < sizeof(dbg_coef); index++) uart_putc(dbg_coef[index]);
            for (index = 0u; index < sizeof(dbg_ep); index++) uart_putc(dbg_ep[index]);
            for (index = 0u; index < LMS_N; index++) uart_putc(dbg_kq[index]);
            continue;
        }
        if (request == LMS_OP_DIAG_7C) {

            uint8_t mode = uart_getc();
            uint8_t cap_a = uart_getc();
            uint8_t cap_b = uart_getc();
            uint32_t k;
            if (mode == 0u) {
                MMIO32(LMS_CAP_CTL) = ((uint32_t)(cap_a ? 1u : 0u) << 7) | (cap_b & 0x7fu);
            }
            uart_putc(UART_RESPONSE);
            uart_putc(0u);
            uart_putc(0u);
            uart_putc(0u);
            if (mode == 1u) {
                uart_put_u32(90u);
                uart_put_u32(0u);
                uart_put_u32(0u);
                for (k = 0u; k < 90u; k++) {
                    MMIO32(LMS_CAP_IDX) = k;
                    uart_put_u32(MMIO32(LMS_CAP_DATA));
                }
            } else {
                uart_put_u32(0u);
                uart_put_u32(0u);
                uart_put_u32(0u);
            }
            continue;
        }
        if (request == LMS_OP_DIAG_7D) {

            uart_putc(UART_RESPONSE);
            uart_putc(0u);
            uart_putc(0u);
            uart_putc(0u);
            uart_put_u32(MMIO32(LMS_TIMEOUT0));
            uart_put_u32(MMIO32(LMS_TIMEOUT1));
            uart_put_u32(0u);
            uart_put_u32(0u);
            continue;
        }
        if (request == LMS_OP_OTS_EVENTS) {

            uint32_t e;
            uint32_t w;
            uart_putc(UART_RESPONSE);
            uart_putc(0u);
            uart_putc(0u);
            uart_putc(0u);
            uart_put_u32(128u);
            uart_put_u32(128u);
            uart_put_u32(0u);
            for (e = 0u; e < 128u; e++) {
                for (w = 0u; w < 2u; w++) {
                    MMIO32(LMS_DBG_ADDR) = (2u << 14) | (e << 7) | w;
                    uart_put_u32(MMIO32(LMS_DBG_DATA));
                }
                for (w = 0u; w < 8u; w++) {
                    MMIO32(LMS_DBG_ADDR) = (0u << 14) | (e << 7) | w;
                    uart_put_u32(MMIO32(LMS_DBG_DATA));
                }
                for (w = 0u; w < 8u; w++) {
                    MMIO32(LMS_DBG_ADDR) = (1u << 14) | (e << 7) | w;
                    uart_put_u32(MMIO32(LMS_DBG_DATA));
                }
            }
            for (e = 0u; e < 128u; e++) {
                for (w = 0u; w < 2u; w++) {
                    MMIO32(LMS_DBG_ADDR) = (4u << 14) | (e << 7) | w;
                    uart_put_u32(MMIO32(LMS_DBG_DATA));
                }
                for (w = 0u; w < 8u; w++) {
                    MMIO32(LMS_DBG_ADDR) = (3u << 14) | (e << 7) | w;
                    uart_put_u32(MMIO32(LMS_DBG_DATA));
                }
            }
            continue;
        }
        if (request == UART_REQUEST_HASH) {
            input_length = uart_getc();
            status = hash_once_from_uart(input_length, &cycles);
            error = input_length > 128u ? 3u : MMIO32(LMS_ERROR);
        } else if (request == UART_REQUEST_DERIVE_RANDOMIZER) {

            status = derive_randomizer_from_uart(&cycles);
            error = MMIO32(LMS_ERROR);
        } else if (request == UART_REQUEST_PRF_CHAIN) {

            status = prf_chain_from_uart(&cycles);
            error = MMIO32(LMS_ERROR);
        } else if (request == UART_REQUEST_DERIVE_XQ) {

            status = derive_xq_from_uart(&cycles);
            error = MMIO32(LMS_ERROR);
            return_digest = 0u;
            response_value = 0u;
        } else if (request == UART_REQUEST_CHAIN) {
            status = chain_from_uart(&cycles);
            error = MMIO32(LMS_ERROR);
        } else if (request == UART_REQUEST_VERIFY) {
            status = verify_from_uart(&cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_SIGN_TEST) {
            status = sign_from_uart(s_uart_sig, &signature_length,
                                    &response_value, &cycles, &total_cycles,
                                    &steady_total_cycles, &parse_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_KEYGEN_TEST) {
            keygen_trace(9u);  /* 0xA9: dispatch reached 0x60 */
            status = keygen_from_uart(keygen_public_key, &public_key_length, &cycles,
                                      &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_LMOTS_KEYGEN_TEST) {
            stage_ping(9);
            status = lmots_keygen_from_uart(lmots_public_key, &cycles, &total_cycles);
            stage_ping(10);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_LMOTS_SIGN_TEST) {
            status = lmots_sign_from_uart(s_uart_sig, &cycles, &total_cycles,
                                          &parse_cycles, &sign_cycles,
                                          &steady_total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_LMOTS_VERIFY_TEST) {
            status = lmots_verify_from_uart(&cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_SEED_LOAD_TEST) {
            status = seed_load_from_uart(&cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
        } else if (request == UART_REQUEST_C_LOAD) {
            status = c_load_from_uart(&error);
            return_digest = 0u;
        } else if (request == LMS_OP_KEYGEN_STAGE) {

            uart_putc(UART_RESPONSE);
            uart_putc(0u);
            uart_putc(0u);
            uart_putc(0u);
            uart_put_u32(g_keygen_stage);
            uart_put_u32(verify_client.last_hw_error);
            uart_put_u32(hardware_hits);
            uart_put_u32(MMIO32(SOC_CYCLE_COUNT));
            continue;
        } else if (request == LMS_OP_SEED_ECHO) {

            for (index = 0u; index < 8u; index++) {
                uint32_t word = MMIO32(LMS_BASE + 0x1C0u + (index << 2));
                seed_echo[index * 4u + 0u] = (uint8_t)(word >> 24);
                seed_echo[index * 4u + 1u] = (uint8_t)(word >> 16);
                seed_echo[index * 4u + 2u] = (uint8_t)(word >> 8);
                seed_echo[index * 4u + 3u] = (uint8_t)word;
            }
            status = LMS_STATUS_DONE;
            error = 0u;
            return_digest = 0u;
        } else if (request == LMS_OP_OTS_COEFFS) {

            uint8_t priv69[LMS_PRIVATE_KEY_LEN];
            lms_private_key_t pk69;
            uint32_t mlen;
            uint32_t k69;
            uart_read_bytes(priv69, sizeof(priv69));
            mlen = (uint32_t)uart_getc() << 8;
            mlen |= (uint32_t)uart_getc();
            if (mlen > VERIFY_MESSAGE_MAX) {

                uart_discard(mlen - VERIFY_MESSAGE_MAX);
                mlen = VERIFY_MESSAGE_MAX;
            }
            uart_read_bytes(s_uart_msg, (size_t)mlen);
            for (k69 = 0u; k69 < sizeof(sign_dump); k69++) {
                sign_dump[k69] = 0u;
            }
            status = 0u;
            error = 0u;

            lmots_coef_backend_set(NULL, NULL);
            if (lms_private_key_parse(&pk69, priv69, sizeof(priv69)) != LMS_OK) {
                error = 0xE1u;
            } else {
                lmots_param_t p69;

                if (lms_get_lmots_param(pk69.lmots_type, &p69) != LMS_OK ||
                    p69.p > (sizeof(sign_dump) - LMS_N)) {
                    error = 0xE3u;
                } else if (lmots_sign_prepare(&pk69, pk69.q, s_uart_msg, (size_t)mlen,
                                              sign_dump, sign_dump + LMS_N) != LMS_OK) {
                    error = 0xE2u;
                } else {
                    status = LMS_STATUS_DONE;
                }
            }
#if !LMS_FW_NO_HW_ACCEL
            lmots_coef_backend_set(hw_coef_backend, &verify_client);
#endif
            return_digest = 0u;
        } else if (request == UART_REQUEST_SEC_SIGN) {
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP)) { continue; }
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            sec_sign_from_uart(nvm_response, s_uart_sig, &signature_length,
                               &cycles, &total_cycles);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
#if !LMS_FW_NO_HW_ACCEL
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP) ||
                sec_key_ready() == 0u) { continue; }
            status = sec_lms_sign_from_uart(s_uart_sig, &signature_length,
                                            &response_value, &cycles, &total_cycles,
                                            &steady_total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;

            if (status != LMS_STATUS_DONE || error != 0u) {
                sign_y_in_taskram = 0u;
            }
#else
            continue;
#endif
        } else if (request == UART_REQUEST_SEC_LMS_KEYGEN) {
#if !LMS_FW_NO_HW_ACCEL
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP) ||
                sec_key_ready() == 0u) { continue; }
            status = sec_lms_keygen_from_uart(keygen_public_key, &public_key_length,
                                              &cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
#else
            continue;
#endif
        } else if (request == UART_REQUEST_SEC_LMS_KEYGEN_NEW) {
#if !LMS_FW_NO_HW_ACCEL
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP) ||
                sec_key_ready() == 0u) { continue; }
            status = sec_lms_keygen_new_from_uart(keygen_public_key, &public_key_length,
                                                  &cycles, &total_cycles);
            error = verify_client.last_hw_error;
            return_digest = 0u;
#else
            continue;
#endif
        } else if (request == UART_REQUEST_NVM_SYNC) {
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP)) { continue; }
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            nvm_sync_from_uart(nvm_response);
            status = LMS_STATUS_DONE;
            error = 0u;
            return_digest = 0u;
        } else if (request == UART_REQUEST_SEC_STATE) {
            if (!(verify_client.capabilities & LMS_MMIO_CAP_WRAP)) { continue; }
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            sec_state_from_uart(nvm_response);
            status = LMS_STATUS_DONE;
            error = 0u;
            return_digest = 0u;
        } else if (request == UART_REQUEST_TRNG_READ) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            trng_read_len = trng_read_from_uart(nvm_response, trng_read_bytes, 0u);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_TRNG_READ_ACK) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            trng_read_len = trng_read_from_uart(nvm_response, trng_read_bytes, 1u);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_TRNG_STATUS) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            trng_status_from_uart(nvm_response);
            status = LMS_STATUS_DONE;
            error = 0u;
            return_digest = 0u;
        } else if (request == UART_REQUEST_FLASH_PROBE) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            flash_probe_from_uart(nvm_response);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_FLASH_PROG) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            flash_prog_from_uart(nvm_response);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else if (request == UART_REQUEST_FLASH_CMD) {
            for (index = 0u; index < sizeof(nvm_response); index++) {
                nvm_response[index] = 0u;
            }
            flash_cmd_from_uart(nvm_response);
            status = (nvm_response[2] == 0u) ? LMS_STATUS_DONE : 0u;
            error = (uint32_t)nvm_response[2];
            return_digest = 0u;
        } else {

            status = 0u;
            error = 0xEEu;
            cycles = 0u;
            total_cycles = 0u;
            return_digest = 0u;
        }

#if LMS_FW_PAPER_BENCH
        if (paper_request(request)) {
            uint64_t measured_hw = paper_hw_cycles() - paper_cycles_start;
            cycles = (uint32_t)measured_hw;
            fw_hardware_cycles_hi = (uint32_t)(measured_hw >> 32);
            hardware_hits = paper_accumulated_hits + (uint32_t)(paper_hw_hits() - paper_hits_start);
        }
#endif
        if (request == UART_REQUEST_LMOTS_KEYGEN_TEST) {
            stage_ping(11);
        }
        uart_putc(UART_RESPONSE);
        uart_putc(status == LMS_STATUS_DONE && error == 0u ? 0u : 1u);
        uart_putc((uint8_t)error);
        uart_putc(0u);
        uart_put_u32(cycles);
        uart_put_u32(hardware_hits);
        uart_put_u32(0u);
        if (request == UART_REQUEST_LMOTS_KEYGEN_TEST) {
            stage_ping(12);
        }
        for (index = 0; index < 32u; index += 4u) {
            uint32_t word;
            if (return_digest && error == 0u) {
#if LMS_FW_NO_HW_ACCEL
                if (request == UART_REQUEST_DERIVE_RANDOMIZER ||
                    request == UART_REQUEST_PRF_CHAIN) {

                    word = (uint32_t)s_uart_msg[index] |
                           ((uint32_t)s_uart_msg[index + 1u] << 8) |
                           ((uint32_t)s_uart_msg[index + 2u] << 16) |
                           ((uint32_t)s_uart_msg[index + 3u] << 24);
                } else
#endif
                {
                    word = MMIO32(LMS_OUTPUT + index);
                }
            } else if (request == UART_REQUEST_NVM_SYNC ||
                       request == UART_REQUEST_SEC_STATE ||
                       request == UART_REQUEST_SEC_SIGN ||
                       request == UART_REQUEST_TRNG_READ ||
                       request == UART_REQUEST_TRNG_READ_ACK ||
                       request == UART_REQUEST_TRNG_STATUS ||
                       request == UART_REQUEST_FLASH_PROBE ||
                       request == UART_REQUEST_FLASH_PROG ||
                       request == UART_REQUEST_FLASH_CMD) {
                word = (uint32_t)nvm_response[index] |
                       ((uint32_t)nvm_response[index + 1u] << 8) |
                       ((uint32_t)nvm_response[index + 2u] << 16) |
                       ((uint32_t)nvm_response[index + 3u] << 24);
#if LMS_FW_PAPER_BENCH
            } else if (paper_request(request) && index == 12u) {
                word = fw_hardware_cycles_hi; /* header +28 */
            } else if (paper_request(request) && index == 16u) {
                word = steady_total_cycles; /* header +32, common Sign low */
            } else if (paper_request(request) && index == 20u) {
                word = fw_steady_cycles_hi; /* header +36 */
            } else if (paper_request(request) && index == 24u) {
                word = 0x50423634u; /* PB64 protocol marker, header +40 */
            } else if (paper_request(request) && index == 28u) {
                word = fw_total_cycles_hi; /* header +44 */
#endif
            } else if (index == 0u) {
                word = response_value;
            } else if (index == 4u) {
                word = total_cycles;
            } else if (index == 8u) {
                if (request == UART_REQUEST_SIGN_TEST ||
                    request == UART_REQUEST_SEC_LMS_SIGN) {
                    word = steady_total_cycles;
                } else if (request == UART_REQUEST_LMOTS_SIGN_TEST) {
                    word = parse_cycles;
                } else {
                    word = 0u;
                }
            } else if (index == 12u) {
                if (request == UART_REQUEST_SIGN_TEST) {
                    word = parse_cycles;
                } else if (request == UART_REQUEST_LMOTS_SIGN_TEST) {
                    word = sign_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
#if defined(LMS_MMIO_SOC_PROFILE)
                    word = sec_prof_stc_cycles;
#else
                    word = 0u;
#endif
                } else {
                    word = 0u;
                }
            } else if (index == 16u) {

                if (request == UART_REQUEST_LMOTS_SIGN_TEST) {
                    word = steady_total_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
#if defined(LMS_MMIO_SOC_PROFILE)
                    word = prof_sec_enable_cycles;
#else
                    word = 0u;
#endif
                } else {
                    word = 0u;
                }
            } else if (index == 20u) {
#if defined(LMS_MMIO_SOC_PROFILE)
                if (request == UART_REQUEST_LMOTS_SIGN_TEST ||
                    request == UART_REQUEST_LMOTS_VERIFY_TEST) {
                    word = verify_client.prof_write_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
                    word = prof_sec_sign_cycles;
                } else {
                    word = 0u;
                }
#else
                word = 0u;
#endif
#if LMS_FW_NO_HW_ACCEL
            } else if ((request == UART_REQUEST_KEYGEN_TEST ||
                        request == UART_REQUEST_SIGN_TEST ||
                        request == UART_REQUEST_VERIFY) && index == 24u) {
                word = 0x53573634u; /* SW64 version marker at header +40. */
            } else if ((request == UART_REQUEST_KEYGEN_TEST ||
                        request == UART_REQUEST_SIGN_TEST ||
                        request == UART_REQUEST_VERIFY) && index == 28u) {
                word = fw_total_cycles_hi; /* header +44 */
#endif
            } else if (index == 24u) {
#if defined(LMS_MMIO_SOC_PROFILE)
                if (request == UART_REQUEST_LMOTS_SIGN_TEST ||
                    request == UART_REQUEST_LMOTS_VERIFY_TEST) {
                    word = verify_client.prof_wait_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
                    word = prof_sec_tail_cycles;
                } else {
                    word = 0u;
                }
#else
                word = 0u;
#endif
            } else if (index == 28u) {
#if defined(LMS_MMIO_SOC_PROFILE)
                if (request == UART_REQUEST_LMOTS_SIGN_TEST ||
                    request == UART_REQUEST_LMOTS_VERIFY_TEST) {
                    word = verify_client.prof_read_cycles;
                } else if (request == UART_REQUEST_SEC_LMS_SIGN) {
                    word = sec_prof_enc_cycles;
                } else {
                    word = 0u;
                }
#else
                word = 0u;
#endif
            } else {
                word = 0u;
            }
            uart_put_u32(word);
        }
        if (request == UART_REQUEST_SEC_SIGN && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < signature_length; index++) {
                uart_putc(s_uart_sig[index]);
            }
        }
        if (request == UART_REQUEST_TRNG_READ && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < trng_read_len; index++) {
                uart_putc(trng_read_bytes[index]);
            }
        }

        if (request == UART_REQUEST_TRNG_READ_ACK && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < trng_read_len; index++) {
                uart_putc(trng_read_bytes[index]);
            }
            uart_putc(crc8_block(trng_read_bytes, trng_read_len));
        }
        if (request == UART_REQUEST_SIGN_TEST && status == LMS_STATUS_DONE && error == 0u) {
#if LMS_FW_NO_HW_ACCEL

            for (index = 0; index < signature_length; index++) {
                uart_putc(s_uart_sig[index]);
            }
#else
            if (sign_y_in_taskram) {

                for (index = 0; index < 40u && index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
                (void)bridge_run(BRIDGE_DIR_TX, BRIDGE_Y_ADDR, sign_y_len);
                for (index = 40u + sign_y_len; index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            } else {

                for (index = 0; index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            }
            sign_y_in_taskram = 0u;
#endif
        }

        if (request == UART_REQUEST_SEC_LMS_SIGN && status == LMS_STATUS_DONE && error == 0u) {
            if (sign_y_in_taskram) {
                for (index = 0; index < 40u && index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
                (void)bridge_run(BRIDGE_DIR_TX, BRIDGE_Y_ADDR, sign_y_len);
                for (index = 40u + sign_y_len; index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            } else {
                for (index = 0; index < signature_length; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            }
            sign_y_in_taskram = 0u;
        }

        if (request == UART_REQUEST_SEC_LMS_KEYGEN && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < public_key_length; index++) {
                uart_putc(keygen_public_key[index]);
            }
        }

        if (request == UART_REQUEST_SEC_LMS_KEYGEN_NEW && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < public_key_length; index++) {
                uart_putc(keygen_public_key[index]);
            }
        }
        if (request == UART_REQUEST_KEYGEN_TEST && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0; index < public_key_length; index++) {
                uart_putc(keygen_public_key[index]);
            }
        }
        if (request == UART_REQUEST_LMOTS_KEYGEN_TEST && status == LMS_STATUS_DONE && error == 0u) {
            stage_ping(13);
            for (index = 0; index < LMS_N; index++) {
                uart_putc(lmots_public_key[index]);
            }
            stage_ping(14);
        }
        if (request == LMS_OP_SEED_ECHO && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0u; index < 32u; index++) {
                uart_putc(seed_echo[index]);
            }
        }
        if (request == LMS_OP_OTS_COEFFS && status == LMS_STATUS_DONE && error == 0u) {
            for (index = 0u; index < sizeof(sign_dump); index++) {
                uart_putc(sign_dump[index]);
            }
        }
        if (request == UART_REQUEST_LMOTS_SIGN_TEST && status == LMS_STATUS_DONE && error == 0u) {
#if LMS_FW_NO_HW_ACCEL

            for (index = 0; index < lmots_out_sig_len; index++) {
                uart_putc(s_uart_sig[index]);
            }
#else
            if (sign_y_in_taskram) {

                for (index = 0; index < lmots_out_sig_len - sign_y_len; index++) {
                    uart_putc(s_uart_sig[index]);
                }
                (void)bridge_run(BRIDGE_DIR_TX, BRIDGE_Y_ADDR, sign_y_len);
            } else {

                for (index = 0; index < lmots_out_sig_len; index++) {
                    uart_putc(s_uart_sig[index]);
                }
            }
            sign_y_in_taskram = 0u;
#endif
        }
    }
}

static void fail(uint32_t code)
{
    MMIO32(GPIO_OUT) = code;

    uart_putc(0x55u);
    uart_putc((uint8_t)code);
    uart_putc(0xaau);
    for (;;) {
    }
}

void trap_entry(void) __attribute__((naked, aligned(4)));
void trap_entry(void)
{
    __asm__ volatile(
        "li   t3, 0x10000018\n"   /* GPIO_OUT */
        "li   t4, 0xF8\n"
        "sw   t4, 0(t3)\n"
        "csrr t0, mcause\n"
        "sw   t0, 0(t3)\n"
        "csrr t0, mepc\n"
        "sw   t0, 0(t3)\n"
        "1: j 1b\n");
}

static int fw_mask_wait_ready(void);

int main(void)
{
    __asm__ volatile("csrw mtvec, %0" : : "r"(trap_entry));
#if defined(FW_HASH_SHA256)
    static const uint32_t expected[8] = {
        0xbf1678bau, 0xeacf018fu, 0xde404141u, 0x2322ae5du,
        0xa36103b0u, 0x9c7a1796u, 0x61ff10b4u, 0xad1500f2u
    };
    static const uint32_t expected_cycles = 68u;
#else
    static const uint32_t expected[8] = {
        0x60663348u, 0x77a86013u, 0x0863681cu, 0x4d11c40cu,
        0x3045b48du, 0xeee1f1f8u, 0x37ea944fu, 0x39578be7u
    };
    static const uint32_t expected_cycles = 12u;
#endif
    uint32_t poll;
    uint32_t index;
#if !LMS_FW_NO_HW_ACCEL
    lms_mmio_bus_t verify_bus;
#endif

    uart_putc(0xb0u);
    if (fw_mask_wait_ready() != 0) {
        fail(LMS_FW_MASK_ERR);
    }
    uart_putc(0xb1u);
    uart_put_u32(fw_mask_status());
    MMIO32(LMS_COMMAND) = LMS_CMD_HASH_ONCE;
    MMIO32(LMS_INPUT_LENGTH) = 3u;
    MMIO32(LMS_OUTPUT_LENGTH) = 32u;
    MMIO32(LMS_INPUT) = 0x00636261u;
    MMIO32(LMS_CONTROL) = LMS_CTRL_START;

    for (poll = 0; poll < 1024u; poll++) {
        if ((MMIO32(LMS_STATUS) & LMS_STATUS_BUSY) == 0u) {
            break;
        }
    }
    if (poll == 1024u) {
        fail(0xe1u);
    }
    if (MMIO32(LMS_STATUS) != LMS_STATUS_DONE || MMIO32(LMS_ERROR) != 0u) {
        fail(0xe2u);
    }
    if (MMIO32(LMS_CYCLE_COUNT) != expected_cycles) {
        fail(0xe3u);
    }
#if defined(FW_HASH_SHA256)
    for (index = 0; index < 8u; index++) {
        if (MMIO32(LMS_OUTPUT + index * 4u) != expected[index]) {
            fail(0xe4u + index);
        }
    }
#else
    (void)index;
    (void)expected;
#endif

    {
        uint32_t st_run;
        for (st_run = 0u; st_run < 8u; st_run++) {
            if (fw_mask_wait_ready() != 0) {
                fail(LMS_FW_MASK_ERR);
            }
            if (fw_mask_selftest_once() != 0) {
                fail(0xf0u);
            }
        }
    }

    hardware_hits = 1u;

    for (index = 0u; index < NVM_STATE_LEN; index++) {
        nvm_state[index] = 0u;
    }
    for (index = 0u; index < NVM_STATE_LEN / NVM_CHUNK_LEN; index++) {
        nvm_crc[index] = 0u;
        nvm_valid[index] = 0u;
    }

#if !LMS_FW_NO_HW_ACCEL
    lms_mmio_bus_init_direct(&verify_bus, (volatile void *)(uintptr_t)LMS_BASE);
    if (lms_mmio_client_init(&verify_client, &verify_bus, 100000u, 0) != LMS_MMIO_OK ||
        lms_mmio_lmots_keygen_enable_insecure(&verify_client) != LMS_MMIO_OK ||
        lms_mmio_lmots_verify_enable(&verify_client) != LMS_MMIO_OK ||
        lms_mmio_lmots_sign_enable_insecure(&verify_client) != LMS_MMIO_OK) {
        fail(0xecu);
    }

    lms_mmio_lmots_sign_disable();

    verify_client.randomizer_c_slot = NULL;
    verify_client.trng_fill_c = NULL;
    verify_client.trng_context = NULL;
#ifdef LMS_FW_SEC_TEST_MODE

#else

    verify_client.trng_fill_c = fw_trng_fill_c;
#endif

    lms_intr_backend_set(hw_intr_backend, &verify_client);

    lmots_verify_leaf_backend_set(hw_verify_leaf, &verify_client);

#ifndef FW_VERIFY_SW_AUTHPATH
    lms_verify_authpath_backend_set(hw_dintr_authpath, &verify_client);
#endif

    lmots_message_hash_backend_set(hw_message_hash_backend, &verify_client);

    lmots_coef_backend_set(hw_coef_backend, &verify_client);

#if defined(LMS_FW_SEC_TEST_MODE)
    {
        uint8_t seed[LMS_SEED_LEN];
        for (index = 0u; index < LMS_SEED_LEN; index++) {
            seed[index] = (uint8_t)index;
        }
        if (fw_seed_load(seed) != LMS_MMIO_OK) {
            fail(0xedu);
        }
    }
#endif
#endif /* !LMS_FW_NO_HW_ACCEL */

#ifndef LMS_RND_IMPL_TRNG
    {
        uint8_t rnd_ctx[16];
        for (index = 0u; index < sizeof(rnd_ctx); index++) {
            rnd_ctx[index] = (uint8_t)(0x70u + index);
        }
        lms_rnd_det_seed(rnd_ctx, sizeof(rnd_ctx));
    }
#endif
    if (verify_client.capabilities & LMS_MMIO_CAP_WRAP) {
        sec_init(&verify_client);
    }

    MMIO32(GPIO_OUT) = 0xa5u;
    serve_uart();
}
