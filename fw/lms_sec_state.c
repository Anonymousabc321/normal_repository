#include "lms_sec_state.h"

#include <string.h>

#include "lms_rnd.h"
#include "sha256.h"

#ifdef LMS_RND_IMPL_TRNG
extern volatile uint32_t trng_fault;
#endif

#define SEC_MAGIC_STATE   0x4c4d5353u  /* "LMSS" */

#define SEC_OFF_MAGIC     0u
#define SEC_OFF_STATE     4u
#define SEC_OFF_CTR       6u
#define SEC_OFF_TXID      10u
#define SEC_BODY_LEN      48u
#define SEC_OFF_TAG       48u

#define SEC_OFF_RESERVED  14u

#define SEC_AAD_LEN       1u

#define SEC_HMAC_MSG_LEN  (SEC_BODY_LEN + SEC_AAD_LEN)

#define SEC_PUF_RESP_LEN 32u
#define SEC_HELPER_LEN   32u

#define SEC_KDF_DOMAIN "LMS-KDF"
#define SEC_KDF_LABEL_WRAP  "wrap"
#define SEC_KDF_LABEL_STATE "state"

static lms_mmio_client_t *sec_client;
static uint8_t  sec_slots[2][SEC_STATE_REC_LEN];
static uint8_t  sec_slot_valid[2];
static uint8_t  sec_active_slot;                   /* 0=A, 1=B */
static uint16_t sec_state;
static uint32_t sec_ctr;
static uint32_t sec_last_tx;                       /* last_committed_tx */
static uint8_t  sec_factory_locked;
static uint8_t  sec_key_loaded;
static uint8_t  sec_boot_complete;
static uint8_t  sec_keygen_pending;
static uint8_t  sec_helper[SEC_HELPER_LEN];
static uint8_t  sec_boot_valid[2];
static uint8_t  sec_wrapped_blob[LMS_MMIO_WRAPPED_LEN];
static uint8_t  sec_wrapped_valid;
static uint8_t  sec_key_I[LMS_I_LEN];
static uint32_t sec_key_index;
#if defined(LMS_MMIO_SOC_PROFILE)

#define SEC_PROF_MMIO32(address) (*(volatile uint32_t *)(uintptr_t)(address))
#define SEC_PROF_CYCLE_COUNT    0x10000010u
uint32_t sec_prof_commit1_cycles;
uint32_t sec_prof_dosign_cycles;
uint32_t sec_prof_commit2_cycles;

uint32_t sec_prof_stc_cycles;
uint32_t sec_prof_enc_cycles;
uint32_t sec_prof_mc_cycles;
uint32_t sec_prof_tag_cycles;
#endif

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void build_aad(uint8_t aad[SEC_AAD_LEN], uint8_t slot_id)
{
    aad[0] = slot_id;
}

static int compute_tag(const uint8_t body[SEC_BODY_LEN], uint8_t slot_id,
                       uint8_t tag[SEC_STATE_TAG_LEN])
{
    uint8_t msg[SEC_HMAC_MSG_LEN];
    uint8_t aad[SEC_AAD_LEN];
    uint8_t full[LMS_N];
    int status;

    build_aad(aad, slot_id);
    memcpy(msg, body, SEC_BODY_LEN);
    memcpy(msg + SEC_BODY_LEN, aad, SEC_AAD_LEN);
    status = lms_mmio_hmac_kstate(sec_client, msg, SEC_HMAC_MSG_LEN, full);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    memcpy(tag, full, SEC_STATE_TAG_LEN);
    return LMS_MMIO_OK;
}

static void encode_body(uint8_t body[SEC_BODY_LEN], uint16_t state, uint32_t ctr,
                        uint32_t tx_id)
{
    put_be32(body + SEC_OFF_MAGIC, SEC_MAGIC_STATE);
    put_be16(body + SEC_OFF_STATE, state);
    put_be32(body + SEC_OFF_CTR, ctr);
    put_be32(body + SEC_OFF_TXID, tx_id);

    memset(body + SEC_OFF_RESERVED, 0, SEC_BODY_LEN - SEC_OFF_RESERVED);
}

static uint8_t sec_rec_diag[2];
static int rec_valid(const uint8_t rec[SEC_STATE_REC_LEN], uint8_t slot_id)
{
    uint8_t tag[SEC_STATE_TAG_LEN];

    sec_rec_diag[slot_id] = 0u;
    if (get_be32(rec + SEC_OFF_MAGIC) != SEC_MAGIC_STATE) {
        sec_rec_diag[slot_id] = 1u;
        return 0;
    }
    if (compute_tag(rec, slot_id, tag) != LMS_MMIO_OK) {
        sec_rec_diag[slot_id] = 3u;
        return 0;
    }
    if (memcmp(tag, rec + SEC_OFF_TAG, SEC_STATE_TAG_LEN) != 0) {
        sec_rec_diag[slot_id] = 4u;
        return 0;
    }
    return 1;
}

static int rec_valid_check(const uint8_t rec[SEC_STATE_REC_LEN], uint8_t slot_id,
                           const uint8_t expected_tag[SEC_STATE_TAG_LEN])
{
    sec_rec_diag[slot_id] = 0u;
    if (get_be32(rec + SEC_OFF_MAGIC) != SEC_MAGIC_STATE) {
        sec_rec_diag[slot_id] = 1u;
        return 0;
    }
    if (memcmp(rec + SEC_OFF_TAG, expected_tag, SEC_STATE_TAG_LEN) != 0) {
        sec_rec_diag[slot_id] = 4u;
        return 0;
    }
    return 1;
}

static int slots_all_zero(void)
{
    uint32_t index;
    uint32_t k;
    for (index = 0u; index < 2u; index++) {
        for (k = 0u; k < SEC_STATE_REC_LEN; k++) {
            if (sec_slots[index][k] != 0u) {
                return 0;
            }
        }
    }
    return 1;
}

/* Fixed simulated device response for this FPGA prototype. */
static void sim_puf_read(uint8_t resp[SEC_PUF_RESP_LEN])
{
    uint32_t index;
    for (index = 0u; index < SEC_PUF_RESP_LEN; index++) {
        resp[index] = (uint8_t)(0x60u + index);
    }
}

static void fe_gen(const uint8_t puf_resp[SEC_PUF_RESP_LEN], uint8_t ctx,
                   uint8_t helper[SEC_HELPER_LEN], uint8_t k_dev[LMS_N])
{
    SHA256_CTX h;
    static const char domain[] = "LMS-FE";
    uint32_t index;

    SHA256_Init(&h);
    SHA256_Update(&h, (const uint8_t *)domain, (unsigned int)(sizeof(domain) - 1u));
    SHA256_Update(&h, puf_resp, SEC_PUF_RESP_LEN);
    SHA256_Update(&h, &ctx, 1u);
    SHA256_Final(k_dev, &h);
    for (index = 0u; index < SEC_HELPER_LEN; index++) {
        helper[index] = (uint8_t)(0xa0u + index);
    }
}

static void fe_rep(const uint8_t puf_resp[SEC_PUF_RESP_LEN],
                   const uint8_t helper[SEC_HELPER_LEN], uint8_t ctx,
                   uint8_t k_dev[LMS_N])
{
    uint8_t dummy[SEC_HELPER_LEN];
    (void)helper;
    fe_gen(puf_resp, ctx, dummy, k_dev);
}

static void sec_kdf(const uint8_t k_dev[LMS_N], const uint8_t I[LMS_I_LEN],
                    const char *label, size_t label_len, uint8_t out[LMS_N])
{
    SHA256_CTX h;
    uint8_t zero = 0u;

    SHA256_Init(&h);
    SHA256_Update(&h, (const uint8_t *)SEC_KDF_DOMAIN, sizeof(SEC_KDF_DOMAIN) - 1u);
    SHA256_Update(&h, &zero, 1u);
    SHA256_Update(&h, (const uint8_t *)label, (unsigned int)label_len);
    SHA256_Update(&h, &zero, 1u);
    SHA256_Update(&h, I, LMS_I_LEN);
    SHA256_Update(&h, &zero, 1u);
    SHA256_Update(&h, k_dev, LMS_N);
    SHA256_Final(out, &h);
}

static int sec_load_hw_keys_i(const uint8_t k_dev[LMS_N], const uint8_t I[LMS_I_LEN])
{
    uint8_t k_wrap[LMS_N];
    uint8_t k_state[LMS_N];
    int status;

    sec_kdf(k_dev, I, SEC_KDF_LABEL_WRAP, sizeof(SEC_KDF_LABEL_WRAP) - 1u, k_wrap);
    sec_kdf(k_dev, I, SEC_KDF_LABEL_STATE, sizeof(SEC_KDF_LABEL_STATE) - 1u, k_state);
    status = lms_mmio_key_slot_load_test(sec_client, LMS_MMIO_KEY_KWRAP, k_wrap);
    if (status == LMS_MMIO_OK) {
        status = lms_mmio_key_slot_load_test(sec_client, LMS_MMIO_KEY_KSTATE, k_state);
    }
    memset(k_wrap, 0, sizeof(k_wrap));
    memset(k_state, 0, sizeof(k_state));
    return status;
}

int sec_keygen_key(uint8_t I[LMS_I_LEN])
{
#if !defined(LMS_FW_SEC_TEST_MODE)
    /* Only rebuild the public tree for the registered key after recovery. */
    if (!sec_boot_complete || !sec_key_loaded) return SEC_ERR_PHASE;
    memcpy(I, sec_key_I, LMS_I_LEN);
    return SEC_OK;
#else
    uint8_t puf_resp[SEC_PUF_RESP_LEN];
    uint8_t k_dev[LMS_N];
    uint8_t wrapped[LMS_MMIO_WRAPPED_LEN];
    int status;

#ifdef LMS_FW_SEC_TEST_MODE
    memcpy(I, sec_key_I, LMS_I_LEN);
#else
    lms_rnd(I, LMS_I_LEN);
    memcpy(sec_key_I, I, LMS_I_LEN);
#endif

    sim_puf_read(puf_resp);
    fe_rep(puf_resp, sec_helper, 0u, k_dev);
    status = sec_load_hw_keys_i(k_dev, sec_key_I);  /* K_WRAP_i/K_STATE_i = KDF(K_DEV, label, I_i) */
    memset(puf_resp, 0, sizeof(puf_resp));
    memset(k_dev, 0, sizeof(k_dev));
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }

    status = lms_mmio_wrap_seed(sec_client, wrapped);
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }
    memcpy(sec_wrapped_blob, wrapped, LMS_MMIO_WRAPPED_LEN);
    sec_wrapped_valid = 1u;
    sec_key_loaded = 1u;
    memset(wrapped, 0, sizeof(wrapped));
    return SEC_OK;
#endif
}

int sec_keygen_new(uint8_t I_new[LMS_I_LEN])
{
#if !defined(LMS_FW_SEC_TEST_MODE)
    (void)I_new;
    return SEC_ERR_PHASE;
#else
    uint8_t puf_resp[SEC_PUF_RESP_LEN];
    uint8_t k_dev[LMS_N];
    uint8_t wrapped[LMS_MMIO_WRAPPED_LEN];
    int status;

#ifdef LMS_FW_SEC_TEST_MODE

    memcpy(sec_key_I, I_new, LMS_I_LEN);
#else

    {
        uint8_t new_seed[LMS_SEED_LEN];

        lms_rnd(sec_key_I, LMS_I_LEN);
        lms_rnd(new_seed, LMS_SEED_LEN);
#ifdef LMS_RND_IMPL_TRNG
        if (trng_fault != 0u) {
            memset(sec_key_I, 0, sizeof(sec_key_I));
            memset(new_seed, 0, sizeof(new_seed));
            return SEC_ERR_AUTH;
        }
#endif
        memcpy(I_new, sec_key_I, LMS_I_LEN);

        status = lms_mmio_seed_load_safe(sec_client, new_seed);
        memset(new_seed, 0, sizeof(new_seed));
        if (status != LMS_MMIO_OK) {
            memset(sec_key_I, 0, sizeof(sec_key_I));
            return SEC_ERR_AUTH;
        }
    }
#endif

    sim_puf_read(puf_resp);
    fe_rep(puf_resp, sec_helper, 0u, k_dev);
    status = sec_load_hw_keys_i(k_dev, sec_key_I);   /* K_WRAP_i/K_STATE_i = KDF(K_DEV, label, I_new) */
    memset(puf_resp, 0, sizeof(puf_resp));
    memset(k_dev, 0, sizeof(k_dev));
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }

    status = lms_mmio_wrap_seed(sec_client, wrapped);
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }
    memcpy(sec_wrapped_blob, wrapped, LMS_MMIO_WRAPPED_LEN);
    sec_wrapped_valid = 1u;
    memset(wrapped, 0, sizeof(wrapped));

    memset(sec_slots[0], 0, sizeof(sec_slots[0]));
    memset(sec_slots[1], 0, sizeof(sec_slots[1]));
    sec_slot_valid[0] = 0u;
    sec_slot_valid[1] = 0u;
    sec_active_slot = 0u;
    sec_state = SEC_ST_IDLE;
    sec_ctr = 0u;
    sec_last_tx = 0u;

    sec_key_loaded = 1u;
    sec_factory_locked = 1u;
    sec_keygen_pending = 0u;
    sec_key_index++;
    return SEC_OK;
#endif
}

void sec_init(lms_mmio_client_t *client)
{
    sec_client = client;
    memset(sec_slots, 0, sizeof(sec_slots));
    sec_slot_valid[0] = 0u;
    sec_slot_valid[1] = 0u;
    sec_active_slot = 0u;
    sec_state = SEC_ST_BOOTING;
    sec_ctr = 0u;
    sec_last_tx = 0u;
    sec_factory_locked = 0u;
    sec_key_loaded = 0u;
    sec_boot_complete = 0u;
    sec_keygen_pending = 0u;
    memset(sec_helper, 0, sizeof(sec_helper));
    sec_key_index = 0u;
}

/* Deployed signing state is owned by RTL. These variables are diagnostics only;
 * no RAM slot, tag comparison or firmware return value authorizes computation. */
static int sec_mirror_ksd(void)
{
#if !defined(LMS_FW_SEC_TEST_MODE)
    lms_mmio_ksd_status_t status;
    if (lms_mmio_ksd_read(sec_client, &status) != LMS_MMIO_OK) {
        sec_state = SEC_ST_ERROR_LOCKED;
        return 0;
    }
    sec_last_tx = status.last_tx;
    if (status.state == LMS_MMIO_KSD_IDLE || status.state == LMS_MMIO_KSD_EXHAUSTED) {
        sec_state = status.state == LMS_MMIO_KSD_IDLE ? SEC_ST_IDLE : SEC_ST_EXHAUSTED;
        sec_ctr = status.next_q;
    } else if (status.state >= LMS_MMIO_KSD_RESERVED_READY &&
               status.state <= LMS_MMIO_KSD_FINALIZE_PENDING) {
        sec_state = SEC_ST_RESERVED;
        sec_ctr = status.signing_q;
    } else if (status.state == LMS_MMIO_KSD_ERROR_LOCKED) {
        sec_state = SEC_ST_ERROR_LOCKED;
    } else {
        sec_state = SEC_ST_BOOTING;
    }
#endif
    return 1;
}

uint16_t sec_hw_state(void)
{
    (void)sec_mirror_ksd();
    return sec_state;
}

uint32_t sec_last_committed_tx(void)
{
    (void)sec_mirror_ksd();
    return sec_last_tx;
}

static int commit_finish(uint8_t inactive, uint16_t new_state, uint32_t ctr,
                         uint32_t tx, const uint8_t tag[SEC_STATE_TAG_LEN])
{
    if (tx <= sec_last_tx) {
        return 0;
    }
    encode_body(sec_slots[inactive], new_state, ctr, tx);
    memcpy(sec_slots[inactive] + SEC_OFF_TAG, tag, SEC_STATE_TAG_LEN);
    if (!rec_valid_check(sec_slots[inactive], inactive, tag)) {
        sec_slot_valid[inactive] = 0u;
        return 0;
    }
    sec_slot_valid[inactive] = 1u;
    sec_active_slot = inactive;
    sec_last_tx = tx;
    sec_state = new_state;
    sec_ctr = ctr;
    return 1;
}

static __attribute__((noinline)) int state_commit(uint16_t new_state, uint32_t ctr)
{
#if !defined(LMS_FW_SEC_TEST_MODE)
    int status;
    if (new_state == SEC_ST_RESERVED) {
        status = lms_mmio_ksd_begin(sec_client, ctr);
    } else if (new_state == SEC_ST_IDLE) {
        status = lms_mmio_ksd_finish(sec_client, ctr);
    } else {
        return 0;
    }
    if (!sec_mirror_ksd()) return 0;
    return status == LMS_MMIO_OK;
#else
    uint8_t inactive;
    uint8_t body[SEC_BODY_LEN];
    uint8_t tag[SEC_STATE_TAG_LEN];
    uint32_t tx;
    int status;
    int rc;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t sc_prof_t0 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    uint32_t sc_prof_t1 = 0u;
    uint32_t sc_prof_t2 = 0u;
#endif

    inactive = (uint8_t)(1u - sec_active_slot);

    if ((sec_client->capabilities & LMS_MMIO_CAP_STATE_COMMIT) != 0u) {

        status = lms_mmio_state_commit(sec_client, new_state, ctr, inactive, &tx, tag);
        if (status != LMS_MMIO_OK) {
            return 0;
        }
#if defined(LMS_MMIO_SOC_PROFILE)
        sc_prof_t1 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
        sec_prof_stc_cycles = sc_prof_t1 - sc_prof_t0;
#endif
        rc = commit_finish(inactive, new_state, ctr, tx, tag);
#if defined(LMS_MMIO_SOC_PROFILE)
        if (rc != 0) {
            sec_prof_enc_cycles = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT) - sc_prof_t1;
        }
#endif
        return rc;
    }

    status = lms_mmio_mc_step(sec_client, &tx);
    if (status != LMS_MMIO_OK) {
        return 0;
    }
    if (tx <= sec_last_tx) {
        return 0;
    }
#if defined(LMS_MMIO_SOC_PROFILE)
    sc_prof_t1 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    sec_prof_mc_cycles = sc_prof_t1 - sc_prof_t0;
#endif
    encode_body(body, new_state, ctr, tx);
    status = compute_tag(body, inactive, tag);
    if (status != LMS_MMIO_OK) {
        sec_slot_valid[inactive] = 0u;
        return 0;
    }
#if defined(LMS_MMIO_SOC_PROFILE)
    sc_prof_t2 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    sec_prof_tag_cycles = sc_prof_t2 - sc_prof_t1;
#endif
    rc = commit_finish(inactive, new_state, ctr, tx, tag);
#if defined(LMS_MMIO_SOC_PROFILE)
    if (rc != 0) {
        sec_prof_enc_cycles = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT) - sc_prof_t2;
    }
#endif
    return rc;
#endif
}

static int sec_factory_init(const uint8_t I[LMS_I_LEN], uint8_t response[32])
{
    uint8_t puf_resp[SEC_PUF_RESP_LEN];
    uint8_t k_dev[LMS_N];
    uint8_t seed[LMS_SEED_LEN];
    uint8_t wrapped[LMS_MMIO_WRAPPED_LEN];
    uint32_t index;
    int status;

#if !defined(LMS_FW_SEC_TEST_MODE)

    (void)puf_resp; (void)k_dev; (void)seed; (void)wrapped; (void)index;
    response[2] = SEC_ERR_UNSUPPORTED;
    return SEC_ERR_UNSUPPORTED;
#endif

    if (sec_factory_locked != 0u) {
        return SEC_ERR_FACTORY_LOCKED;
    }

    sim_puf_read(puf_resp);
    fe_gen(puf_resp, 0u, sec_helper, k_dev);

    memcpy(sec_key_I, I, LMS_I_LEN);
    status = sec_load_hw_keys_i(k_dev, sec_key_I);
    memset(puf_resp, 0, sizeof(puf_resp));
    memset(k_dev, 0, sizeof(k_dev));
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }

    for (index = 0u; index < LMS_SEED_LEN; index++) {
        seed[index] = (uint8_t)index;
    }
    status = lms_mmio_seed_load_test(sec_client, 0u, seed);
    memset(seed, 0, sizeof(seed));
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }
    status = lms_mmio_wrap_seed(sec_client, wrapped);
    if (status != LMS_MMIO_OK) {
        return SEC_ERR_AUTH;
    }

    memcpy(sec_wrapped_blob, wrapped, LMS_MMIO_WRAPPED_LEN);
    sec_wrapped_valid = 1u;

    sec_factory_locked = 1u;
    sec_keygen_pending = 0u;

    response[4] = 0x46u;
    for (index = 0u; index < 8u; index++) {
        response[20u + index] = sec_helper[index];
        response[28u + index] = (index < 4u) ? wrapped[index] : 0u;
    }
    memset(wrapped, 0, sizeof(wrapped));
    return SEC_OK;
}

static int sec_phase_init_open(void)
{
#if !defined(LMS_FW_SEC_TEST_MODE)
    return sec_boot_complete == 0u;
#else
    return (sec_state == SEC_ST_BOOTING) ? 1 : 0;
#endif
}

static int sec_phase_gate(uint8_t response[32])
{
    if (sec_phase_init_open() != 0) {
        return 0;
    }
    response[2] = (uint8_t)SEC_ERR_PHASE;
    return 1;
}

/* Trusted setup transports keys before sideband recovery locks them. The host
 * must authorize this setup phase; hardware independently rejects runtime key
 * loading. Neither this command nor BOOT can send a persistence ACK. */
static int sec_provision(const uint8_t I[LMS_I_LEN])
{
#if !defined(LMS_FW_SEC_TEST_MODE)
    uint8_t puf_resp[SEC_PUF_RESP_LEN], k_dev[LMS_N];
    lms_mmio_ksd_status_t status;
    int rc;
    if (!sec_phase_init_open() ||
        lms_mmio_ksd_read(sec_client, &status) != LMS_MMIO_OK ||
        status.state != LMS_MMIO_KSD_RECOVERY_LOCKED) return SEC_ERR_PHASE;
    if (!sec_wrapped_valid) return SEC_ERR_AUTH;
    memcpy(sec_key_I, I, LMS_I_LEN);
    sim_puf_read(puf_resp);
    fe_rep(puf_resp, sec_helper, 0u, k_dev);
    rc = sec_load_hw_keys_i(k_dev, sec_key_I);
    memset(puf_resp, 0, sizeof(puf_resp));
    memset(k_dev, 0, sizeof(k_dev));
    if (rc != LMS_MMIO_OK ||
        lms_mmio_unwrap_seed(sec_client, sec_wrapped_blob) != LMS_MMIO_OK)
        return SEC_ERR_AUTH;
    sec_key_loaded = 1u;
    sec_state = SEC_ST_BOOTING;
    return SEC_OK;
#else
    (void)I;
    return SEC_ERR_UNSUPPORTED;
#endif
}

int sec_boot(const uint8_t I[LMS_I_LEN])
{

    if (sec_phase_init_open() == 0) {
        return SEC_ERR_PHASE;
    }
#if !defined(LMS_FW_SEC_TEST_MODE)
    /* Never select a RAM slot, recompute a tag or reload keys after recovery. */
    if (!sec_key_loaded || memcmp(I, sec_key_I, LMS_I_LEN) != 0)
        return SEC_ERR_AUTH;
    if (lms_mmio_ksd_wait_recovery(sec_client) != LMS_MMIO_OK || !sec_mirror_ksd())
        return SEC_ERR_LOCKED;
    sec_boot_complete = 1u;
    sec_factory_locked = 1u;
    return SEC_OK;
#else
    sec_state = SEC_ST_BOOTING;
    {
        uint8_t puf_resp[SEC_PUF_RESP_LEN];
        uint8_t k_dev[LMS_N];
        uint8_t valid[2];
        uint32_t tx[2];
        int8_t chosen;
        uint16_t rec_state;
        uint32_t rec_ctr;
        int status;

        memcpy(sec_key_I, I, LMS_I_LEN);
        sim_puf_read(puf_resp);
        fe_rep(puf_resp, sec_helper, 0u, k_dev);
        status = sec_load_hw_keys_i(k_dev, sec_key_I);
        memset(puf_resp, 0, sizeof(puf_resp));
        memset(k_dev, 0, sizeof(k_dev));
        if (status != LMS_MMIO_OK) {
            sec_state = SEC_ST_ERROR_LOCKED;
            return SEC_ERR_AUTH;
        }
        sec_key_loaded = 1u;

#if !defined(LMS_FW_SEC_TEST_MODE)

        if (sec_wrapped_valid != 0u) {
            status = lms_mmio_unwrap_seed(sec_client, sec_wrapped_blob);
            sec_factory_locked = 1u;
            if (status != LMS_MMIO_OK) {
                sec_state = SEC_ST_ERROR_LOCKED;
                return SEC_ERR_AUTH;
            }
        }
#endif

        valid[0] = (uint8_t)rec_valid(sec_slots[0], 0u);
        valid[1] = (uint8_t)rec_valid(sec_slots[1], 1u);
        sec_boot_valid[0] = valid[0];
        sec_boot_valid[1] = valid[1];
        tx[0] = get_be32(sec_slots[0] + SEC_OFF_TXID);
        tx[1] = get_be32(sec_slots[1] + SEC_OFF_TXID);

        chosen = -1;
        if (valid[0] != 0u && valid[1] != 0u) {
            if (tx[0] == tx[1]) {

                if (memcmp(sec_slots[0], sec_slots[1], SEC_OFF_TAG) != 0) {
                    sec_state = SEC_ST_ERROR_LOCKED;
                    return SEC_ERR_LOCKED;
                }
                chosen = 0;
            } else {
                chosen = (tx[0] > tx[1]) ? 0 : 1;
            }
        } else if (valid[0] != 0u) {
            chosen = 0;
        } else if (valid[1] != 0u) {
            chosen = 1;
        }

        if (chosen < 0) {

            if (sec_factory_locked != 0u) {
                if (slots_all_zero()) {

                    sec_state = SEC_ST_IDLE;
                    sec_ctr = 0u;
                } else {

                    sec_state = SEC_ST_ERROR_LOCKED;
                    return SEC_ERR_LOCKED;
                }
            } else {

                return SEC_RSP_BUSY;
            }
        } else {
            sec_active_slot = (uint8_t)chosen;
            sec_slot_valid[0] = valid[0];
            sec_slot_valid[1] = valid[1];
            sec_last_tx = tx[chosen];
            rec_state = get_be16(sec_slots[chosen] + SEC_OFF_STATE);
            rec_ctr = get_be32(sec_slots[chosen] + SEC_OFF_CTR);

            if (rec_state == SEC_ST_RESERVED) {

                if (!state_commit(SEC_ST_IDLE, rec_ctr + 1u)) {
                    sec_state = SEC_ST_ERROR_LOCKED;
                    return SEC_ERR_COMMIT;
                }
            } else if (rec_state == SEC_ST_KEYGEN_PENDING) {

                sec_keygen_pending = 1u;
                sec_state = SEC_ST_KEYGEN_PENDING;
                sec_ctr = rec_ctr;
            } else if (rec_state == SEC_ST_IDLE || rec_state == SEC_ST_EXHAUSTED) {
                sec_state = rec_state;
                sec_ctr = rec_ctr;
            } else {
                sec_state = SEC_ST_ERROR_LOCKED;
                return SEC_ERR_LOCKED;
            }
        }

        if (sec_state != SEC_ST_ERROR_LOCKED && sec_state != SEC_ST_BOOTING) {
            sec_factory_locked = 1u;
        }
    }
    return SEC_OK;
#endif
}

uint32_t sec_ctr_value(void)
{
    (void)sec_mirror_ksd();
    return sec_ctr;
}

uint8_t sec_key_ready(void)
{
    return sec_key_loaded;
}

uint8_t sec_keygen_pending_flag(void)
{
    return sec_keygen_pending;
}

void sec_export_active(uint8_t out[SEC_STATE_REC_LEN])
{
    memcpy(out, sec_slots[sec_active_slot], SEC_STATE_REC_LEN);
}

/* Independent firmware check against the actual active RAM record, not the
 * return register of state_commit(). This is defense against a skipped reserve
 * call in the single-instruction fault model; it is NOT an endpoint durable ACK
 * or a hardware boundary against compromised firmware. Keep the HMAC check
 * separate from commit_finish's comparison with its freshly computed tag. */
static __attribute__((noinline)) int reservation_ram_matches(uint32_t q, uint32_t previous_tx)
{
#if !defined(LMS_FW_SEC_TEST_MODE)
    lms_mmio_ksd_status_t status;
    return lms_mmio_ksd_read(sec_client, &status) == LMS_MMIO_OK &&
        status.state == LMS_MMIO_KSD_RESERVED_READY &&
        status.signing_q == q && status.last_tx > previous_tx;
#else
    const uint8_t *record;
    uint8_t slot = sec_active_slot;
    if (slot > 1u || sec_slot_valid[slot] == 0u ||
        sec_state != SEC_ST_RESERVED || sec_ctr != q ||
        sec_last_tx <= previous_tx) {
        return 0;
    }
    record = sec_slots[slot];
    if (get_be16(record + SEC_OFF_STATE) != SEC_ST_RESERVED ||
        get_be32(record + SEC_OFF_CTR) != q ||
        get_be32(record + SEC_OFF_TXID) != sec_last_tx) {
        return 0;
    }
    return rec_valid(record, slot);
#endif
}

int sec_sign(uint32_t max_ctr,
             int (*do_sign)(uint32_t q, void *ctx), void *ctx,
             uint32_t *q_out)
{
    uint32_t q;
    uint32_t previous_tx;
    int sign_rc;
    (void)sec_mirror_ksd();
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t sec_prof_t0 = 0u;
    uint32_t sec_prof_t1 = 0u;
    uint32_t sec_prof_t2 = 0u;
    uint32_t sec_prof_t3 = 0u;
#endif

    if (q_out != 0) {
        *q_out = 0u;
    }

    if (sec_state == SEC_ST_ERROR_LOCKED) {
        return SEC_ERR_LOCKED;
    }
    if (sec_state != SEC_ST_IDLE) {
        return SEC_RSP_BUSY;  /* BOOTING/RESERVED/KEYGEN_PENDING */
    }
    if (sec_key_loaded == 0u) {
        return SEC_ERR_LOCKED;
    }
    if (max_ctr == 0u || sec_ctr >= max_ctr) {
        sec_state = SEC_ST_EXHAUSTED;
        return SEC_ERR_EXHAUSTED;
    }

    q = sec_ctr;
    previous_tx = sec_last_tx;
#if defined(LMS_MMIO_SOC_PROFILE)
    sec_prof_t0 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
#endif

    if (!state_commit(SEC_ST_RESERVED, q) ||
        !reservation_ram_matches(q, previous_tx)) {

        (void)state_commit(SEC_ST_IDLE, q + 1u);
        return SEC_ERR_COMMIT;
    }

#if defined(LMS_MMIO_SOC_PROFILE)
    sec_prof_t1 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    sec_prof_commit1_cycles = sec_prof_t1 - sec_prof_t0;
#endif

    sign_rc = (do_sign != 0) ? do_sign(q, ctx) : LMS_ERR_INVALID;

#if defined(LMS_MMIO_SOC_PROFILE)
    sec_prof_t2 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
    sec_prof_dosign_cycles = sec_prof_t2 - sec_prof_t1;
#endif

    if (sign_rc == LMS_OK &&
        state_commit(SEC_ST_IDLE, q + 1u)) {
#if defined(LMS_MMIO_SOC_PROFILE)
        sec_prof_t3 = SEC_PROF_MMIO32(SEC_PROF_CYCLE_COUNT);
        sec_prof_commit2_cycles = sec_prof_t3 - sec_prof_t2;
#endif
        if (q_out != 0) {
            *q_out = q;
        }
        return SEC_OK;
    }

    (void)state_commit(SEC_ST_IDLE, q + 1u);
    return (sign_rc != LMS_OK) ? SEC_ERR_PATH : SEC_ERR_COMMIT;
}

static int sec_uart_commit_allowed(uint16_t new_state, uint32_t ctr)
{
    switch (sec_state) {
    case SEC_ST_IDLE:

        if (new_state == SEC_ST_RESERVED || new_state == SEC_ST_KEYGEN_PENDING ||
            new_state == SEC_ST_IDLE || new_state == SEC_ST_EXHAUSTED) {
            return ctr >= sec_ctr;
        }
        return 0;
    case SEC_ST_RESERVED:

        if (new_state == SEC_ST_IDLE) {
            return ctr > sec_ctr;
        }
        return 0;
    case SEC_ST_KEYGEN_PENDING:

        if (new_state == SEC_ST_IDLE) {
            return ctr >= sec_ctr;
        }
        return 0;
    default:

        return 0;
    }
}

int sec_handle_uart_cmd(uint8_t sub, const uint8_t *params, uint8_t response[32])
{
    uint32_t new_state;
    uint32_t ctr;
    uint8_t slot;
    uint32_t index;
    int rc;

    memset(response, 0, 32u);
    response[0] = sub;
    response[2] = SEC_OK;
    response[3] = (uint8_t)(sec_slot_valid[0] | (uint8_t)(sec_slot_valid[1] << 1));

    if (sub == SEC_SUB_PROVISION) {
        rc = sec_provision(params);
        response[2] = (uint8_t)rc;
        return rc;
    }

    if (sub == SEC_SUB_COMMIT) {

        if (sec_state == SEC_ST_ERROR_LOCKED) {
            response[2] = SEC_ERR_LOCKED;
            return SEC_ERR_LOCKED;
        }
        if (sec_state == SEC_ST_BOOTING) {
            response[2] = SEC_RSP_BUSY;
            return SEC_RSP_BUSY;
        }
        new_state = get_be32(params + 0) & 0xffffu;
        ctr = get_be32(params + 4);
        (void)get_be32(params + 8);

        if (ctr < sec_ctr || !sec_uart_commit_allowed((uint16_t)new_state, ctr)) {
            response[2] = SEC_ERR_COMMIT;
            return SEC_ERR_COMMIT;
        }
        if (state_commit((uint16_t)new_state, ctr)) {
            put_be32(response + 4, sec_last_tx);
            put_be32(response + 8, (uint32_t)sec_state);
            put_be32(response + 12, sec_ctr);
        } else {
            response[2] = SEC_ERR_COMMIT;
        }
        response[3] = (uint8_t)(sec_slot_valid[0] | (uint8_t)(sec_slot_valid[1] << 1));
        return (int)response[2];
    }
    if (sub == SEC_SUB_READ_ACTIVE) {

        for (index = 0u; index < 28u; index++) {
            response[4u + index] = sec_slots[sec_active_slot][index];
        }
        return 0;
    }
    if (sub == SEC_SUB_READ_SLOT) {
        slot = params[0];
        if (slot > 1u || sec_slot_valid[slot] == 0u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        for (index = 0u; index < 28u; index++) {
            response[4u + index] = sec_slots[slot][index];
        }
        return 0;
    }
    if (sub == SEC_SUB_INJECT_TAG) {
#if defined(LMS_FW_SEC_TEST_MODE)

        sec_slots[sec_active_slot][SEC_OFF_TAG] ^= 0xffu;
        return 0;
#else

        response[2] = SEC_ERR_UNSUPPORTED;
        return SEC_ERR_UNSUPPORTED;
#endif
    }
    if (sub == SEC_SUB_FACTORY_INIT) {
        rc = sec_factory_init(params, response);
        response[2] = (uint8_t)rc;
        return rc;
    }
    if (sub == SEC_SUB_BOOT) {

        rc = (sec_phase_gate(response) != 0) ? (int)SEC_ERR_PHASE : sec_boot(params);
        response[2] = (uint8_t)rc;
        put_be32(response + 4, (uint32_t)sec_hw_state());
        put_be32(response + 8, sec_ctr_value());
        put_be32(response + 12, sec_last_committed_tx());
        response[20] = sec_factory_locked;
        response[21] = sec_key_loaded;
        response[24] = sec_boot_valid[0];
        response[25] = sec_boot_valid[1];
        response[26] = sec_rec_diag[0];
        response[27] = sec_rec_diag[1];
        response[22] = sec_keygen_pending;
        response[23] = sec_active_slot;
        return rc;
    }
    if (sub == SEC_SUB_GET_STATE) {
        (void)sec_mirror_ksd();
        put_be32(response + 4, (uint32_t)sec_state);
        put_be32(response + 8, sec_ctr);
        put_be32(response + 12, sec_last_tx);
        response[20] = sec_factory_locked;
        response[21] = sec_key_loaded;
        response[22] = sec_keygen_pending;
        response[23] = sec_active_slot;
        return 0;
    }
    if (sub == SEC_SUB_NVM_LOAD) {

        if (sec_phase_gate(response) != 0) {
            return SEC_ERR_PHASE;
        }
        slot = params[0];
        if (slot > 1u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        memcpy(sec_slots[slot], params + 1, SEC_STATE_REC_LEN);
        sec_slot_valid[slot] = 1u;
        response[3] = (uint8_t)(sec_slot_valid[0] | (uint8_t)(sec_slot_valid[1] << 1));
        return 0;
    }
    if (sub == SEC_SUB_NVM_READ) {

        slot = params[0];
        if (slot > 1u || sec_slot_valid[slot] == 0u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        for (index = 0u; index < 28u; index++) {
            response[4u + index] = sec_slots[slot][index];
        }
        return 0;
    }
    if (sub == SEC_SUB_MC_LOAD) {

        if (sec_phase_gate(response) != 0) {
            return SEC_ERR_PHASE;
        }
        if (lms_mmio_mc_load(sec_client, get_be32(params + 0)) != LMS_MMIO_OK) {
            response[2] = SEC_ERR_AUTH;
            return SEC_ERR_AUTH;
        }
        return 0;
    }
    if (sub == SEC_SUB_WRAP_LOAD) {

        if (sec_phase_gate(response) != 0) {
            return SEC_ERR_PHASE;
        }
        memcpy(sec_wrapped_blob, params, LMS_MMIO_WRAPPED_LEN);
        sec_wrapped_valid = 1u;
        return 0;
    }
    if (sub == SEC_SUB_WRAPPED_READ_LO) {

        if (sec_wrapped_valid == 0u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        for (index = 0u; index < 28u; index++) {
            response[4u + index] = sec_wrapped_blob[index];
        }
        return 0;
    }
    if (sub == SEC_SUB_WRAPPED_READ_HI) {

        if (sec_wrapped_valid == 0u) {
            response[2] = SEC_ERR_PARAM;
            return SEC_ERR_PARAM;
        }
        for (index = 0u; index < 20u; index++) {
            response[4u + index] = sec_wrapped_blob[28u + index];
        }
        return 0;
    }
    response[2] = SEC_ERR_UNSUPPORTED;
    return SEC_ERR_UNSUPPORTED;
}
