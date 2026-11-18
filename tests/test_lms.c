#include "lms.h"
#include "../src/lms_internal.h"

#include <stdio.h>
#include <string.h>

static int expect_ok(int status, const char *label)
{
    if (status != LMS_OK) {
        printf("FAIL: %s returned %d\n", label, status);
        return 1;
    }
    return 0;
}

static int expect_fail(int status, const char *label)
{
    if (status == LMS_OK) {
        printf("FAIL: %s unexpectedly succeeded\n", label);
        return 1;
    }
    return 0;
}

static int test_lmots_chain_vector(void)
{
    static const uint8_t expected[LMS_N] = {
        0x22, 0x65, 0x54, 0xe7, 0x47, 0xdf, 0xf2, 0x24,
        0x86, 0x98, 0xfb, 0x6a, 0x44, 0xde, 0xc1, 0x22,
        0xab, 0xea, 0x95, 0x36, 0x15, 0x00, 0xa1, 0x06,
        0x35, 0x93, 0x2d, 0xb0, 0x9a, 0xe7, 0xaf, 0xf7
    };
    uint8_t I[LMS_I_LEN];
    uint8_t value[LMS_N];
    uint8_t unchanged[LMS_N];
    lmots_chain_stats_t stats;
    int failures = 0;
    size_t index;

    for (index = 0; index < sizeof(I); index++) {
        I[index] = (uint8_t)index;
    }
    for (index = 0; index < sizeof(value); index++) {
        value[index] = (uint8_t)index;
    }

    lmots_chain_stats_reset();
    failures += expect_ok(lmots_chain_compute(I, LMS_HASH_SHA256, 2, 3, 4, 5, value),
                          "LM-OTS chain fixed vector");
    if (memcmp(value, expected, sizeof(value)) != 0) {
        puts("FAIL: LM-OTS chain fixed vector mismatch");
        failures++;
    }
    lmots_chain_stats_get(&stats);
    if (stats.calls != 1 || stats.steps != 5) {
        printf("FAIL: chain stats expected 1/5, got %u/%u\n",
               (unsigned)stats.calls, (unsigned)stats.steps);
        failures++;
    }

    memcpy(unchanged, value, sizeof(unchanged));
    failures += expect_ok(lmots_chain_compute(I, LMS_HASH_SHA256, 2, 3, 255, 0, value),
                          "LM-OTS zero-step chain");
    if (memcmp(value, unchanged, sizeof(value)) != 0) {
        puts("FAIL: zero-step chain changed its input");
        failures++;
    }
    failures += expect_fail(lmots_chain_compute(I, LMS_HASH_SHA256, 2, 3, 250, 6, value),
                            "LM-OTS chain index overflow");

    return failures;
}

static int test_lmots_private_value_vector(void)
{
    static const uint8_t I[LMS_I_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const uint8_t seed[LMS_SEED_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t expected[LMS_N] = {
        0x40, 0x98, 0x04, 0xc0, 0xa0, 0x6e, 0xa6, 0x48,
        0xbb, 0x27, 0x26, 0x47, 0xae, 0x23, 0xd6, 0x93,
        0x04, 0xd4, 0xa6, 0x0e, 0x8e, 0xf3, 0x94, 0x6c,
        0xaf, 0xaa, 0x46, 0x84, 0xb5, 0x93, 0xee, 0x61
    };
    lms_private_key_t priv;
    uint8_t value[LMS_N];
    int failures = 0;

    failures += expect_ok(lms_private_key_init(&priv, LMS_SHA256_N32_H5,
                                               LMOTS_SHA256_N32_W4, I, seed),
                          "LM-OTS Appendix A init");
    failures += expect_ok(lmots_private_value(&priv, 2u, 3u, value),
                          "LM-OTS Appendix A private value");
    if (memcmp(value, expected, sizeof(value)) != 0) {
        puts("FAIL: LM-OTS Appendix A private value mismatch");
        failures++;
    }

    return failures;
}

typedef struct {
    unsigned coef_calls;
    unsigned hash_calls;
    int fail_coef;
    int fail_hash;
    int changed_coefficient;
} coef_verify_mock_t;

static int test_message_digest(const uint8_t I[LMS_I_LEN], lms_hash_alg_t hash_alg,
                               uint32_t q, const uint8_t C[LMS_N],
                               const uint8_t *message, size_t message_len,
                               uint8_t Q[LMS_N])
{
    uint8_t prefix[LMS_I_LEN + 4u + 2u + LMS_N];
    memcpy(prefix, I, LMS_I_LEN);
    lms_store_u32(prefix + LMS_I_LEN, q);
    lms_store_u16(prefix + LMS_I_LEN + 4u, D_MESG);
    memcpy(prefix + LMS_I_LEN + 6u, C, LMS_N);
    return lms_hash_parts(prefix, sizeof(prefix), message, message_len,
                          NULL, 0u, NULL, 0u, hash_alg, Q);
}

static int test_coef_backend(void *context, const uint8_t I[LMS_I_LEN],
                             lms_hash_alg_t hash_alg, uint32_t q,
                             const uint8_t C[LMS_N], const uint8_t *message,
                             size_t message_len, uint32_t lmots_type,
                             uint8_t Q[LMS_N],
                             uint8_t coefficients[LMS_MAX_OTS_P])
{
    coef_verify_mock_t *mock = (coef_verify_mock_t *)context;
    lmots_param_t param;
    uint8_t digest_with_checksum[LMS_N + 2u];
    uint32_t i;
    mock->coef_calls++;
    if (mock->fail_coef || lms_get_lmots_param(lmots_type, &param) != LMS_OK ||
        test_message_digest(I, hash_alg, q, C, message, message_len,
                            digest_with_checksum) != LMS_OK) {
        return LMS_ERR_INVALID;
    }
    /* The contract writes exactly n bytes of Q; its checksum tail is private
     * to this mock. Consumers must use the returned coefficients instead. */
    memcpy(Q, digest_with_checksum, param.n);
    lms_store_u16(digest_with_checksum + param.n,
                  (uint16_t)lms_lmots_checksum(digest_with_checksum, param.n,
                                               param.w, param.ls));
    for (i = 0u; i < param.p; i++) {
        coefficients[i] = (uint8_t)lms_lmots_coef(digest_with_checksum, i, param.w);
    }
    if (mock->changed_coefficient >= 0) {
        coefficients[(unsigned)mock->changed_coefficient] ^= 1u;
    }
    return LMS_OK;
}

static int test_message_hash_backend(void *context, const uint8_t I[LMS_I_LEN],
                                     lms_hash_alg_t hash_alg, uint32_t q,
                                     const uint8_t C[LMS_N],
                                     const uint8_t *message, size_t message_len,
                                     uint8_t Q[LMS_N])
{
    coef_verify_mock_t *mock = (coef_verify_mock_t *)context;
    mock->hash_calls++;
    if (mock->fail_hash) {
        return LMS_ERR_INVALID;
    }
    return test_message_digest(I, hash_alg, q, C, message, message_len, Q);
}

static int test_coef_with_software_verify(const char *name, uint32_t lms_type,
                                         uint32_t lmots_type)
{
    static const uint8_t message[] = "coef backend with software verification";
    uint8_t I[LMS_I_LEN], seed[LMS_SEED_LEN];
    uint8_t signature[4u + LMS_N + 67u * LMS_N];
    uint8_t reference[LMS_N], recovered[LMS_N];
    lms_private_key_t priv;
    lmots_param_t param;
    lmots_chain_stats_t stats;
    coef_verify_mock_t mock = { 0u, 0u, 0, 1, -1 };
    const uint32_t q = 7u;
    unsigned i;
    int status;
    int failures = 0;

    for (i = 0u; i < sizeof(I); i++) I[i] = (uint8_t)(0x40u + i);
    for (i = 0u; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x80u + i);
    if (lms_get_lmots_param(lmots_type, &param) != LMS_OK || param.p != 67u ||
        lms_private_key_init(&priv, lms_type, lmots_type, I, seed) != LMS_OK ||
        lmots_public_from_private(&priv, q, reference) != LMS_OK ||
        lmots_sign(&priv, q, message, sizeof(message) - 1u,
                    signature, sizeof(signature)) != LMS_OK) {
        printf("FAIL: %s coefficient regression setup\n", name);
        return 1;
    }

    lmots_verify_backend_set(NULL, NULL);
    lmots_verify_chain_backend_set(NULL, NULL);
    lmots_coef_backend_set(test_coef_backend, &mock);
    lmots_message_hash_backend_set(test_message_hash_backend, &mock);
    lmots_chain_stats_reset();
    failures += expect_ok(lmots_public_from_signature(I, param.hash_alg, q,
                                lmots_type, message, sizeof(message) - 1u,
                                signature, sizeof(signature), recovered),
                          "coef success with software verify");
    lmots_chain_stats_get(&stats);
    if (memcmp(reference, recovered, LMS_N) != 0 || stats.calls != param.p ||
        mock.coef_calls != 1u || mock.hash_calls != 0u) {
        printf("FAIL: %s coefficient backend parity or dispatch\n", name);
        failures++;
    }

    /* Each of W4's three checksum coefficients must affect the reconstructed
     * public key. This detects consumers silently recomputing/ignoring them. */
    for (i = 64u; i < 67u; i++) {
        mock.changed_coefficient = (int)i;
        failures += expect_ok(lmots_public_from_signature(I, param.hash_alg, q,
                                    lmots_type, message, sizeof(message) - 1u,
                                    signature, sizeof(signature), recovered),
                              "changed checksum coefficient reconstruction");
        if (memcmp(reference, recovered, LMS_N) == 0) {
            printf("FAIL: %s ignored checksum coefficient %u\n", name, i);
            failures++;
        }
    }
    mock.changed_coefficient = -1;
    mock.fail_coef = 1;
    mock.fail_hash = 0;
    failures += expect_ok(lmots_public_from_signature(I, param.hash_alg, q,
                                lmots_type, message, sizeof(message) - 1u,
                                signature, sizeof(signature), recovered),
                          "coef failure with message hash fallback");
    if (memcmp(reference, recovered, LMS_N) != 0 || mock.hash_calls != 1u) {
        printf("FAIL: %s message hash fallback parity or dispatch\n", name);
        failures++;
    }
    mock.fail_hash = 1;
    lmots_chain_stats_reset();
    status = lmots_public_from_signature(I, param.hash_alg, q, lmots_type,
                                         message, sizeof(message) - 1u,
                                         signature, sizeof(signature), recovered);
    lmots_chain_stats_get(&stats);
    if (status != LMS_ERR_INVALID || stats.calls != 0u ||
        mock.coef_calls != 6u || mock.hash_calls != 2u) {
        printf("FAIL: %s failed message hash did not stop verification\n", name);
        failures++;
    }
    lmots_coef_backend_set(NULL, NULL);
    lmots_message_hash_backend_set(NULL, NULL);
    printf("%s coefficient/software-verify regression: %s (checksum 64/65/66, hash fallback/failure)\n",
           name, failures ? "FAIL" : "PASS");
    return failures;
}

static int run_lms_case(const char *name, uint32_t lms_type, uint32_t lmots_type)
{
    static const uint8_t I[LMS_I_LEN] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t seed[LMS_SEED_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t msg[] = "abc";
    static const uint8_t empty[] = "";

    lms_private_key_t priv;
    lms_private_key_t restored_priv;
    lms_public_key_t pub;
    lms_public_key_t parsed;
    lmots_chain_stats_t chain_stats;
    uint8_t sig[LMS_MAX_SIGNATURE_LEN];
    uint8_t sig2[LMS_MAX_SIGNATURE_LEN];
    uint8_t pub_buf[LMS_PUBLIC_KEY_LEN];
    uint8_t priv_buf[LMS_PRIVATE_KEY_LEN];
    uint8_t long_msg[4096];
    size_t sig_len = 0;
    size_t sig2_len = 0;
    int failures = 0;
    size_t i;

    for (i = 0; i < sizeof(long_msg); i++) {
        long_msg[i] = (uint8_t)i;
    }

    printf("Running %s\n", name);
    lmots_chain_stats_reset();

    failures += expect_ok(lms_private_key_init(&priv, lms_type, lmots_type, I, seed), "init");
    failures += expect_ok(lms_public_key_generate(&priv, &pub), "public key generate");
    failures += expect_ok(lms_public_key_serialize(&pub, pub_buf, sizeof(pub_buf)), "public key serialize");
    failures += expect_ok(lms_public_key_parse(&parsed, pub_buf, sizeof(pub_buf)), "public key parse");

    failures += expect_ok(lms_sign(&priv, msg, strlen((const char *)msg), sig, sizeof(sig), &sig_len), "sign msg");
    failures += expect_ok(lms_verify(&parsed, msg, strlen((const char *)msg), sig, sig_len), "verify msg");

    sig[12] ^= 0x01;
    failures += expect_fail(lms_verify(&parsed, msg, strlen((const char *)msg), sig, sig_len), "verify tampered signature");
    sig[12] ^= 0x01;

    failures += expect_fail(lms_verify(&parsed, (const uint8_t *)"abd", 3, sig, sig_len), "verify tampered message");

    failures += expect_ok(lms_sign(&priv, empty, 0, sig2, sizeof(sig2), &sig2_len), "sign empty");
    failures += expect_ok(lms_verify(&parsed, empty, 0, sig2, sig2_len), "verify empty");

    failures += expect_ok(lms_sign(&priv, long_msg, sizeof(long_msg), sig2, sizeof(sig2), &sig2_len), "sign long");
    failures += expect_ok(lms_verify(&parsed, long_msg, sizeof(long_msg), sig2, sig2_len), "verify long");

    failures += expect_ok(lms_private_key_serialize(&priv, priv_buf, sizeof(priv_buf)), "private key serialize");
    failures += expect_ok(lms_private_key_parse(&restored_priv, priv_buf, sizeof(priv_buf)), "private key parse");
    failures += expect_ok(lms_sign(&restored_priv, msg, strlen((const char *)msg), sig2, sizeof(sig2), &sig2_len), "sign restored state");
    failures += expect_ok(lms_verify(&parsed, msg, strlen((const char *)msg), sig2, sig2_len), "verify restored state");

    if (priv.q != 3) {
        printf("FAIL: q expected 3, got %u\n", (unsigned)priv.q);
        failures++;
    }
    if (restored_priv.q != 4) {
        printf("FAIL: restored q expected 4, got %u\n", (unsigned)restored_priv.q);
        failures++;
    }
    if (sig_len != lms_signature_len(lms_type, lmots_type)) {
        printf("FAIL: unexpected signature length %u\n", (unsigned)sig_len);
        failures++;
    }
    lmots_chain_stats_get(&chain_stats);
    if (chain_stats.calls == 0 || chain_stats.steps == 0) {
        printf("FAIL: missing LM-OTS chain stats for %s\n", name);
        failures++;
    }

    return failures;
}

int main(void)
{
    int failures = 0;

    failures += test_lmots_private_value_vector();
    failures += test_lmots_chain_vector();
    failures += test_coef_with_software_verify("SHAKE256", LMS_SHAKE256_N32_H5,
                                               LMOTS_SHAKE256_N32_W4);
    failures += test_coef_with_software_verify("SHA256", LMS_SHA256_N32_H5,
                                               LMOTS_SHA256_N32_W4);
    failures += run_lms_case("SHAKE256", LMS_SHAKE256_N32_H5, LMOTS_SHAKE256_N32_W4);
    failures += run_lms_case("SHA256", LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W4);

    failures += run_lms_case("Haraka", LMS_HARAKA_N32_H5, LMOTS_HARAKA_N32_W4);

    failures += expect_fail(lms_signature_len(LMS_SHAKE256_N32_H5, LMOTS_SHA256_N32_W4) == 0 ? LMS_ERR_INVALID : LMS_OK,
                            "mixed hash parameter set");

    if (failures) {
        printf("LMS tests failed: %d\n", failures);
        return 1;
    }

    puts("LMS tests passed");
    return 0;
}
