#include "lms_mmio.h"

#include "lms_internal.h"

#include <string.h>

int lms_mmio_ksd_read(lms_mmio_client_t *client, lms_mmio_ksd_status_t *status)
{
    uint32_t attempt;
    if (!client || !status || !client->bus.read32) return LMS_MMIO_ERR_INVALID;
    if (client->bus.read32(client->bus.context, LMS_MMIO_REG_KSD_MARKER) !=
        LMS_MMIO_KSD_MARKER) return LMS_MMIO_ERR_PROTOCOL;
    for (attempt = 0; attempt < 8u; ++attempt) {
        status->state = client->bus.read32(client->bus.context, LMS_MMIO_REG_KSD_STATE);
        status->signing_q = client->bus.read32(client->bus.context, LMS_MMIO_REG_KSD_SIGNING_Q);
        status->next_q = client->bus.read32(client->bus.context, LMS_MMIO_REG_KSD_NEXT_Q);
        status->last_tx = client->bus.read32(client->bus.context, LMS_MMIO_REG_KSD_LAST_TX);
        status->profile = client->bus.read32(client->bus.context, LMS_MMIO_REG_KSD_PROFILE);
        if (status->state == client->bus.read32(client->bus.context, LMS_MMIO_REG_KSD_STATE))
            return LMS_MMIO_OK;
    }
    return LMS_MMIO_ERR_TIMEOUT;
}

int lms_mmio_ksd_wait_recovery(lms_mmio_client_t *client)
{
    uint32_t poll;
    lms_mmio_ksd_status_t status;
    if (!client) return LMS_MMIO_ERR_INVALID;
    for (poll = 0; poll < client->timeout_polls; ++poll) {
        if (lms_mmio_ksd_read(client, &status) != LMS_MMIO_OK) return LMS_MMIO_ERR_PROTOCOL;
        if (status.state == LMS_MMIO_KSD_IDLE || status.state == LMS_MMIO_KSD_EXHAUSTED)
            return LMS_MMIO_OK;
        if (status.state == LMS_MMIO_KSD_ERROR_LOCKED) return LMS_MMIO_ERR_HARDWARE;
    }
    return LMS_MMIO_ERR_TIMEOUT;
}

int lms_mmio_ksd_begin(lms_mmio_client_t *client, uint32_t expected_q)
{
    uint32_t poll, previous_tx;
    lms_mmio_ksd_status_t status;
    if (!client || !client->bus.write32 || lms_mmio_ksd_read(client, &status) != LMS_MMIO_OK)
        return LMS_MMIO_ERR_PROTOCOL;
    if (status.state != LMS_MMIO_KSD_IDLE || status.next_q != expected_q)
        return LMS_MMIO_ERR_HARDWARE;
    previous_tx = status.last_tx;
    client->bus.write32(client->bus.context, LMS_MMIO_REG_KSD_CONTROL, LMS_MMIO_KSD_BEGIN);
    for (poll = 0; poll < client->timeout_polls; ++poll) {
        if (lms_mmio_ksd_read(client, &status) != LMS_MMIO_OK) return LMS_MMIO_ERR_PROTOCOL;
        if (status.state == LMS_MMIO_KSD_RESERVED_READY)
            return status.signing_q == expected_q && status.last_tx > previous_tx ?
                LMS_MMIO_OK : LMS_MMIO_ERR_HARDWARE;
        if (status.state == LMS_MMIO_KSD_ERROR_LOCKED || status.state == LMS_MMIO_KSD_EXHAUSTED)
            return LMS_MMIO_ERR_HARDWARE;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_KSD_CONTROL, LMS_MMIO_KSD_ABORT);
    return LMS_MMIO_ERR_TIMEOUT;
}

int lms_mmio_ksd_finish(lms_mmio_client_t *client, uint32_t expected_next_q)
{
    uint32_t poll;
    lms_mmio_ksd_status_t status;
    if (!client || !client->bus.write32) return LMS_MMIO_ERR_INVALID;
    for (poll = 0; poll < client->timeout_polls; ++poll) {
        if (lms_mmio_ksd_read(client, &status) != LMS_MMIO_OK) return LMS_MMIO_ERR_PROTOCOL;
        if (status.state == LMS_MMIO_KSD_IDLE || status.state == LMS_MMIO_KSD_EXHAUSTED)
            return status.next_q == expected_next_q ? LMS_MMIO_OK : LMS_MMIO_ERR_HARDWARE;
        if (status.state == LMS_MMIO_KSD_ERROR_LOCKED || status.state == LMS_MMIO_KSD_RECOVERY_LOCKED)
            return LMS_MMIO_ERR_HARDWARE;
        /* No computation was started. Cancel the unused but durable reservation.
         * Running SIGN finalizes itself; firmware cannot manufacture engine_done. */
        if (status.state == LMS_MMIO_KSD_RESERVED_READY)
            client->bus.write32(client->bus.context, LMS_MMIO_REG_KSD_CONTROL, LMS_MMIO_KSD_ABORT);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_KSD_CONTROL, LMS_MMIO_KSD_ABORT);
    return LMS_MMIO_ERR_TIMEOUT;
}

typedef uint32_t mmio_alias_word_t __attribute__((__may_alias__));

#ifndef LMS_SIGN_RESULT_POST
#define LMS_SIGN_RESULT_POST 0
#endif
#ifndef LMS_SIGN_RESULT_FAST
#define LMS_SIGN_RESULT_FAST 0
#endif

#if defined(LMS_MMIO_SOC_PROFILE)
#include <stdint.h>
#define LMS_SOC_CYCLE_COUNT_ADDR 0x10000010u
static uint32_t soc_cycle_count(void)
{
    return *(volatile uint32_t *)(uintptr_t)LMS_SOC_CYCLE_COUNT_ADDR;
}
#endif

const lms_mmio_hash_desc_t LMS_MMIO_HASH_DESC_SHA256 = {
    LMS_HASH_SHA256,                    /* hash_alg */
    0x00000007u,                        /* version */
    LMS_MMIO_CAP_SHA256,                /* probe_cap */
    128u,                               /* max_input_bytes */
    "SHA-256"
};

const lms_mmio_hash_desc_t LMS_MMIO_HASH_DESC_SHAKE256 = {
    LMS_HASH_SHAKE256,                  /* hash_alg */
    0x00000001u,                        /* version */
    LMS_MMIO_CAP_SHAKE256,              /* probe_cap: bit12 */
    136u,                               /* max_input_bytes */
    "SHAKE256"
};

static uint32_t direct_read32(void *context, uint32_t offset)
{
    volatile uint32_t *reg = (volatile uint32_t *)((volatile uint8_t *)context + offset);
    return *reg;
}

static void direct_write32(void *context, uint32_t offset, uint32_t value)
{
    volatile uint32_t *reg = (volatile uint32_t *)((volatile uint8_t *)context + offset);
    *reg = value;
}

static int lmots_param_hw(lmots_param_t *param, uint32_t lmots_type)
{
    if (lms_get_lmots_param(lmots_type, param) != LMS_OK) {
        return LMS_MMIO_ERR_INVALID;
    }
    if (param->w != 1u && param->w != 2u && param->w != 4u && param->w != 8u) {
        return LMS_MMIO_ERR_INVALID;
    }
    return LMS_MMIO_OK;
}

static uint32_t pack_coefficients_words(uint32_t *words,
                                        const uint8_t *coefficients,
                                        uint32_t p,
                                        uint32_t w)
{
    uint32_t i;
    uint32_t per;
    uint32_t mask;
    uint32_t shift;
    uint32_t w_idx = 0u;
    uint32_t w_shift = 0u;

    per = 32u / w;
    mask = (w == 8u) ? 0xffu : ((1u << w) - 1u);
    shift = w;
    for (i = 0u; i < 32u; i++) {
        words[i] = 0u;
    }

    for (i = 0u; i < p; i++) {
        words[w_idx] |= ((uint32_t)coefficients[i] & mask) << w_shift;
        w_shift += shift;
        if (w_shift >= 32u) {
            w_shift -= 32u;
            w_idx++;
        }
    }
    return (p + per - 1u) / per;
}

void lms_mmio_bus_init_direct(lms_mmio_bus_t *bus, volatile void *base)
{
    if (bus) {
        bus->context = (void *)base;
        bus->read32 = direct_read32;
        bus->write32 = direct_write32;
    }
}

int lms_mmio_client_init(lms_mmio_client_t *client,
                         const lms_mmio_bus_t *bus,
                         uint32_t timeout_polls,
                         int allow_fallback)
{
    if (!client || !bus || !bus->read32 || !bus->write32 || timeout_polls == 0u) {
        return LMS_MMIO_ERR_INVALID;
    }

    memset(client, 0, sizeof(*client));
    client->bus = *bus;
    client->timeout_polls = timeout_polls;
    client->allow_fallback = allow_fallback != 0;
    client->hash_desc = NULL;
    return LMS_MMIO_OK;
}

int lms_mmio_probe(lms_mmio_client_t *client)
{
    uint32_t version;
    uint32_t capabilities;

    if (!client || !client->bus.read32) {
        return LMS_MMIO_ERR_INVALID;
    }

    version      = client->bus.read32(client->bus.context, LMS_MMIO_REG_VERSION);
    capabilities = client->bus.read32(client->bus.context, LMS_MMIO_REG_CAPABILITY);
    client->probed      = 0;
    client->capabilities = capabilities;
    client->hash_desc   = NULL;

    if ((capabilities & LMS_MMIO_HASH_DESC_SHAKE256.probe_cap) &&
        version == LMS_MMIO_HASH_DESC_SHAKE256.version) {
        client->hash_desc = &LMS_MMIO_HASH_DESC_SHAKE256;
    } else if ((capabilities & LMS_MMIO_HASH_DESC_SHA256.probe_cap) &&
               version >= 1u && version <= LMS_MMIO_HASH_DESC_SHA256.version) {
        client->hash_desc = &LMS_MMIO_HASH_DESC_SHA256;
    }

    if (!client->hash_desc) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    client->probed = 1;
    return LMS_MMIO_OK;
}

static void write_bytes(const lms_mmio_bus_t *bus,
                        uint32_t base,
                        const uint8_t *bytes,
                        size_t length)
{
    size_t offset = 0;

    /* Check alignment once; read only complete words, then zero-pad the tail. */
    if (((uintptr_t)bytes & 3u) == 0u) {
        const mmio_alias_word_t *wp = (const mmio_alias_word_t *)(const void *)bytes;
        size_t full_length = length & ~(size_t)3u;
        for (; offset < full_length; offset += 4u) {
            bus->write32(bus->context, base + (uint32_t)offset, wp[offset >> 2]);
        }
    }
    for (; offset < length; offset += 4u) {
        uint32_t word = 0;
        size_t lane;
        for (lane = 0; lane < 4u && offset + lane < length; lane++) {
            word |= (uint32_t)bytes[offset + lane] << (8u * lane);
        }
        bus->write32(bus->context, base + (uint32_t)offset, word);
    }
}

static void read_bytes(const lms_mmio_bus_t *bus,
                       uint32_t base,
                       uint8_t *bytes,
                       size_t length)
{
    size_t offset;

    if ((length & 3u) == 0u && (((uintptr_t)bytes & 3u) == 0u)) {
        uint32_t *wp = (uint32_t *)(void *)bytes;
        for (offset = 0; offset < length; offset += 4u) {
            wp[offset >> 2] = bus->read32(bus->context, base + (uint32_t)offset);
        }
        return;
    }
    for (offset = 0; offset < length; offset += 4u) {
        uint32_t word = bus->read32(bus->context, base + (uint32_t)offset);
        size_t lane;
        for (lane = 0; lane < 4u && offset + lane < length; lane++) {
            bytes[offset + lane] = (uint8_t)(word >> (8u * lane));
        }
    }
}

static void write_task_bytes(const lms_mmio_bus_t *bus,
                             uint32_t word_base,
                             const uint8_t *bytes,
                             size_t length)
{
    size_t offset = 0;
    if (word_base >= LMS_MMIO_TASK_STREAM_BASE) {

        bus->write32(bus->context, LMS_MMIO_REG_TASK_ADDR, word_base);
        if (((uintptr_t)bytes & 3u) == 0u) {

            const mmio_alias_word_t *wp = (const mmio_alias_word_t *)(const void *)bytes;
            size_t n = length >> 2;
            for (offset = 0; offset < n; offset++) {
                bus->write32(bus->context, LMS_MMIO_REG_TASK_DATA, wp[offset]);
            }
            offset *= 4u;
        }
        {
            for (; offset < length; offset += 4u) {
                uint32_t word = 0u;
                size_t lane;
                for (lane = 0; lane < 4u && offset + lane < length; lane++) {
                    word |= (uint32_t)bytes[offset + lane] << (8u * lane);
                }
                bus->write32(bus->context, LMS_MMIO_REG_TASK_DATA, word);
            }
        }
    } else {

        if (((uintptr_t)bytes & 3u) == 0u) {
            const mmio_alias_word_t *wp = (const mmio_alias_word_t *)(const void *)bytes;
            size_t n = length >> 2;
            for (offset = 0; offset < n; offset++) {
                bus->write32(bus->context, LMS_MMIO_REG_TASK_ADDR,
                             word_base + (uint32_t)offset);
                bus->write32(bus->context, LMS_MMIO_REG_TASK_DATA, wp[offset]);
            }
            offset *= 4u;
        }
        {
            for (; offset < length; offset += 4u) {
                uint32_t word = 0u;
                size_t lane;
                for (lane = 0; lane < 4u && offset + lane < length; lane++) {
                    word |= (uint32_t)bytes[offset + lane] << (8u * lane);
                }
                bus->write32(bus->context, LMS_MMIO_REG_TASK_ADDR,
                             word_base + (uint32_t)(offset / 4u));
                bus->write32(bus->context, LMS_MMIO_REG_TASK_DATA, word);
            }
        }
    }
}

static void read_task_bytes(const lms_mmio_bus_t *bus,
                            uint32_t word_base,
                            uint8_t *bytes,
                            size_t length)
{
    size_t offset;

    bus->write32(bus->context, LMS_MMIO_REG_TASK_ADDR, word_base);
    if ((length & 3u) == 0u && (((uintptr_t)bytes & 3u) == 0u)) {

        uint32_t *wp = (uint32_t *)(void *)bytes;
        size_t n = length >> 2;
        for (offset = 0; offset < n; offset++) {
            wp[offset] = bus->read32(bus->context, LMS_MMIO_REG_TASK_DATA);
        }
    } else {
        for (offset = 0; offset < length; offset += 4u) {
            uint32_t word;
            size_t lane;
            word = bus->read32(bus->context, LMS_MMIO_REG_TASK_DATA);
            for (lane = 0; lane < 4u && offset + lane < length; lane++) {
                bytes[offset + lane] = (uint8_t)(word >> (8u * lane));
            }
        }
    }
}

static int ensure_probe(lms_mmio_client_t *client)
{
    return client->probed ? LMS_MMIO_OK : lms_mmio_probe(client);
}

static int wait_for_result_n(lms_mmio_client_t *client,
                             uint8_t *output,
                             size_t output_len,
                             uint32_t *cycles)
{
    uint32_t poll;

    for (poll = 0; poll < client->timeout_polls; poll++) {
        uint32_t status = client->bus.read32(client->bus.context, LMS_MMIO_REG_STATUS);
        if ((status & LMS_MMIO_STATUS_BUSY) != 0u) {
            continue;
        }
        if ((status & LMS_MMIO_STATUS_ERROR) != 0u) {
            client->last_hw_error = client->bus.read32(client->bus.context, LMS_MMIO_REG_ERROR);
            return LMS_MMIO_ERR_HARDWARE;
        }
        if ((status & LMS_MMIO_STATUS_DONE) != 0u) {
            if (output && output_len != 0u) {
                read_bytes(&client->bus, LMS_MMIO_REG_OUTPUT, output, output_len);
            }
            if (cycles) {
                *cycles = client->bus.read32(client->bus.context, LMS_MMIO_REG_CYCLE_COUNT);
            }
            client->last_hw_error = 0u;
            return LMS_MMIO_OK;
        }
    }

    return LMS_MMIO_ERR_TIMEOUT;
}

static int wait_for_result(lms_mmio_client_t *client,
                           uint8_t output[LMS_N],
                           uint32_t *cycles)
{
    return wait_for_result_n(client, output, LMS_N, cycles);
}

static int prepare_command(lms_mmio_client_t *client, uint32_t required_capability)
{
    int status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & required_capability) != required_capability) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    client->last_hw_error = 0u;
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_CLEAR);
    if (client->bus.read32(client->bus.context, LMS_MMIO_REG_STATUS) != 0u) {
        return LMS_MMIO_ERR_HARDWARE;
    }
    return LMS_MMIO_OK;
}

int lms_mmio_hash_once(lms_mmio_client_t *client,
                       const uint8_t *input,
                       size_t input_len,
                       uint8_t output[LMS_N],
                       uint32_t *cycles)
{
    uint8_t hardware_output[LMS_N];
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !output || (!input && input_len != 0u)) {
        return LMS_MMIO_ERR_INVALID;
    }
    if (cycles) {
        *cycles = 0u;
    }

    status = prepare_command(client, LMS_MMIO_CAP_HASH_ONCE);
    if (status == LMS_MMIO_OK &&
        input_len > (size_t)client->hash_desc->max_input_bytes) {
        status = LMS_MMIO_ERR_INVALID;
    }
    if (status == LMS_MMIO_OK) {
        client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_HASH_ONCE);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_INPUT_LENGTH, (uint32_t)input_len);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);
        write_bytes(&client->bus, LMS_MMIO_REG_INPUT, input, input_len);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
        status = wait_for_result(client, hardware_output, &command_cycles);
    }
    if (status == LMS_MMIO_OK) {
        memcpy(output, hardware_output, LMS_N);

        client->hardware_hash_once_count++;
        client->hardware_hash_once_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
        return LMS_MMIO_OK;
    }
    if (client->allow_fallback &&
        lms_hash(client->hash_desc->hash_alg, input, input_len, output, LMS_N) == 0) {
        client->fallback_count++;
        return LMS_MMIO_OK;
    }
    return status;
}

int lms_mmio_hash_once_ram(lms_mmio_client_t *client,
                           const uint8_t *input,
                           size_t input_len,
                           uint8_t output[LMS_N],
                           uint32_t *cycles)
{
    uint8_t hardware_output[LMS_N];
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !output || (!input && input_len != 0u)) {
        return LMS_MMIO_ERR_INVALID;
    }
    if (cycles) {
        *cycles = 0u;
    }

    status = prepare_command(client, LMS_MMIO_CAP_HASH_ONCE);
    if (status == LMS_MMIO_OK &&
        input_len > LMS_MMIO_HASH_ONCE_RAM_MAX) {
        status = LMS_MMIO_ERR_INVALID;
    }
    if (status == LMS_MMIO_OK) {
        client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_HASH_ONCE_RAM);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_INPUT_LENGTH, (uint32_t)input_len);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);

        write_task_bytes(&client->bus, 32u, input, input_len);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
        status = wait_for_result(client, hardware_output, &command_cycles);
    }
    if (status == LMS_MMIO_OK) {
        memcpy(output, hardware_output, LMS_N);

        client->hardware_hash_once_count++;
        client->hardware_hash_once_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
        return LMS_MMIO_OK;
    }
    if (client->allow_fallback &&
        lms_hash(client->hash_desc->hash_alg, input, input_len, output, LMS_N) == 0) {
        client->fallback_count++;
        return LMS_MMIO_OK;
    }
    return status;
}

int lms_mmio_msg_q_coef(lms_mmio_client_t *client,
                        const uint8_t I[LMS_I_LEN],
                        uint32_t q,
                        const uint8_t C[LMS_N],
                        const uint8_t *message,
                        size_t message_len,
                        uint32_t lmots_type,
                        uint8_t Q[LMS_N],
                        uint8_t coefficients[LMS_MAX_OTS_P],
                        uint32_t *cycles)
{
    lmots_param_t param;
    uint8_t head[54];                 /* Hash input: I || u32str(q) (big endian) || D_MESG || C. */
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t L;
    uint32_t command_cycles = 0u;
    uint32_t i;
    int status;

    if (!client || !I || !C ||
        (!message && message_len != 0u && message_len <= 74u)) {

        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }

    L = 54u + (uint32_t)message_len;
    if (L > LMS_MMIO_HASH_ONCE_RAM_MAX) {
        return LMS_MMIO_ERR_INVALID;
    }

    status = prepare_command(client, LMS_MMIO_CAP_MSG_Q_COEF);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_MSG_Q_COEF);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_INPUT_LENGTH, L);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, 0u);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);

    memcpy(head, I, LMS_I_LEN);
    lms_store_u32(head + LMS_I_LEN, q);
    head[20] = 0x81;
    head[21] = 0x81;
    memcpy(head + 22, C, LMS_N);

    uint32_t mqc_base;
    if (L > LMS_MMIO_MAX_INPUT) {
        mqc_base = 568u;
    } else {
        mqc_base = (param.w == 1u) ? 568u : 32u + param.p * 8u;
    }
    write_task_bytes(&client->bus, mqc_base, head, 54u);
    if (message) {
        write_task_bytes(&client->bus, mqc_base + 14u, message, message_len);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);

    status = wait_for_result(client, Q, &command_cycles);
    if (status == LMS_MMIO_OK && coefficients) {

        nwords = (param.p * param.w + 31u) / 32u;
        if (nwords > 32u) {
            nwords = 32u;
        }
        for (i = 0u; i < nwords; i++) {
            client->bus.write32(client->bus.context, LMS_MMIO_REG_TASK_ADDR, i);
            packed[i] = client->bus.read32(client->bus.context, LMS_MMIO_REG_TASK_DATA);
        }

        for (i = 0u; i < param.p; i++) {
            uint32_t bit = i * param.w;
            uint32_t word = bit / 32u;
            uint32_t shift = bit % 32u;
            uint32_t mask = (param.w == 8u) ? 0xffu : ((1u << param.w) - 1u);
            coefficients[i] = (uint8_t)((packed[word] >> shift) & mask);
        }
    }
    if (status == LMS_MMIO_OK) {
        client->hardware_hash_once_count++;
        client->hardware_hash_once_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
        return LMS_MMIO_OK;
    }
    return status;
}

int lms_mmio_chain(lms_mmio_client_t *client,
                   const uint8_t I[LMS_I_LEN],
                   uint32_t q,
                   uint32_t i,
                   uint32_t start,
                   uint32_t steps,
                   uint8_t value[LMS_N],
                   uint32_t *cycles)
{
    uint8_t hardware_output[LMS_N];
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !value || i > UINT16_MAX || start > UINT8_MAX ||
        steps > UINT8_MAX || start + steps > UINT8_MAX) {
        return LMS_MMIO_ERR_INVALID;
    }
    if (cycles) {
        *cycles = 0u;
    }

    status = prepare_command(client, LMS_MMIO_CAP_CHAIN);
    if (status == LMS_MMIO_OK) {
        client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_CHAIN);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_I, i);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_START, start);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_STEPS, steps);
        write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
        write_bytes(&client->bus, LMS_MMIO_REG_INPUT, value, LMS_N);
        client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
        status = wait_for_result(client, hardware_output, &command_cycles);
    }
    if (status == LMS_MMIO_OK) {
        memcpy(value, hardware_output, LMS_N);
        client->hardware_chain_count++;
        client->hardware_chain_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
        return LMS_MMIO_OK;
    }
    if (client->allow_fallback &&
        lmots_chain_compute(I, client->hash_desc->hash_alg, q, i, start, steps, value) == LMS_OK) {
        client->fallback_count++;
        return LMS_MMIO_OK;
    }
    return status;
}

int lms_mmio_seed_load_test(lms_mmio_client_t *client,
                            uint32_t key_handle,
                            const uint8_t seed[LMS_SEED_LEN])
{
    int status;

    if (!client || !seed || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_DERIVE_CHAIN |
                                     LMS_MMIO_CAP_INSECURE_TEST_MODE);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_SEED_LOAD);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    write_bytes(&client->bus, LMS_MMIO_REG_SEED, seed, LMS_SEED_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    {
        return wait_for_result(client, NULL, NULL);
    }
}

int lms_mmio_seed_load_safe(lms_mmio_client_t *client,
                            const uint8_t seed[LMS_SEED_LEN])
{
    int status;

    if (!client || !seed) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_WRAP);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_SEED_WRITE_SAFE);
    write_bytes(&client->bus, LMS_MMIO_REG_SEED, seed, LMS_SEED_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    {
        return wait_for_result(client, NULL, NULL);
    }
}

int lms_mmio_mc_read(lms_mmio_client_t *client, uint32_t *value)
{
    int status;

    if (!client || !value) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & LMS_MMIO_CAP_SIM_MC) == 0u) {
        return LMS_MMIO_ERR_PROTOCOL;
    }
    *value = client->bus.read32(client->bus.context, LMS_MMIO_REG_SIM_MC);
    return LMS_MMIO_OK;
}

int lms_mmio_mc_step(lms_mmio_client_t *client, uint32_t *value)
{
    uint8_t output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_SIM_MC);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_MC_STEP);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &cycles);
    if (status == LMS_MMIO_OK && value) {

        *value = (uint32_t)output[0] | ((uint32_t)output[1] << 8) |
                 ((uint32_t)output[2] << 16) | ((uint32_t)output[3] << 24);
    }
    return status;
}

int lms_mmio_state_commit(lms_mmio_client_t *client,
                          uint16_t new_state, uint32_t ctr, uint8_t aad,
                          uint32_t *tx_out, uint8_t tag[16])
{
    uint8_t output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client || !tx_out || !tag) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_SIM_MC | LMS_MMIO_CAP_HMAC_KSTATE);
    if (status != LMS_MMIO_OK) {
        return status;
    }

    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_I, new_state);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, ctr);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, aad);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_STATE_COMMIT);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);

    status = wait_for_result_n(client, output, 20u, &cycles);
    if (status == LMS_MMIO_OK) {

        *tx_out = (uint32_t)output[0] | ((uint32_t)output[1] << 8) |
                  ((uint32_t)output[2] << 16) | ((uint32_t)output[3] << 24);
        memcpy(tag, output + 4, 16u);
    }
    return status;
}

int lms_mmio_mc_load(lms_mmio_client_t *client, uint32_t value)
{
    uint8_t output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_SIM_MC);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_MC_LOAD);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, value);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    return wait_for_result(client, output, &cycles);
}

int lms_mmio_key_slot_load_test(lms_mmio_client_t *client,
                                uint32_t key_slot,
                                const uint8_t key[LMS_SEED_LEN])
{
    uint32_t base;
    int status;

    if (!client || !key || (key_slot != LMS_MMIO_KEY_KWRAP && key_slot != LMS_MMIO_KEY_KSTATE)) {
        return LMS_MMIO_ERR_INVALID;
    }

    base = LMS_MMIO_REG_KWRAP;
    status = prepare_command(client, LMS_MMIO_CAP_WRAP |
                                     LMS_MMIO_CAP_INSECURE_TEST_MODE);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_SEED_LOAD);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_slot);
    write_bytes(&client->bus, base, key, LMS_SEED_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    {
        uint32_t ignored_cycles;
        uint8_t ignored_output[LMS_N];
        return wait_for_result(client, ignored_output, &ignored_cycles);
    }
}

int lms_mmio_wrap_seed(lms_mmio_client_t *client,
                       uint8_t wrapped[LMS_MMIO_WRAPPED_LEN])
{
    uint8_t ignored_output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client || !wrapped) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_WRAP);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_WRAP_SEED);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, ignored_output, &cycles);
    if (status == LMS_MMIO_OK) {
        read_bytes(&client->bus, LMS_MMIO_REG_WRAPPED, wrapped, LMS_MMIO_WRAPPED_LEN);
    }
    return status;
}

int lms_mmio_unwrap_seed(lms_mmio_client_t *client,
                         const uint8_t wrapped[LMS_MMIO_WRAPPED_LEN])
{
    uint8_t ignored_output[LMS_N];
    uint32_t cycles;
    int status;

    if (!client || !wrapped) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_WRAP);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    write_bytes(&client->bus, LMS_MMIO_REG_WRAPPED, wrapped, LMS_MMIO_WRAPPED_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_UNWRAP_SEED);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    return wait_for_result(client, ignored_output, &cycles);
}

int lms_mmio_hmac_kstate(lms_mmio_client_t *client,
                         const uint8_t *input,
                         size_t input_len,
                         uint8_t output[LMS_N])
{
    uint32_t cycles;
    int status;

    if (!client || !output || (!input && input_len != 0u) || input_len > 119u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_HMAC_KSTATE);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND, LMS_MMIO_CMD_HMAC_KSTATE);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_INPUT_LENGTH, (uint32_t)input_len);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH, LMS_MMIO_OUTPUT_LEN);
    write_bytes(&client->bus, LMS_MMIO_REG_INPUT, input, input_len);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    return wait_for_result(client, output, &cycles);
}

int lms_mmio_derive_chain(lms_mmio_client_t *client,
                          uint32_t key_handle,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t i,
                          uint32_t start,
                          uint32_t steps,
                          uint8_t output[LMS_N],
                          uint32_t *cycles)
{
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output || key_handle != 0u || i > UINT16_MAX ||
        start > UINT8_MAX || steps > UINT8_MAX || start + steps > UINT8_MAX) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_DERIVE_CHAIN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_DERIVE_CHAIN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_I, i);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_START, start);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_STEPS, steps);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_derive_count++;
        client->hardware_derive_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_derive_randomizer(lms_mmio_client_t *client,
                               uint32_t key_handle,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint8_t output[LMS_N],
                               uint32_t *cycles)
{
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = prepare_command(client, LMS_MMIO_CAP_DERIVE_CHAIN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_DERIVE_RANDOMIZER);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_derive_count++;
        client->hardware_derive_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_keygen(lms_mmio_client_t *client,
                          uint32_t key_handle,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t lmots_type,
                          uint8_t output[LMS_N],
                          uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_KEYGEN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_KEYGEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_keygen_count++;
        client->hardware_keygen_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_keygen_leaf(lms_mmio_client_t *client,
                                uint32_t key_handle,
                                const uint8_t I[LMS_I_LEN],
                                uint32_t q,
                                uint32_t node_num,
                                uint32_t lmots_type,
                                uint8_t output[LMS_N],
                                uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_KEYGEN_LEAF);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_KEYGEN_LEAF);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_LEAF_NODE, node_num);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_keygen_count++;
        client->hardware_keygen_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_sign(lms_mmio_client_t *client,
                        uint32_t key_handle,
                        const uint8_t I[LMS_I_LEN],
                        uint32_t q,
                        uint32_t lmots_type,
                        const uint8_t coefficients[LMS_MAX_OTS_P],
                        uint8_t outputs[LMS_MAX_OTS_P * LMS_N],
                        uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t chain_bytes;
    uint32_t command_cycles = 0u;
    int status;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t0 = soc_cycle_count();
#endif

    if (!client || !I || !outputs || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    chain_bytes = param.p * param.n;

    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_SIGN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_SIGN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        chain_bytes);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t1 = soc_cycle_count();
#endif
    status = wait_for_result(client, NULL, &command_cycles);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t2 = soc_cycle_count();
#endif
    if (status == LMS_MMIO_OK) {
        read_task_bytes(&client->bus, LMS_MMIO_TASK_CHAIN_WORD_BASE,
                        outputs, chain_bytes);
#if defined(LMS_MMIO_SOC_PROFILE)
        uint32_t prof_t3 = soc_cycle_count();
        client->prof_write_cycles = prof_t1 - prof_t0;
        client->prof_wait_cycles = prof_t2 - prof_t1;
        client->prof_read_cycles = prof_t3 - prof_t2;
#endif
        client->hardware_sign_count++;
        client->hardware_sign_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_sign_taskram(lms_mmio_client_t *client,
                                uint32_t key_handle,
                                const uint8_t I[LMS_I_LEN],
                                uint32_t q,
                                uint32_t lmots_type,
                                const uint8_t coefficients[LMS_MAX_OTS_P],
                                uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t chain_bytes;
    uint32_t command_cycles = 0u;
    int status;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t0 = soc_cycle_count();
#endif

    if (!client || !I || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    chain_bytes = param.p * param.n;

    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_SIGN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_SIGN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        chain_bytes);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t1 = soc_cycle_count();
#endif
    status = wait_for_result(client, NULL, &command_cycles);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t2 = soc_cycle_count();
    client->prof_write_cycles = prof_t1 - prof_t0;
    client->prof_wait_cycles = prof_t2 - prof_t1;
    client->prof_read_cycles = 0u;
#endif
    if (status == LMS_MMIO_OK) {
        client->hardware_sign_count++;
        client->hardware_sign_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

/* ---- R6 Stage 2: streaming LM-OTS Sign via the result window ---------------- */

int lms_mmio_lmots_sign_start(lms_mmio_client_t *client,
                              uint32_t key_handle,
                              const uint8_t I[LMS_I_LEN],
                              uint32_t q,
                              uint32_t lmots_type,
                              const uint8_t coefficients[LMS_MAX_OTS_P])
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t chain_bytes;
    int status;

    if (!client || !I || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    chain_bytes = param.p * param.n;
    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_SIGN);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_SIGN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        chain_bytes);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_KEY, key_handle);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->sign_stream_words = (chain_bytes / LMS_N) * 8u;
    client->sign_stream_active = 1u;
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL,
                        LMS_MMIO_CTRL_START);
    return LMS_MMIO_OK;
}

int lms_mmio_lmots_sign_poll(lms_mmio_client_t *client,
                             uint32_t *count,
                             uint32_t *status)
{
    uint32_t st;
    uint32_t cnt;

    if (!client || !client->sign_stream_active) {
        return LMS_MMIO_ERR_INVALID;
    }
    st = client->bus.read32(client->bus.context, LMS_MMIO_REG_RESULT_STATUS);
    cnt = client->bus.read32(client->bus.context, LMS_MMIO_REG_RESULT_COUNT);
    if (count) {
        *count = cnt;
    }
    if (status) {
        *status = st;
    }
    return LMS_MMIO_OK;
}

int lms_mmio_lmots_sign_read_word(lms_mmio_client_t *client,
                                  uint32_t index,
                                  uint32_t *word)
{
    uint32_t st;

    if (!client || !word || !client->sign_stream_active ||
        index >= client->sign_stream_words) {
        return LMS_MMIO_ERR_INVALID;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_RESULT_ADDR, index);
    /* The B-port data register settles one clock after ADDR; this STATUS read
     * is the required spacing and also surfaces result-window errors. */
    st = client->bus.read32(client->bus.context, LMS_MMIO_REG_RESULT_STATUS);
    if ((st & LMS_MMIO_RESULT_STATUS_ERROR) != 0u) {
        client->last_hw_error =
            client->bus.read32(client->bus.context, LMS_MMIO_REG_RESULT_ERROR);
        return LMS_MMIO_ERR_HARDWARE;
    }
    *word = client->bus.read32(client->bus.context, LMS_MMIO_REG_RESULT_DATA);
    return LMS_MMIO_OK;
}

int lms_mmio_lmots_sign_read_chain(lms_mmio_client_t *client,
                                   uint32_t chain,
                                   uint8_t output[LMS_N])
{
    uint32_t base;
    uint32_t st;
    uint32_t lane;

    if (!client || !output || !client->sign_stream_active) {
        return LMS_MMIO_ERR_INVALID;
    }
    base = chain * 8u;
    if (base + 8u > client->sign_stream_words) {
        return LMS_MMIO_ERR_INVALID;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_RESULT_ADDR, base);
    st = client->bus.read32(client->bus.context, LMS_MMIO_REG_RESULT_STATUS);
    if ((st & LMS_MMIO_RESULT_STATUS_ERROR) != 0u) {
        client->last_hw_error =
            client->bus.read32(client->bus.context, LMS_MMIO_REG_RESULT_ERROR);
        return LMS_MMIO_ERR_HARDWARE;
    }
    for (lane = 0u; lane < 8u; lane++) {
        /* Stage 1b hardware advances RESULT_ADDR after each DATA read. */
        uint32_t word =
            client->bus.read32(client->bus.context, LMS_MMIO_REG_RESULT_DATA);
        output[lane * 4u + 0u] = (uint8_t)word;
        output[lane * 4u + 1u] = (uint8_t)(word >> 8);
        output[lane * 4u + 2u] = (uint8_t)(word >> 16);
        output[lane * 4u + 3u] = (uint8_t)(word >> 24);
    }
    return LMS_MMIO_OK;
}

int lms_mmio_lmots_sign_release(lms_mmio_client_t *client)
{
    if (!client) {
        return LMS_MMIO_ERR_INVALID;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_RESULT_RELEASE, 1u);
    client->sign_stream_active = 0u;
    client->sign_stream_words = 0u;
    return LMS_MMIO_OK;
}

#if LMS_SIGN_RESULT_POST || LMS_SIGN_RESULT_FAST
/* Throughput probe: the same direct-volatile + 4x-unroll access pattern as
 * hw_sign_read_y, but targeting RESULT_DATA.  Addresses are intentionally not
 * validated here; this mode measures the read rate, not signature correctness. */
static void sign_read_chain_fast(lms_mmio_client_t *client, uint32_t chain,
                                 uint8_t output[LMS_N])
{
    volatile uint8_t *base = (volatile uint8_t *)client->bus.context;
    volatile uint32_t *addr =
        (volatile uint32_t *)(base + LMS_MMIO_REG_RESULT_ADDR);
    volatile uint32_t *data =
        (volatile uint32_t *)(base + LMS_MMIO_REG_RESULT_DATA);
    uint32_t lane;

    *addr = chain * 8u;
    (void)*(volatile uint32_t *)(base + LMS_MMIO_REG_RESULT_STATUS);
    if (((uintptr_t)output & 3u) == 0u) {
        uint32_t *out = (uint32_t *)(void *)output;
        out[0] = *data;
        out[1] = *data;
        out[2] = *data;
        out[3] = *data;
        out[4] = *data;
        out[5] = *data;
        out[6] = *data;
        out[7] = *data;
    } else {
        for (lane = 0u; lane < 8u; lane++) {
            uint32_t word = *data;
            output[lane * 4u + 0u] = (uint8_t)word;
            output[lane * 4u + 1u] = (uint8_t)(word >> 8);
            output[lane * 4u + 2u] = (uint8_t)(word >> 16);
            output[lane * 4u + 3u] = (uint8_t)(word >> 24);
        }
    }
}
#endif

int lms_mmio_lmots_sign_stream(lms_mmio_client_t *client,
                               uint32_t key_handle,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint32_t lmots_type,
                               const uint8_t coefficients[LMS_MAX_OTS_P],
                               uint8_t outputs[LMS_MAX_OTS_P * LMS_N],
                               uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t read_chains = 0u;
    uint32_t count = 0u;
    uint32_t st = 0u;
    uint32_t poll;
    uint32_t command_cycles;
    int status;

    if (!client || !outputs) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    /* Issue the command; the result epoch/count reset is the SIGN start. */
    status = lms_mmio_lmots_sign_start(client, key_handle, I, q, lmots_type,
                                       coefficients);
    if (status != LMS_MMIO_OK) {
        return status;
    }
#if LMS_SIGN_RESULT_POST
    /* Throughput probe: wait for DONE without reading, then burst all chains
     * with the direct-pointer loop.  This isolates the read rate. */
    for (poll = 0u; poll < client->timeout_polls; poll++) {
        status = lms_mmio_lmots_sign_poll(client, &count, &st);
        if (status != LMS_MMIO_OK) {
            (void)lms_mmio_lmots_sign_release(client);
            return status;
        }
        if ((st & LMS_MMIO_RESULT_STATUS_ERROR) != 0u) {
            (void)lms_mmio_lmots_sign_release(client);
            return LMS_MMIO_ERR_HARDWARE;
        }
        if ((st & LMS_MMIO_RESULT_STATUS_DONE) != 0u) {
            break;
        }
    }
    if ((st & LMS_MMIO_RESULT_STATUS_DONE) != 0u) {
        for (read_chains = 0u; read_chains < param.p; read_chains++) {
            sign_read_chain_fast(client, read_chains,
                                 &outputs[read_chains * LMS_N]);
        }
    }
#else
    /* Read every chain that has been committed so far; count is monotonic. */
    for (poll = 0u; poll < client->timeout_polls; poll++) {
        status = lms_mmio_lmots_sign_poll(client, &count, &st);
        if (status != LMS_MMIO_OK) {
            (void)lms_mmio_lmots_sign_release(client);
            return status;
        }
        if (count > param.p) {
            count = param.p;
        }
        while (read_chains < count) {
#if LMS_SIGN_RESULT_FAST
            sign_read_chain_fast(client, read_chains,
                                 &outputs[read_chains * LMS_N]);
#else
            status = lms_mmio_lmots_sign_read_chain(
                client, read_chains, &outputs[read_chains * LMS_N]);
            if (status != LMS_MMIO_OK) {
                (void)lms_mmio_lmots_sign_release(client);
                return status;
            }
#endif
            read_chains++;
        }
#if !LMS_SIGN_RESULT_FAST
        if ((st & LMS_MMIO_RESULT_STATUS_ERROR) != 0u) {
            (void)lms_mmio_lmots_sign_release(client);
            client->last_hw_error =
                client->bus.read32(client->bus.context, LMS_MMIO_REG_RESULT_ERROR);
            return LMS_MMIO_ERR_HARDWARE;
        }
#endif
        if ((st & LMS_MMIO_RESULT_STATUS_DONE) != 0u) {
            break;
        }
    }
#endif
    if ((st & LMS_MMIO_RESULT_STATUS_DONE) == 0u ||
        read_chains != param.p) {
        (void)lms_mmio_lmots_sign_release(client);
        return LMS_MMIO_ERR_TIMEOUT;
    }
    command_cycles =
        client->bus.read32(client->bus.context, LMS_MMIO_REG_CYCLE_COUNT);
    (void)lms_mmio_lmots_sign_release(client);
    client->hardware_sign_count++;
    client->hardware_sign_cycles += command_cycles;
    if (cycles) {
        *cycles = command_cycles;
    }
    return LMS_MMIO_OK;
}

int lms_mmio_lmots_verify(lms_mmio_client_t *client,
                          const uint8_t I[LMS_I_LEN],
                          uint32_t q,
                          uint32_t lmots_type,
                          const uint8_t coefficients[LMS_MAX_OTS_P],
                          const uint8_t inputs[LMS_MAX_OTS_P * LMS_N],
                          uint8_t output[LMS_N],
                          uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t chain_bytes;
    uint32_t command_cycles = 0u;
    int status;
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t0 = soc_cycle_count();
#endif

    if (!client || !I || !inputs || !output) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    chain_bytes = param.p * param.n;

    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_VERIFY);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    write_task_bytes(&client->bus, LMS_MMIO_TASK_CHAIN_WORD_BASE,
                     inputs, chain_bytes);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_VERIFY);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t1 = soc_cycle_count();
#endif
    status = wait_for_result(client, output, &command_cycles);
#if defined(LMS_MMIO_SOC_PROFILE)
    uint32_t prof_t2 = soc_cycle_count();
    client->prof_write_cycles = prof_t1 - prof_t0;
    client->prof_wait_cycles = prof_t2 - prof_t1;
    client->prof_read_cycles = 0u;
#endif
    if (status == LMS_MMIO_OK) {
        client->hardware_verify_count++;
        client->hardware_verify_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_verify_taskram(lms_mmio_client_t *client,
                                  const uint8_t I[LMS_I_LEN],
                                  uint32_t q,
                                  uint32_t lmots_type,
                                  const uint8_t coefficients[LMS_MAX_OTS_P],
                                  uint8_t output[LMS_N],
                                  uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }

    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_VERIFY);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_VERIFY);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_verify_count++;
        client->hardware_verify_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_verify_leaf(lms_mmio_client_t *client,
                               const uint8_t I[LMS_I_LEN],
                               uint32_t q,
                               uint32_t node_num,
                               uint32_t lmots_type,
                               const uint8_t coefficients[LMS_MAX_OTS_P],
                               const uint8_t inputs[LMS_MAX_OTS_P * LMS_N],
                               uint8_t output[LMS_N],
                               uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t chain_bytes;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !inputs || !output) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    chain_bytes = param.p * param.n;

    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_VERIFY);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    write_task_bytes(&client->bus, LMS_MMIO_TASK_CHAIN_WORD_BASE,
                     inputs, chain_bytes);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_VERIFY_LEAF);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_LEAF_NODE, node_num);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_verify_count++;
        client->hardware_verify_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

int lms_mmio_lmots_verify_leaf_taskram(lms_mmio_client_t *client,
                                       const uint8_t I[LMS_I_LEN],
                                       uint32_t q,
                                       uint32_t node_num,
                                       uint32_t lmots_type,
                                       const uint8_t coefficients[LMS_MAX_OTS_P],
                                       uint8_t output[LMS_N],
                                       uint32_t *cycles)
{
    lmots_param_t param;
    uint32_t packed[32];
    uint32_t nwords;
    uint32_t command_cycles = 0u;
    int status;

    if (!client || !I || !output) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = lmots_param_hw(&param, lmots_type);
    if (status != LMS_MMIO_OK) {
        return status;
    }

    if (coefficients) {
        nwords = pack_coefficients_words(packed, coefficients, param.p, param.w);
    } else {
        nwords = 0u;
    }
    status = prepare_command(client, LMS_MMIO_CAP_LMOTS_VERIFY);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_W, param.w);
    if (coefficients) {
        write_task_bytes(&client->bus, 0u, (const uint8_t *)packed, nwords * 4u);
    }
    client->bus.write32(client->bus.context, LMS_MMIO_REG_COMMAND,
                        LMS_MMIO_CMD_LMOTS_VERIFY_LEAF);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_OUTPUT_LENGTH,
                        LMS_MMIO_OUTPUT_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_Q, q);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_ARG_LEAF_NODE, node_num);
    write_bytes(&client->bus, LMS_MMIO_REG_IDENTIFIER, I, LMS_I_LEN);
    client->bus.write32(client->bus.context, LMS_MMIO_REG_CONTROL, LMS_MMIO_CTRL_START);
    status = wait_for_result(client, output, &command_cycles);
    if (status == LMS_MMIO_OK) {
        client->hardware_verify_count++;
        client->hardware_verify_cycles += command_cycles;
        if (cycles) {
            *cycles = command_cycles;
        }
    }
    return status;
}

static int lmots_mmio_sign(void *context,
                           const uint8_t I[LMS_I_LEN],
                           lms_hash_alg_t hash_alg,
                           uint32_t q,
                           uint32_t lmots_type,
                           const uint8_t *coefficients,
                           uint8_t *outputs)
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (client->coef_ready) {

        client->coef_ready = 0;
        return lms_mmio_lmots_sign(client, client->key_handle, I, q, lmots_type,
                                   NULL, outputs, NULL) == LMS_MMIO_OK
            ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_sign(client, client->key_handle, I, q, lmots_type,
                               coefficients, outputs, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_mmio_verify(void *context,
                             const uint8_t I[LMS_I_LEN],
                             lms_hash_alg_t hash_alg,
                             uint32_t q,
                             uint32_t lmots_type,
                             const uint8_t *coefficients,
                             const uint8_t *inputs,
                             uint8_t output[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    if (client->coef_ready) {

        client->coef_ready = 0;
        return lms_mmio_lmots_verify(client, I, q, lmots_type,
                                     NULL, inputs, output, NULL) == LMS_MMIO_OK
            ? LMS_OK : LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_verify(client, I, q, lmots_type, coefficients,
                                 inputs, output, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_mmio_keygen(void *context,
                             const uint8_t I[LMS_I_LEN],
                             lms_hash_alg_t hash_alg,
                             uint32_t q,
                             uint32_t lmots_type,
                             uint8_t output[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lms_mmio_lmots_keygen(client, client->key_handle, I, q, lmots_type,
                                 output, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_mmio_get_randomizer_c(lms_mmio_client_t *client,
                                       const uint8_t I[LMS_I_LEN],
                                       uint32_t q,
                                       uint8_t output[LMS_N])
{
    if (client->randomizer_c_slot != NULL) {
        memcpy(output, client->randomizer_c_slot, LMS_N);
        return LMS_OK;
    }
    if (client->trng_fill_c != NULL) {
        return client->trng_fill_c(client->trng_context, output) == 0 ? LMS_OK : LMS_ERR_INVALID;
    }

    return lms_mmio_derive_randomizer(client, 0u, I, q, output, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_mmio_randomizer(void *context,
                                 const uint8_t I[LMS_I_LEN],
                                 lms_hash_alg_t hash_alg,
                                 uint32_t q,
                                 uint8_t output[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;
    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lmots_mmio_get_randomizer_c(client, I, q, output);
}

int lms_mmio_lmots_keygen_enable(lms_mmio_client_t *client, uint32_t key_handle)
{
    int status;
    if (!client || client->allow_fallback || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK ||
        (client->capabilities & LMS_MMIO_CAP_LMOTS_KEYGEN) == 0u) {
        return status != LMS_MMIO_OK ? status : LMS_MMIO_ERR_PROTOCOL;
    }
    client->key_handle = key_handle;
    lmots_keygen_backend_set(lmots_mmio_keygen, client);
    return LMS_MMIO_OK;
}

int lms_mmio_lmots_sign_enable(lms_mmio_client_t *client, uint32_t key_handle)
{
    int status;
    if (!client || client->allow_fallback || key_handle != 0u) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK ||
        (client->capabilities & LMS_MMIO_CAP_LMOTS_SIGN) == 0u) {
        return status != LMS_MMIO_OK ? status : LMS_MMIO_ERR_PROTOCOL;
    }
    client->key_handle = key_handle;
    lmots_sign_backend_set(lmots_mmio_sign, client);
    lmots_sign_randomizer_backend_set(lmots_mmio_randomizer, client);
    return LMS_MMIO_OK;
}

static int lmots_mmio_chain(void *context,
                            const uint8_t I[LMS_I_LEN],
                            lms_hash_alg_t hash_alg,
                            uint32_t q,
                            uint32_t i,
                            uint32_t start,
                            uint32_t steps,
                            uint8_t value[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;

    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lms_mmio_chain(client, I, q, i, start, steps, value, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_mmio_sign_derive(void *context,
                                   const uint8_t I[LMS_I_LEN],
                                   lms_hash_alg_t hash_alg,
                                   uint32_t q,
                                   uint32_t i,
                                   uint32_t start,
                                   uint32_t steps,
                                   uint8_t value[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;

    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lms_mmio_derive_chain(client, 0u, I, q, i, start, steps, value, NULL) == LMS_MMIO_OK
        ? LMS_OK : LMS_ERR_INVALID;
}

static int lmots_mmio_sign_randomizer(void *context,
                                       const uint8_t I[LMS_I_LEN],
                                       lms_hash_alg_t hash_alg,
                                       uint32_t q,
                                       uint8_t output[LMS_N])
{
    lms_mmio_client_t *client = (lms_mmio_client_t *)context;

    if (hash_alg != client->hash_desc->hash_alg) {
        return LMS_ERR_INVALID;
    }
    return lmots_mmio_get_randomizer_c(client, I, q, output);
}

int lms_mmio_lmots_keygen_enable_insecure(lms_mmio_client_t *client)
{
    int status;

    if (!client || client->allow_fallback) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & LMS_MMIO_CAP_CHAIN) == 0u) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    lmots_keygen_chain_backend_set(lmots_mmio_chain, client);
    if ((client->capabilities & LMS_MMIO_CAP_DERIVE_CHAIN) != 0u) {
        lmots_keygen_derive_backend_set(lmots_mmio_sign_derive, client);
    }
    if ((client->capabilities & LMS_MMIO_CAP_LMOTS_KEYGEN) != 0u) {

        lmots_keygen_backend_set(lmots_mmio_keygen, client);
    }
    return LMS_MMIO_OK;
}

void lms_mmio_lmots_keygen_disable(void)
{
    lmots_keygen_chain_backend_set(NULL, NULL);
    lmots_keygen_derive_backend_set(NULL, NULL);
    lmots_keygen_backend_set(NULL, NULL);
}

int lms_mmio_lmots_verify_enable(lms_mmio_client_t *client)
{
    int status;

    if (!client || client->allow_fallback) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & (LMS_MMIO_CAP_CHAIN |
                                LMS_MMIO_CAP_LMOTS_VERIFY)) == 0u) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    if ((client->capabilities & LMS_MMIO_CAP_LMOTS_VERIFY) != 0u) {
        lmots_verify_backend_set(lmots_mmio_verify, client);
    } else {
        lmots_verify_chain_backend_set(lmots_mmio_chain, client);
    }
    return LMS_MMIO_OK;
}

void lms_mmio_lmots_verify_disable(void)
{
    lmots_verify_chain_backend_set(NULL, NULL);
    lmots_verify_backend_set(NULL, NULL);
}

int lms_mmio_lmots_sign_enable_insecure(lms_mmio_client_t *client)
{
    int status;

    if (!client || client->allow_fallback) {
        return LMS_MMIO_ERR_INVALID;
    }
    status = ensure_probe(client);
    if (status != LMS_MMIO_OK) {
        return status;
    }
    if ((client->capabilities & LMS_MMIO_CAP_CHAIN) == 0u) {
        return LMS_MMIO_ERR_PROTOCOL;
    }

    lmots_sign_chain_backend_set(lmots_mmio_chain, client);
    if ((client->capabilities & LMS_MMIO_CAP_DERIVE_CHAIN) != 0u) {
        lmots_sign_derive_backend_set(lmots_mmio_sign_derive, client);
        lmots_sign_randomizer_backend_set(lmots_mmio_sign_randomizer, client);
    }
    if ((client->capabilities & LMS_MMIO_CAP_LMOTS_SIGN) != 0u) {

        lmots_sign_backend_set(lmots_mmio_sign, client);
    }
    return LMS_MMIO_OK;
}

void lms_mmio_lmots_sign_disable(void)
{
    lmots_sign_chain_backend_set(NULL, NULL);
    lmots_sign_derive_backend_set(NULL, NULL);
    lmots_sign_randomizer_backend_set(NULL, NULL);
    lmots_sign_backend_set(NULL, NULL);
}
