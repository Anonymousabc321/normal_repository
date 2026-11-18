#ifndef LMS_UART_PROTO_H
#define LMS_UART_PROTO_H

#include <stdint.h>

#define LMS_UART_RESPONSE   0x52u
#define LMS_UART_PING_BASE  0xA5u

#define LMS_OP_PING            0x01u
#define LMS_OP_RESET_KEEP      0x02u
#define LMS_OP_PROTO_VERSION   0x03u
#define LMS_OP_CAPABILITIES    0x04u

#define LMS_OP_HASH               0x05u
#define LMS_OP_HASH_RAM           0x06u
#define LMS_OP_CHAIN              0x07u
#define LMS_OP_DERIVE             0x08u
#define LMS_OP_PRF_CHAIN          0x09u
#define LMS_OP_DERIVE_RANDOMIZER  0x0Au
#define LMS_OP_DERIVE_XQ          0x0Bu

/* ---- LM-OTS 0x0C–0x12 ---- */
#define LMS_OP_OTS_KEYGEN      0x0Cu
#define LMS_OP_OTS_SIGN        0x0Du
#define LMS_OP_OTS_VERIFY      0x0Eu
#define LMS_OP_OTS_VERIFY_LEAF 0x0Fu
#define LMS_OP_OTS_COEFFS      0x10u
#define LMS_OP_OTS_SNAPSHOT    0x11u
#define LMS_OP_OTS_EVENTS      0x12u

/* ---- LMS 0x13–0x15 ---- */
#define LMS_OP_LMS_KEYGEN 0x13u
#define LMS_OP_LMS_SIGN   0x14u
#define LMS_OP_LMS_VERIFY 0x15u

/* Reserved for HSS. This firmware dispatches single-tree LMS operations. */
#define LMS_OP_HSS_KEYGEN 0x16u
#define LMS_OP_HSS_SIGN   0x17u
#define LMS_OP_HSS_VERIFY 0x18u

#define LMS_OP_SEED_LOAD 0x19u
#define LMS_OP_C_LOAD    0x1Au
#define LMS_OP_NVM_SYNC  0x1Bu

/* ---- TRNG 0x1C–0x1E ---- */
#define LMS_OP_TRNG_READ   0x1Cu
#define LMS_OP_TRNG_STATUS 0x1Du
#define LMS_OP_TRNG_ACK    0x1Eu

/* ---- SPI flash 0x1F–0x21 ---- */
#define LMS_OP_FLASH_PROBE 0x1Fu
#define LMS_OP_FLASH_PROG  0x20u
#define LMS_OP_FLASH_CMD   0x21u

#define LMS_OP_SEC_STATE            0x22u
#define LMS_OP_SEC_SIGN             0x23u
#define LMS_OP_SEC_LMS_SIGN         0x24u
#define LMS_OP_SEC_LMS_KEYGEN       0x25u
#define LMS_OP_SEC_LMS_KEYGEN_NEW   0x26u

#define LMS_OP_OBSERVE      0x27u
#define LMS_OP_TXTRACE      0x28u
#define LMS_OP_SEED_ECHO    0x29u
#define LMS_OP_KEYGEN_STAGE 0x2Au

#define LMS_OP_DIAG_7A 0x2Bu
#define LMS_OP_DIAG_7B 0x2Cu
#define LMS_OP_DIAG_7C 0x2Du
#define LMS_OP_DIAG_7D 0x2Eu
#define LMS_OP_DIAG_7E 0x2Fu
#define LMS_OP_DIAG_7F 0x30u

#endif /* LMS_UART_PROTO_H */
