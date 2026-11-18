.DEFAULT_GOAL := library

BUILD ?= build
CC = gcc
AR ?= ar
CFLAGS ?= -O2 -std=c99 -Wall -Wextra
RISCV_PREFIX ?= riscv64-unknown-elf-
PYTHON ?= python3
VIVADO ?= vivado

INCLUDES := -Iinclude -Ihashs
HEADERS := $(wildcard include/*.h src/*.h fw/*.h hashs/*.h)
LMS := src/lms.c src/lms_params.c src/lm_ots.c src/lms_tree.c src/lms_sign.c src/lms_verify.c
HASH := hashs/sha256.c hashs/fips202.c
XKCP := hashs/xkcp/xkcp_shake.c hashs/xkcp/KeccakP-1600-inplace32BI.c
HOST := $(LMS) src/hss.c src/hash_api.c src/lms_coprocess.c $(HASH) hashs/haraka.c $(HOST_HASH_SOURCES)
OBJECTS := $(patsubst %.c,$(BUILD)/host/%.o,$(HOST))
FIRMWARE := fw/lms_soc_start.S fw/lms_soc_smoke.c fw/lms_soc_runtime.c fw/lms_sec_state.c \
            $(LMS) src/hash_api.c src/lms_mmio.c src/lms_subtree.c $(HASH) fw/lms_rnd_trng.c
RVFLAGS := -march=rv32imc_zicsr -mabi=ilp32 -O2 -Wall -Wextra -ffreestanding \
           -fno-builtin -ffunction-sections -fdata-sections -nostdlib -nostartfiles -msmall-data-limit=0
FWFLAGS := -DFW_HASH_SHAKE256 -DLMS_NO_HARAKA -DLMS_RND_IMPL_TRNG \
           -DLMS_FW_OTS_SNAPSHOT=0 -DLMS_FW_PAPER_BENCH=0 -DLMS_FW_PAPER_ROOT_ONLY=0 \
           -DLMS_SIGN_RESULT_STREAM=0 -DLMS_SIGN_RESULT_POST=0 -DLMS_SIGN_RESULT_FAST=0

.PHONY: library test test-xkcp firmware bitstream
library: $(BUILD)/libseclms.a

$(BUILD)/host/%.o: %.c $(HEADERS) $(if $(HOST_HASH_SOURCES),$(wildcard hashs/xkcp/*.h)) Makefile
	@mkdir -p "$(@D)"
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) -c $< -o "$@"

$(BUILD)/libseclms.a: $(OBJECTS)
	$(AR) rcs "$@" $(OBJECTS)

$(BUILD)/test_%: tests/test_%.c $(BUILD)/libseclms.a
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $< "$(BUILD)/libseclms.a" -o "$@"

test: $(BUILD)/test_lms $(BUILD)/test_hss
	"$(BUILD)/test_lms"
	"$(BUILD)/test_hss"

test-xkcp:
	$(MAKE) BUILD="$(BUILD)/xkcp" CPPFLAGS="$(CPPFLAGS) -DLMS_HASH_XKCP_32BI" HOST_HASH_SOURCES="$(XKCP)" test

firmware: $(BUILD)/firmware.hex

$(BUILD)/firmware.elf: $(FIRMWARE) $(HEADERS) fw/lms_soc.ld Makefile
	@mkdir -p "$(@D)"
	$(RISCV_PREFIX)gcc $(RVFLAGS) $(INCLUDES) -Isrc -Ifw $(FWFLAGS) \
	    -Wl,-T,fw/lms_soc.ld,--gc-sections,--no-relax,-Map,$(BUILD)/firmware.map \
	    -o "$@" $(FIRMWARE) -lgcc

$(BUILD)/firmware.bin: $(BUILD)/firmware.elf
	$(RISCV_PREFIX)objcopy -O binary "$<" "$@"

$(BUILD)/firmware.hex: $(BUILD)/firmware.bin flow/firmware_hex.py
	"$(PYTHON)" flow/firmware_hex.py "$<" "$@"

bitstream: $(BUILD)/firmware.hex
	"$(VIVADO)" -mode batch -notrace -source flow/impl_lms_cw310.tcl \
	    -log "$(BUILD)/vivado.log" -journal "$(BUILD)/vivado.jou" \
	    -tclargs "$<" "$(BUILD)/cw310"
