# Vivado batch build for the single-core CW310 deployment.

set script_dir [file dirname [file normalize [info script]]]
set project_dir [file dirname $script_dir]
set output_dir [file join $project_dir build cw310]
set firmware_hex [file normalize [file join $project_dir build firmware.hex]]
if {[llength $argv] > 0} { set firmware_hex [file normalize [lindex $argv 0]] }
if {[llength $argv] > 1} { set output_dir [file normalize [lindex $argv 1]] }
if {![file exists $firmware_hex]} { error "Missing firmware image: $firmware_hex" }
file mkdir $output_dir

# CW310 deployment uses the single unmasked SHAKE256 engine and hardware entropy.
set has_sec 1
set ena_sha256 0
set ena_shake256 1
set ins_test_mode 0
set sca_test 0
set random_delay 0
set derive_shuffle 0
set allow_xq_derive 0
set single_core 1
set masked 0
set_property verilog_define "LMS_SOC_HAS_SECURITY=$has_sec LMS_SOC_ENABLE_SHA256=$ena_sha256 LMS_SOC_ENABLE_SHAKE256=$ena_shake256" [current_fileset]

set ibex_dir [file join $project_dir rtl ibex]

read_verilog -sv [file join $ibex_dir prim_assert.sv]
read_verilog -sv [file join $ibex_dir prim_ram_1p_pkg.sv]
read_verilog -sv [file join $ibex_dir prim_secded_pkg.sv]
read_verilog -sv [file join $ibex_dir prim_clock_gating.sv]
read_verilog -sv [file join $ibex_dir prim_buf.sv]
read_verilog -sv [file join $ibex_dir prim_flop.sv]
read_verilog -sv [file join $ibex_dir ibex_pkg.sv]
read_verilog -sv [file join $ibex_dir ibex_alu.sv]
read_verilog -sv [file join $ibex_dir ibex_compressed_decoder.sv]
read_verilog -sv [file join $ibex_dir ibex_controller.sv]
read_verilog -sv [file join $ibex_dir ibex_counter.sv]
read_verilog -sv [file join $ibex_dir ibex_cs_registers.sv]
read_verilog -sv [file join $ibex_dir ibex_csr.sv]
read_verilog -sv [file join $ibex_dir ibex_decoder.sv]
read_verilog -sv [file join $ibex_dir ibex_dummy_instr.sv]
read_verilog -sv [file join $ibex_dir ibex_ex_block.sv]
read_verilog -sv [file join $ibex_dir ibex_fetch_fifo.sv]
read_verilog -sv [file join $ibex_dir ibex_id_stage.sv]
read_verilog -sv [file join $ibex_dir ibex_if_stage.sv]
read_verilog -sv [file join $ibex_dir ibex_load_store_unit.sv]
read_verilog -sv [file join $ibex_dir ibex_multdiv_slow.sv]
read_verilog -sv [file join $ibex_dir ibex_multdiv_fast.sv]
read_verilog -sv [file join $ibex_dir ibex_prefetch_buffer.sv]
read_verilog -sv [file join $ibex_dir ibex_register_file_ff.sv]
read_verilog -sv [file join $ibex_dir ibex_branch_predict.sv]
read_verilog -sv [file join $ibex_dir ibex_wb_stage.sv]
read_verilog -sv [file join $ibex_dir ibex_core.sv]
read_verilog -sv [file join $ibex_dir ibex_top.sv]
read_verilog [file join $project_dir rtl uart_tx.v]
read_verilog [file join $project_dir rtl uart_rx.v]
read_verilog [file join $project_dir rtl lms_fpga_ram.v]
read_verilog [file join $project_dir rtl lms_sha256_round.v]
read_verilog [file join $project_dir rtl lms_sha256_core.v]
read_verilog -sv [file join $project_dir rtl lms_keccak_round.v]
read_verilog [file join $project_dir rtl lms_keccak_core.v]
read_verilog -sv [file join $project_dir rtl kecti3_round.v]
read_verilog -sv [file join $project_dir rtl lms_keccak_core_masked.v]
read_verilog [file join $project_dir rtl lms_ksd_txn.v]
read_verilog [file join $project_dir rtl lms_ksd_sign_adapter.v]
read_verilog [file join $project_dir rtl lms_hash_cmd_check.v]
read_verilog -sv [file join $project_dir rtl lms_sha256_blockgen.v]
read_verilog -sv [file join $project_dir rtl lms_shake256_blockgen.v]
read_verilog -sv [file join $project_dir rtl lms_hash_engine.v]
read_verilog [file join $project_dir rtl lms_trng.v]
read_verilog [file join $project_dir rtl lms_hmac_drbg.v]
read_verilog [file join $project_dir rtl lms_mask_rng.v]
read_verilog [file join $project_dir rtl lms_trng_mmio.v]
read_verilog [file join $project_dir rtl lms_flash_spi.v]
read_verilog [file join $project_dir rtl lms_sha256_mmio.v]
read_verilog [file join $project_dir rtl lms_sha256_sec.v]
read_verilog [file join $project_dir rtl lms_shake256_mmio.v]
read_verilog [file join $project_dir rtl lms_hash_mmio.v]
read_verilog [file join $project_dir rtl lms_sha256_mmio_bridge.v]
read_verilog [file join $project_dir rtl lms_uart_bridge.v]
read_verilog [file join $project_dir rtl lms_cw305_afifo.v]
read_verilog [file join $project_dir rtl lms_ksd_usb_mailbox.v]
read_verilog [file join $project_dir rtl lms_cw305_usb_uart.v]
read_verilog -sv [file join $project_dir rtl lms_soc.v]
read_verilog [file join $project_dir rtl lms_trace.v]
read_verilog [file join $project_dir rtl lms_cw310_top.v]
read_mem $firmware_hex

synth_design -top lms_cw310_top -part xc7k410tfbg676-2 \
    -flatten_hierarchy none -no_lc -directive RuntimeOptimized \
    -generic FIRMWARE_HEX=$firmware_hex -generic INSECURE_TEST_MODE=$ins_test_mode -generic TRNG_SIM_MODE=0 \
    -generic SCA_TEST=$sca_test -generic RANDOM_DELAY=$random_delay -generic DERIVE_SHUFFLE=$derive_shuffle \
    -generic ALLOW_XQ_DERIVE=$allow_xq_derive \
    -generic SINGLE_CORE=$single_core \
    -generic MASKED=$masked \
    -generic ENABLE_SHA256=$ena_sha256 -generic ENABLE_SHAKE256=$ena_shake256 -generic HAS_SECURITY=$has_sec

read_xdc [file join $project_dir flow cw310.xdc]
source [file join $project_dir flow ksd_usb_cdc.tcl]
report_cdc -details -file [file join $output_dir ksd_cdc_synth.txt]

if {[llength [get_clocks -quiet clk50]] > 0} {
    puts "IMPL: clk50 found; hold uncertainty comes from cw310.xdc"
} else {
    puts "IMPL WARNING: clk50 not found"
}

write_checkpoint -force [file join $output_dir lms_cw310_synth.dcp]
report_utilization -file [file join $output_dir utilization_synth.txt]
report_timing_summary -file [file join $output_dir timing_synth.txt]

opt_design

set_param general.maxThreads 1
place_design -directive Explore
phys_opt_design -directive AggressiveExplore

route_design -directive AggressiveExplore

set whs [get_property SLACK [get_timing_paths -delay_type min -max_paths 1]]
puts "IMPL: post-route WHS=$whs"
if {$whs < 0.0} {
    puts "IMPL: WHS negative -> re-route with Explore"
    route_design -directive Explore
    set whs [get_property SLACK [get_timing_paths -delay_type min -max_paths 1]]
    puts "IMPL: WHS after hold fix=$whs"
}
if {$whs < 0.0} {
    error "IMPL: hold still violated (WHS=$whs); refusing to write bitstream"
}
set wns [get_property SLACK [get_timing_paths -delay_type max -max_paths 1]]
puts "IMPL: post-route WNS=$wns"
if {$wns < 0.0} {
    error "IMPL: setup violated (WNS=$wns); refusing to write bitstream"
}

write_checkpoint -force [file join $output_dir lms_cw310_routed.dcp]
report_utilization -file [file join $output_dir utilization_routed.txt]
report_timing_summary -file [file join $output_dir timing_routed.txt]
report_io -file [file join $output_dir io_routed.txt]
report_drc -file [file join $output_dir drc_routed.txt]
set_property BITSTREAM.GENERAL.COMPRESS TRUE [current_design]
write_bitstream -force [file join $output_dir lms_cw310.bit]

puts "BITSTREAM: [file join $output_dir lms_cw310.bit]"
puts "IMPL_LMS_CW310_DONE"
