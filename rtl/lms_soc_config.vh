`ifndef LMS_SOC_CONFIG_VH
`define LMS_SOC_CONFIG_VH

`timescale 1 ns / 1 ps
`default_nettype none

`define LMS_SOC_CLK 50000000
`define LMS_SOC_RAM_XADR 17

`define LMS_SOC_ENABLE_SHA256   1'b0
`define LMS_SOC_ENABLE_SHAKE256 1'b1

`define LMS_SOC_HAS_SECURITY    1'b1

`endif
