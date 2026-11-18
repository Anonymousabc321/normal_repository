`default_nettype none

module lms_sha256_mmio_bridge #(
    parameter [31:0] LMS_BASE = 32'h1600_0000,
    parameter INSECURE_TEST_MODE = 0,
    parameter ENABLE_SHA256   = 1,
    parameter ENABLE_SHAKE256 = 0,
    parameter HAS_SECURITY    = 1,
    parameter RANDOM_DELAY    = 0,
    parameter DERIVE_SHUFFLE  = 0,
    parameter ALLOW_XQ_DERIVE = 0,
    parameter SINGLE_CORE     = 0,
    parameter MASKED          = 0,

    parameter TRNG_SIM_MODE    = 0
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        ksd_recover_valid,
    input  wire [895:0] ksd_recover_record,
    output wire        ksd_recover_accept,
    input  wire        ksd_ack_valid,
    input  wire [895:0] ksd_ack_record,
    output wire        ksd_ack_accept,
    output wire        ksd_persist_valid,
    output wire [895:0] ksd_persist_record,
    input  wire        ksd_trusted_fault,
    input  wire        mem_valid,
    input  wire [31:0] mem_addr,
    input  wire [31:0] mem_wdata,
    input  wire [3:0]  mem_wstrb,
    output wire        mem_hit,
    output wire        mem_ready,
    output wire [31:0] mem_rdata,

    input  wire        stream_wr_en,
    input  wire [11:0] stream_wr_addr,
    input  wire [31:0] stream_wr_data,
    input  wire        stream_rd_en,
    input  wire [11:0] stream_rd_addr,
    output wire        stream_rd_valid,
    output wire [31:0] stream_rd_data,
    output wire        stream_busy,
    output wire [31:0] dbg_state
    ,output wire [31:0] dbg_bus
);

    wire address_hit = mem_valid && mem_addr[31:11] == LMS_BASE[31:11];
    wire full_word_write = mem_wstrb == 4'b1111;
    wire [31:0] accelerator_rdata;

    assign mem_hit = address_hit;
    assign mem_ready = address_hit;
    assign mem_rdata = address_hit ? accelerator_rdata : 32'b0;

    lms_hash_mmio #(
        .BASE(LMS_BASE),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .ENABLE_SHA256(ENABLE_SHA256),
        .ENABLE_SHAKE256(ENABLE_SHAKE256),
        .HAS_SECURITY(HAS_SECURITY),
        .RANDOM_DELAY(RANDOM_DELAY),
        .DERIVE_SHUFFLE(DERIVE_SHUFFLE),
        .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE),
        .SINGLE_CORE(SINGLE_CORE),
        .MASKED(MASKED),
        .TRNG_SIM_MODE(TRNG_SIM_MODE)
    ) accelerator (
        .clk(clk),
        .rst(rst),
        .ksd_recover_valid(ksd_recover_valid), .ksd_recover_record(ksd_recover_record),
        .ksd_recover_accept(ksd_recover_accept),
        .ksd_ack_valid(ksd_ack_valid), .ksd_ack_record(ksd_ack_record),
        .ksd_ack_accept(ksd_ack_accept), .ksd_persist_valid(ksd_persist_valid),
        .ksd_persist_record(ksd_persist_record), .ksd_trusted_fault(ksd_trusted_fault),
        .bus_valid(address_hit),
        .bus_write(address_hit && full_word_write),
        .bus_addr(mem_addr),
        .bus_wdata(mem_wdata),
        .bus_rdata(accelerator_rdata),
        .stream_wr_en(stream_wr_en),
        .stream_wr_addr(stream_wr_addr),
        .stream_wr_data(stream_wr_data),
        .stream_rd_en(stream_rd_en),
        .stream_rd_addr(stream_rd_addr),
        .stream_rd_valid(stream_rd_valid),
        .stream_rd_data(stream_rd_data),
        .stream_busy(stream_busy),
        .dbg_state(dbg_state),
        .dbg_bus(dbg_bus)
    );

endmodule

`default_nettype wire
