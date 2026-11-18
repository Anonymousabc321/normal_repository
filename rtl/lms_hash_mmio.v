`default_nettype none

/* verilator lint_off UNUSEDSIGNAL */
/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off ASSIGNIN */
/* verilator lint_off UNDRIVEN */

//

//

//

//     SHA-256:   0x1600_0000 + 0x000 .. 0x3ff(bus_addr[10] = 0)
//     SHAKE256:  0x1600_0000 + 0x400 .. 0x7ff(bus_addr[10] = 1)

//

module lms_hash_mmio #(
    parameter [31:0] BASE = 32'h1600_0000,
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
    input  wire        bus_valid,
    input  wire        bus_write,
    input  wire [31:0] bus_addr,
    input  wire [31:0] bus_wdata,

    output wire [31:0] bus_rdata,

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

    wire [31:0] dbg_shake_w;
    wire [31:0] dbg_bus_w;
    assign dbg_state = dbg_shake_w;
    assign dbg_bus   = dbg_bus_w;

    /* The trusted recovery profile chooses the security owner. CPU address
     * selection cannot recover the other hash route in the same session. */
    reg [7:0] ksd_hash_r;
    wire sha_recover_accept, shake_recover_accept, sha_ack_accept, shake_ack_accept;
    wire sha_persist_valid, shake_persist_valid;
    wire [895:0] sha_persist_record, shake_persist_record;
    wire [7:0] ksd_owner_w = ksd_hash_r != 0 ? ksd_hash_r :
        sha_recover_accept ? 8'd1 : shake_recover_accept ? 8'd2 : 8'd0;
    wire sha_recover_valid = ksd_recover_valid && ksd_recover_record[663:656] == 8'd1 &&
        (ksd_owner_w == 0 || ksd_owner_w == 1);
    wire shake_recover_valid = ksd_recover_valid && ksd_recover_record[663:656] == 8'd2 &&
        (ksd_owner_w == 0 || ksd_owner_w == 2);
    always @(posedge clk) begin
        if (rst) ksd_hash_r <= 8'd0;
        else if (sha_recover_accept) ksd_hash_r <= 8'd1;
        else if (shake_recover_accept) ksd_hash_r <= 8'd2;
    end
    assign ksd_recover_accept = sha_recover_accept || shake_recover_accept;
    assign ksd_ack_accept = sha_ack_accept || shake_ack_accept;
    assign ksd_persist_valid = sha_persist_valid || shake_persist_valid;
    assign ksd_persist_record = sha_persist_valid ? sha_persist_record : shake_persist_record;
    generate
        if (!ENABLE_SHA256) begin : g_no_sha_ksd
            assign sha_recover_accept = 1'b0;
            assign sha_ack_accept = 1'b0;
            assign sha_persist_valid = 1'b0;
            assign sha_persist_record = 896'b0;
        end
        if (!ENABLE_SHAKE256) begin : g_no_shake_ksd
            assign shake_recover_accept = 1'b0;
            assign shake_ack_accept = 1'b0;
            assign shake_persist_valid = 1'b0;
            assign shake_persist_record = 896'b0;
        end
    endgenerate

    generate
        if (ENABLE_SHA256 && !ENABLE_SHAKE256) begin : g_sha256_only
            lms_sha256_mmio #(
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HAS_SECURITY(HAS_SECURITY),
                .SINGLE_CORE(SINGLE_CORE)

            ) u_sha256 (
                .clk(clk),
                .rst(rst),
                .ksd_recover_valid(sha_recover_valid), .ksd_recover_record(ksd_recover_record),
                .ksd_recover_accept(sha_recover_accept),
                .ksd_ack_valid(ksd_ack_valid && ksd_hash_r == 8'd1),
                .ksd_ack_record(ksd_ack_record), .ksd_ack_accept(sha_ack_accept),
                .ksd_persist_valid(sha_persist_valid), .ksd_persist_record(sha_persist_record),
                .ksd_trusted_fault(ksd_trusted_fault),
                .bus_valid(bus_valid),
                .bus_write(bus_write),
                .bus_addr(bus_addr[9:0]),
                .bus_wdata(bus_wdata),
                .bus_rdata(bus_rdata),
                .stream_wr_en(stream_wr_en),
                .stream_wr_addr(stream_wr_addr),
                .stream_wr_data(stream_wr_data),
                .stream_rd_en(stream_rd_en),
                .stream_rd_addr(stream_rd_addr),
                .stream_rd_valid(stream_rd_valid),
                .stream_rd_data(stream_rd_data),
                .stream_busy(stream_busy)
            );
        end else if (!ENABLE_SHA256 && ENABLE_SHAKE256) begin : g_shake256_only
            wire shake_mem_hit;
            lms_shake256_mmio #(
                .SHAKE_BASE(BASE),
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HAS_SECURITY(HAS_SECURITY),
                .RANDOM_DELAY(RANDOM_DELAY),
                .DERIVE_SHUFFLE(DERIVE_SHUFFLE),
                .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE),
                .SINGLE_CORE(SINGLE_CORE),
                .MASKED(MASKED),
                .TRNG_SIM_MODE(TRNG_SIM_MODE)
            ) u_shake256 (
                .clk(clk),
                .rst(rst),
                .ksd_recover_valid(shake_recover_valid), .ksd_recover_record(ksd_recover_record),
                .ksd_recover_accept(shake_recover_accept),
                .ksd_ack_valid(ksd_ack_valid && ksd_hash_r == 8'd2),
                .ksd_ack_record(ksd_ack_record), .ksd_ack_accept(shake_ack_accept),
                .ksd_persist_valid(shake_persist_valid), .ksd_persist_record(shake_persist_record),
                .ksd_trusted_fault(ksd_trusted_fault),
                .bus_valid(bus_valid),
                .bus_write(bus_write),
                .bus_addr(bus_addr),
                .bus_wdata(bus_wdata),
                .bus_rdata(bus_rdata),
                .mem_hit(shake_mem_hit),
                .stream_wr_en(stream_wr_en),
                .stream_wr_addr(stream_wr_addr),
                .stream_wr_data(stream_wr_data),
                .stream_rd_en(stream_rd_en),
                .stream_rd_addr(stream_rd_addr),
                .stream_rd_valid(stream_rd_valid),
                .stream_rd_data(stream_rd_data),
                .stream_busy(stream_busy),
                .dbg_state(dbg_shake_w),
                .dbg_bus(dbg_bus_w)
            );
        end else if (ENABLE_SHA256 && ENABLE_SHAKE256) begin : g_both
            wire [31:0] sha_rdata;
            wire [31:0] shake_rdata;
            wire        shake_mem_hit;

            wire        sha_stream_rd_valid_unused;
            wire [31:0] sha_stream_rd_data_unused;
            wire        sha_stream_busy_unused;
            wire        sha_valid   = bus_valid && !bus_addr[10];
            wire        shake_valid = bus_valid && bus_addr[10];

            wire [31:0] shake_addr = {bus_addr[31:10] - 22'd1, bus_addr[9:0]};

            lms_sha256_mmio #(
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HAS_SECURITY(HAS_SECURITY),
                .SINGLE_CORE(SINGLE_CORE)

            ) u_sha256 (
                .clk(clk),
                .rst(rst),
                .ksd_recover_valid(sha_recover_valid), .ksd_recover_record(ksd_recover_record),
                .ksd_recover_accept(sha_recover_accept),
                .ksd_ack_valid(ksd_ack_valid && ksd_hash_r == 8'd1),
                .ksd_ack_record(ksd_ack_record), .ksd_ack_accept(sha_ack_accept),
                .ksd_persist_valid(sha_persist_valid), .ksd_persist_record(sha_persist_record),
                .ksd_trusted_fault(ksd_trusted_fault),
                .bus_valid(sha_valid),
                .bus_write(bus_write),
                .bus_addr(bus_addr[9:0]),
                .bus_wdata(bus_wdata),
                .bus_rdata(sha_rdata),

                .stream_wr_en(1'b0),
                .stream_wr_addr(12'b0),
                .stream_wr_data(32'b0),
                .stream_rd_en(1'b0),
                .stream_rd_addr(12'b0),
                .stream_rd_valid(sha_stream_rd_valid_unused),
                .stream_rd_data(sha_stream_rd_data_unused),
                .stream_busy(sha_stream_busy_unused)
            );
            lms_shake256_mmio #(
                .SHAKE_BASE(BASE),
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HAS_SECURITY(HAS_SECURITY),
                .RANDOM_DELAY(RANDOM_DELAY),
                .DERIVE_SHUFFLE(DERIVE_SHUFFLE),
                .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE),
                .SINGLE_CORE(SINGLE_CORE),
                .MASKED(MASKED),
                .TRNG_SIM_MODE(TRNG_SIM_MODE)
            ) u_shake256 (
                .clk(clk),
                .rst(rst),
                .ksd_recover_valid(shake_recover_valid), .ksd_recover_record(ksd_recover_record),
                .ksd_recover_accept(shake_recover_accept),
                .ksd_ack_valid(ksd_ack_valid && ksd_hash_r == 8'd2),
                .ksd_ack_record(ksd_ack_record), .ksd_ack_accept(shake_ack_accept),
                .ksd_persist_valid(shake_persist_valid), .ksd_persist_record(shake_persist_record),
                .ksd_trusted_fault(ksd_trusted_fault),
                .bus_valid(shake_valid),
                .bus_write(bus_write),
                .bus_addr(shake_addr),
                .bus_wdata(bus_wdata),
                .bus_rdata(shake_rdata),
                .mem_hit(shake_mem_hit),
                .stream_wr_en(stream_wr_en),
                .stream_wr_addr(stream_wr_addr),
                .stream_wr_data(stream_wr_data),
                .stream_rd_en(stream_rd_en),
                .stream_rd_addr(stream_rd_addr),
                .stream_rd_valid(stream_rd_valid),
                .stream_rd_data(stream_rd_data),
                .stream_busy(stream_busy),
                .dbg_state(dbg_shake_w),
                .dbg_bus(dbg_bus_w)
            );
            assign bus_rdata = bus_addr[10] ? shake_rdata : sha_rdata;
        end else begin : g_none

            assign bus_rdata = 32'b0;
        end
    endgenerate

endmodule

`default_nettype wire
