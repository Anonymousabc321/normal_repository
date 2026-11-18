`default_nettype none
/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off UNUSEDSIGNAL */

module lms_sha256_sec #(
    parameter INSECURE_TEST_MODE = 0,

    parameter HASH_TYPE = 0,

    parameter SEED_SHARED = 0
) (
    input  wire        clk,
    input  wire        rst,

    input  wire        bus_valid,
    input  wire        bus_write,
    input  wire [9:0]  bus_addr,
    input  wire [31:0] bus_wdata,
    output reg  [31:0] bus_rdata,

    input  wire        reg_write_ok,

    input  wire        seed_latch_en,

    input  wire [255:0] seed_share_in,
    input  wire        kwrap_latch_en,
    input  wire        kstate_latch_en,
    input  wire        mc_step_en,
    input  wire        mc_load_en,
    input  wire [31:0] mc_load_value,
    input  wire        wrap_start,
    input  wire        wrap_is_unwrap,
    input  wire        hmac_start,
    input  wire [7:0]  input_length,

    input  wire        stc_start,
    input  wire [15:0] stc_state,
    input  wire [31:0] stc_ctr,
    input  wire [7:0]  stc_aad,

    output wire        busy,
    output wire        done,
    output wire        error_valid,
    output wire [31:0] error_code,
    output wire [31:0] cycles,

    output wire        stc_active,
    output wire [31:0] stc_tx,

    output wire [255:0] result_data,
    output wire [7:0]   result_wmask,
    output wire         result_valid,

    output wire [31:0] mc_next_value,

    output wire [255:0] seed_data,
    output wire [255:0] seed_data_b,
    output wire         seed_valid,

    output wire         k_wrap_valid,
    output wire         k_state_valid,

    output wire         core_start,
    output wire         core_init,
    output wire         core_state_load,
    output wire [255:0] core_state_in,

    output wire         sec_is_hmac,
    output wire [1:0]   wrap_phase,
    output wire [1:0]   block_index,
    output wire [1:0]   block_count,
    output wire [255:0] k_wrap,
    output wire [255:0] k_state,
    output wire [255:0] wrap_ct,
    output wire [255:0] wrap_tag,

    output wire [255:0] wrap_mu_inner,
    input  wire         core_busy,
    input  wire         core_done,
    input  wire [255:0] core_digest
);

    localparam [31:0] ERR_CONTROL = 32'h00000007;

    localparam [9:0] REG_SIM_MC       = 10'h060;
    localparam [9:0] REG_SEED_BASE    = 10'h080;
    localparam [9:0] REG_WRAPPED_BASE = 10'h0a0;  /* 48B: 0x0a0..0x0cf */
    localparam [9:0] REG_KWRAP_BASE   = 10'h0e0;  /* 32B: 0x0e0..0x0ff */

    localparam [3:0] SEC_IDLE       = 4'd0;
    localparam [3:0] SEC_START_CORE = 4'd1;
    localparam [3:0] SEC_WAIT_CORE  = 4'd2;
    localparam [3:0] SEC_DONE       = 4'd3;

    reg [31:0] seed_staging_words [0:7];
    reg [255:0] seed_a_r;
    reg [255:0] seed_b_r;
    reg seed_valid_r;
    reg [31:0] k_wrap_staging [0:7];
    reg [31:0] k_state_staging [0:7];
    reg [255:0] k_wrap_r;
    reg [255:0] k_state_r;
    reg k_wrap_valid_r;
    reg k_state_valid_r;

    reg [31:0] sim_mc_r;

    reg [31:0] wrapped_words [0:11];

    reg [1:0] wrap_phase_r;
    reg wrap_is_unwrap_r;
    reg sec_is_hmac_r;
    reg [255:0] wrap_mask_r;
    reg [255:0] wrap_tag_r;
    reg [255:0] wrap_mu_inner_r;
    reg stc_active_r;
    reg [31:0] stc_tx_r;

    reg [1:0] block_index_r;
    reg [1:0] block_count_r;
    reg core_start_r;
    reg [3:0] sec_state_r;

    reg [31:0] sec_cycles_r;
    reg [255:0] sec_digest_r;
    reg sec_error_r;
    reg [31:0] sec_error_code_r;
    reg sec_has_result_r;

    wire [3:0] wrapped_windex_w = bus_addr[5:2] - 4'h8;

    wire [31:0] hmac_inner_blocks_w = (HASH_TYPE == 1)
        ? 32'd2
        : ((32'd64 + {24'b0, input_length} + 32'd72) >> 6);

    wire [255:0] wrap_ct_w = wrap_is_unwrap_r
        ? {wrapped_words[0][7:0], wrapped_words[0][15:8],
           wrapped_words[0][23:16], wrapped_words[0][31:24],
           wrapped_words[1][7:0], wrapped_words[1][15:8],
           wrapped_words[1][23:16], wrapped_words[1][31:24],
           wrapped_words[2][7:0], wrapped_words[2][15:8],
           wrapped_words[2][23:16], wrapped_words[2][31:24],
           wrapped_words[3][7:0], wrapped_words[3][15:8],
           wrapped_words[3][23:16], wrapped_words[3][31:24],
           wrapped_words[4][7:0], wrapped_words[4][15:8],
           wrapped_words[4][23:16], wrapped_words[4][31:24],
           wrapped_words[5][7:0], wrapped_words[5][15:8],
           wrapped_words[5][23:16], wrapped_words[5][31:24],
           wrapped_words[6][7:0], wrapped_words[6][15:8],
           wrapped_words[6][23:16], wrapped_words[6][31:24],
           wrapped_words[7][7:0], wrapped_words[7][15:8],
           wrapped_words[7][23:16], wrapped_words[7][31:24]}
        : ((seed_a_r ^ wrap_mask_r) ^ seed_b_r);

    wire [127:0] wrapped_tag_w = {
        wrapped_words[8][7:0], wrapped_words[8][15:8],
        wrapped_words[8][23:16], wrapped_words[8][31:24],
        wrapped_words[9][7:0], wrapped_words[9][15:8],
        wrapped_words[9][23:16], wrapped_words[9][31:24],
        wrapped_words[10][7:0], wrapped_words[10][15:8],
        wrapped_words[10][23:16], wrapped_words[10][31:24],
        wrapped_words[11][7:0], wrapped_words[11][15:8],
        wrapped_words[11][23:16], wrapped_words[11][31:24]
    };

    assign sec_is_hmac  = sec_is_hmac_r;
    assign wrap_phase   = wrap_phase_r;
    assign block_index  = block_index_r;
    assign block_count  = block_count_r;
    assign k_wrap       = k_wrap_r;
    assign k_state      = k_state_r;
    assign wrap_ct      = wrap_ct_w;
    assign wrap_tag     = wrap_tag_r;
    assign wrap_mu_inner = wrap_mu_inner_r;

    assign core_start = core_start_r;
    assign core_init = (block_index_r == 2'd0);
    assign core_state_load = 1'b0;
    assign core_state_in = 256'b0;
    assign stc_active = stc_active_r;
    assign stc_tx = stc_tx_r;

    assign busy = (sec_state_r != SEC_IDLE);
    assign done = (sec_state_r == SEC_DONE);
    assign error_valid = done && sec_error_r;
    assign error_code = sec_error_code_r;
    assign cycles = sec_cycles_r;
    assign result_valid = done && sec_has_result_r;
    assign result_wmask = 8'hff;
    genvar result_index;
    generate
        for (result_index = 0; result_index < 8; result_index = result_index + 1) begin : g_result_data
            assign result_data[255 - result_index * 32 -: 32] = {
                sec_digest_r[255 - (result_index * 32 + 24) -: 8],
                sec_digest_r[255 - (result_index * 32 + 16) -: 8],
                sec_digest_r[255 - (result_index * 32 + 8) -: 8],
                sec_digest_r[255 - result_index * 32 -: 8]
            };
        end
    endgenerate

    assign mc_next_value = mc_load_en ? ((mc_load_value > sim_mc_r) ? mc_load_value : sim_mc_r)
                         : mc_step_en ? ((sim_mc_r == 32'hFFFFFFFF) ? 32'hFFFFFFFF
                                                                     : sim_mc_r + 1'b1)
                         : sim_mc_r + 1'b1;
    assign seed_data = seed_a_r;
    assign seed_data_b = seed_b_r;
    assign seed_valid = seed_valid_r;
    assign k_wrap_valid = k_wrap_valid_r;
    assign k_state_valid = k_state_valid_r;

    integer latch_index;

    always @* begin
        bus_rdata = 32'b0;
        if (bus_valid && !bus_write) begin
            if (bus_addr == REG_SIM_MC) begin
                bus_rdata = sim_mc_r;
            end else if (bus_addr >= REG_WRAPPED_BASE &&
                         bus_addr < REG_WRAPPED_BASE + 48 &&
                         bus_addr[1:0] == 2'b00) begin
                bus_rdata = wrapped_words[wrapped_windex_w];
            end
        end
    end

    always @(posedge clk) begin
        core_start_r <= 1'b0;

        if (bus_valid && bus_write && reg_write_ok) begin

            if (bus_addr >= REG_SEED_BASE &&
                bus_addr < REG_SEED_BASE + 32 && bus_addr[1:0] == 2'b00) begin
                seed_staging_words[bus_addr[4:2]] <= bus_wdata;
            end
            if (bus_addr >= REG_KWRAP_BASE &&
                bus_addr < REG_KWRAP_BASE + 32 && bus_addr[1:0] == 2'b00) begin

                k_wrap_staging[bus_addr[4:2]] <= bus_wdata;
                k_state_staging[bus_addr[4:2]] <= bus_wdata;
            end
            if (bus_addr >= REG_WRAPPED_BASE &&
                bus_addr < REG_WRAPPED_BASE + 48 && bus_addr[1:0] == 2'b00) begin
                wrapped_words[wrapped_windex_w] <= bus_wdata;
            end
        end

        if (seed_latch_en) begin
            for (latch_index = 0; latch_index < 8; latch_index = latch_index + 1) begin
                seed_a_r[255 - latch_index * 32 -: 32] <= {
                    seed_staging_words[latch_index][7:0],
                    seed_staging_words[latch_index][15:8],
                    seed_staging_words[latch_index][23:16],
                    seed_staging_words[latch_index][31:24]
                } ^ (SEED_SHARED ? seed_share_in[255 - latch_index * 32 -: 32] : 32'b0);
                seed_b_r[255 - latch_index * 32 -: 32] <=
                    (SEED_SHARED ? seed_share_in[255 - latch_index * 32 -: 32] : 32'b0);
                seed_staging_words[latch_index] <= 32'b0;
            end
            seed_valid_r <= 1'b1;
        end
        if (kwrap_latch_en) begin
            for (latch_index = 0; latch_index < 8; latch_index = latch_index + 1) begin
                k_wrap_r[255 - latch_index * 32 -: 32] <= {
                    k_wrap_staging[latch_index][7:0],
                    k_wrap_staging[latch_index][15:8],
                    k_wrap_staging[latch_index][23:16],
                    k_wrap_staging[latch_index][31:24]
                };
                k_wrap_staging[latch_index] <= 32'b0;
            end
            k_wrap_valid_r <= 1'b1;
        end
        if (kstate_latch_en) begin
            for (latch_index = 0; latch_index < 8; latch_index = latch_index + 1) begin
                k_state_r[255 - latch_index * 32 -: 32] <= {
                    k_state_staging[latch_index][7:0],
                    k_state_staging[latch_index][15:8],
                    k_state_staging[latch_index][23:16],
                    k_state_staging[latch_index][31:24]
                };
                k_state_staging[latch_index] <= 32'b0;
            end
            k_state_valid_r <= 1'b1;
        end
        if (mc_step_en) begin

            sim_mc_r <= (sim_mc_r == 32'hFFFFFFFF) ? 32'hFFFFFFFF : sim_mc_r + 1'b1;
        end
        if (mc_load_en) begin

            sim_mc_r <= (mc_load_value > sim_mc_r) ? mc_load_value : sim_mc_r;
        end

        if (wrap_start) begin
            wrap_phase_r <= 2'd0;
            wrap_is_unwrap_r <= wrap_is_unwrap;
            sec_is_hmac_r <= 1'b0;
            block_index_r <= 2'd0;
            block_count_r <= 2'd2;
            sec_cycles_r <= 32'd1;
            sec_state_r <= SEC_START_CORE;
        end else if (hmac_start) begin
            wrap_phase_r <= 2'd1;
            wrap_is_unwrap_r <= 1'b0;
            sec_is_hmac_r <= 1'b1;
            block_index_r <= 2'd0;
            block_count_r <= hmac_inner_blocks_w[1:0];
            sec_cycles_r <= 32'd1;
            sec_state_r <= SEC_START_CORE;
        end else if (stc_start) begin

            sim_mc_r <= sim_mc_r + 1'b1;
            stc_active_r <= 1'b1;
            stc_tx_r <= sim_mc_r + 1'b1;
            wrap_phase_r <= 2'd1;
            wrap_is_unwrap_r <= 1'b0;
            sec_is_hmac_r <= 1'b1;
            block_index_r <= 2'd0;
            block_count_r <= hmac_inner_blocks_w[1:0];
            sec_cycles_r <= 32'd1;
            sec_state_r <= SEC_START_CORE;
        end else if (sec_state_r == SEC_START_CORE) begin
            core_start_r <= 1'b1;
            sec_cycles_r <= sec_cycles_r + 1'b1;
            sec_state_r <= SEC_WAIT_CORE;
        end else if (sec_state_r == SEC_WAIT_CORE) begin
            sec_cycles_r <= sec_cycles_r + 1'b1;
            if (core_done) begin
                if (sec_is_hmac_r) begin
                    /* HMAC */
                    if (wrap_phase_r == 2'd1) begin
                        if (block_index_r + 1'b1 < block_count_r) begin
                            block_index_r <= block_index_r + 1'b1;
                            sec_state_r <= SEC_START_CORE;
                        end else begin
                            wrap_tag_r <= core_digest;
                            wrap_phase_r <= 2'd2;
                            block_index_r <= 2'd0;
                            block_count_r <= 2'd2;
                            sec_state_r <= SEC_START_CORE;
                        end
                    end else begin
                        if (block_index_r + 1'b1 < block_count_r) begin
                            block_index_r <= block_index_r + 1'b1;
                            sec_state_r <= SEC_START_CORE;
                        end else begin
                            sec_digest_r <= core_digest;
                            sec_error_r <= 1'b0;
                            sec_error_code_r <= 32'b0;
                            sec_has_result_r <= 1'b1;
                            sec_state_r <= SEC_DONE;
                        end
                    end
                end else if (wrap_phase_r == 2'd0) begin

                    if (block_index_r + 1'b1 < block_count_r) begin
                        block_index_r <= block_index_r + 1'b1;
                        sec_state_r <= SEC_START_CORE;
                    end else begin
                        wrap_mu_inner_r <= core_digest;
                        wrap_phase_r <= 2'd1;
                        block_index_r <= 2'd0;
                        block_count_r <= 2'd2;
                        sec_state_r <= SEC_START_CORE;
                    end
                end else if (wrap_phase_r == 2'd1) begin

                    if (block_index_r + 1'b1 < block_count_r) begin
                        block_index_r <= block_index_r + 1'b1;
                        sec_state_r <= SEC_START_CORE;
                    end else begin
                        wrap_mask_r <= core_digest;
                        wrap_phase_r <= 2'd2;
                        block_index_r <= 2'd0;
                        block_count_r <= 2'd2;
                        sec_state_r <= SEC_START_CORE;
                    end
                end else if (wrap_phase_r == 2'd2) begin

                    if (block_index_r + 1'b1 < block_count_r) begin
                        block_index_r <= block_index_r + 1'b1;
                        sec_state_r <= SEC_START_CORE;
                    end else begin
                        wrap_tag_r <= core_digest;
                        wrap_phase_r <= 2'd3;
                        block_index_r <= 2'd0;
                        block_count_r <= 2'd2;
                        sec_state_r <= SEC_START_CORE;
                    end
                end else begin

                    if (block_index_r + 1'b1 < block_count_r) begin
                        block_index_r <= block_index_r + 1'b1;
                        sec_state_r <= SEC_START_CORE;
                    end else begin
                        sec_digest_r <= core_digest;
                        sec_has_result_r <= 1'b0;
                        if (!wrap_is_unwrap_r) begin

                            for (latch_index = 0; latch_index < 8; latch_index = latch_index + 1) begin
                                wrapped_words[latch_index] <= {
                                    wrap_ct_w[255 - (latch_index * 32 + 24) -: 8],
                                    wrap_ct_w[255 - (latch_index * 32 + 16) -: 8],
                                    wrap_ct_w[255 - (latch_index * 32 + 8) -: 8],
                                    wrap_ct_w[255 - latch_index * 32 -: 8]
                                };
                            end
                            for (latch_index = 0; latch_index < 4; latch_index = latch_index + 1) begin
                                wrapped_words[8 + latch_index] <= {
                                    core_digest[255 - (latch_index * 32 + 24) -: 8],
                                    core_digest[255 - (latch_index * 32 + 16) -: 8],
                                    core_digest[255 - (latch_index * 32 + 8) -: 8],
                                    core_digest[255 - latch_index * 32 -: 8]
                                };
                            end
                            sec_error_r <= 1'b0;
                            sec_error_code_r <= 32'b0;
                        end else if (wrapped_tag_w == core_digest[255:128]) begin

                            seed_a_r <= (wrap_ct_w ^ wrap_mask_r) ^
                                        (SEED_SHARED ? seed_share_in : 256'b0);
                            seed_b_r <= SEED_SHARED ? seed_share_in : 256'b0;
                            seed_valid_r <= 1'b1;
                            sec_error_r <= 1'b0;
                            sec_error_code_r <= 32'b0;
                        end else begin

                            sec_error_r <= 1'b1;
                            sec_error_code_r <= ERR_CONTROL;
                        end
                        sec_state_r <= SEC_DONE;
                    end
                end
            end
        end else if (sec_state_r == SEC_DONE) begin
            sec_state_r <= SEC_IDLE;
            stc_active_r <= 1'b0;
        end

        if (rst) begin
            seed_a_r <= 256'b0;
            seed_b_r <= 256'b0;
            seed_valid_r <= 1'b0;
            k_wrap_r <= 256'b0;
            k_state_r <= 256'b0;
            k_wrap_valid_r <= 1'b0;
            k_state_valid_r <= 1'b0;
            sim_mc_r <= 32'b0;
            wrap_phase_r <= 2'b0;
            wrap_is_unwrap_r <= 1'b0;
            sec_is_hmac_r <= 1'b0;
            wrap_mask_r <= 256'b0;
            wrap_tag_r <= 256'b0;
            wrap_mu_inner_r <= 256'b0;
            stc_active_r <= 1'b0;
            stc_tx_r <= 32'b0;
            block_index_r <= 2'b0;
            block_count_r <= 2'b0;
            core_start_r <= 1'b0;
            sec_state_r <= SEC_IDLE;
            sec_cycles_r <= 32'b0;
            sec_digest_r <= 256'b0;
            sec_error_r <= 1'b0;
            sec_error_code_r <= 32'b0;
            sec_has_result_r <= 1'b0;
            for (latch_index = 0; latch_index < 8; latch_index = latch_index + 1) begin
                seed_staging_words[latch_index] <= 32'b0;
                k_wrap_staging[latch_index] <= 32'b0;
                k_state_staging[latch_index] <= 32'b0;
            end
            for (latch_index = 0; latch_index < 12; latch_index = latch_index + 1) begin
                wrapped_words[latch_index] <= 32'b0;
            end
        end
    end

endmodule

`default_nettype wire
