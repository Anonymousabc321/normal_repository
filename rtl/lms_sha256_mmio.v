`default_nettype none

/* verilator lint_off WIDTHTRUNC */
/* verilator lint_off WIDTHEXPAND */
/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off UNUSEDSIGNAL */

module lms_sha256_mmio #(
    parameter INSECURE_TEST_MODE = 0,
    parameter HAS_SECURITY = 1,
    parameter SINGLE_CORE = 0

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
    input  wire [9:0]  bus_addr,
    input  wire [31:0] bus_wdata,
    output reg  [31:0] bus_rdata,

    input  wire        stream_wr_en,
    input  wire [11:0] stream_wr_addr,
    input  wire [31:0] stream_wr_data,
    input  wire        stream_rd_en,
    input  wire [11:0] stream_rd_addr,
    output wire        stream_rd_valid,
    output wire [31:0] stream_rd_data,
    output wire        stream_busy
);
    localparam [31:0] VERSION = 32'h00000007;
    localparam [31:0] CAPABILITY = 32'h000000e7 |
        (INSECURE_TEST_MODE ? 32'h00000008 : 32'b0) |
        (INSECURE_TEST_MODE ? 32'h00000010 : 32'h00000000) |
        32'h00000300 | 32'h00000400 |
        32'h00002000 |
        32'h00004000 |
        (HAS_SECURITY ? 32'h00000800 : 32'h00000000) |
        (HAS_SECURITY ? 32'h00008000 : 32'h00000000);

    localparam [9:0] REG_VERSION       = 10'h000;
    localparam [9:0] REG_CAPABILITY    = 10'h004;
    localparam [9:0] REG_COMMAND       = 10'h008;
    localparam [9:0] REG_CONTROL       = 10'h00c;
    localparam [9:0] REG_STATUS        = 10'h010;
    localparam [9:0] REG_ERROR         = 10'h014;
    localparam [9:0] REG_INPUT_LENGTH  = 10'h018;
    localparam [9:0] REG_OUTPUT_LENGTH = 10'h01c;
    localparam [9:0] REG_CYCLE_COUNT   = 10'h020;
    localparam [9:0] REG_ARG_Q         = 10'h024;
    localparam [9:0] REG_ARG_I         = 10'h028;
    localparam [9:0] REG_ARG_START     = 10'h02c;
    localparam [9:0] REG_ARG_STEPS     = 10'h030;
    localparam [9:0] REG_ARG_KEY       = 10'h034;
    localparam [9:0] REG_TASK_ADDR     = 10'h038;
    localparam [9:0] REG_TASK_DATA     = 10'h03c;
    localparam [9:0] REG_IDENTIFIER    = 10'h040;
    localparam [9:0] REG_SIM_MC        = 10'h060;
    localparam [9:0] REG_ARG_LEAF_NODE = 10'h050;
    localparam [9:0] REG_ARG_W         = 10'h054;
    localparam [9:0] REG_SEED_BASE     = 10'h080;
    localparam [9:0] REG_WRAPPED_BASE  = 10'h0a0;  /* 48B: 0x0a0..0x0cf */
    localparam [9:0] REG_KWRAP_BASE    = 10'h0e0;
    localparam [9:0] REG_INPUT_BASE    = 10'h100;
    localparam [9:0] REG_OUTPUT_BASE   = 10'h200;

    localparam [31:0] CMD_HASH_ONCE = 32'h00000001;
    localparam [31:0] CMD_HASH_ONCE_RAM = 32'h00000019;
    localparam [31:0] CMD_MSG_Q_COEF = 32'h0000001a;
    localparam [31:0] CMD_CHAIN = 32'h00000002;
    localparam [31:0] CMD_SEED_LOAD = 32'h00000003;
    localparam [31:0] CMD_DERIVE_CHAIN = 32'h00000004;
    localparam [31:0] CMD_DERIVE_RANDOMIZER = 32'h00000005;
    localparam [31:0] CMD_LMOTS_KEYGEN = 32'h00000006;
    localparam [31:0] CMD_LMOTS_SIGN = 32'h00000007;
    localparam [31:0] CMD_LMOTS_VERIFY = 32'h00000008;
    localparam [31:0] CMD_MC_STEP = 32'h00000010;
    localparam [31:0] CMD_MC_LOAD = 32'h00000011;
    localparam [31:0] CMD_WRAP_SEED = 32'h00000012;
    localparam [31:0] CMD_UNWRAP_SEED = 32'h00000013;
    localparam [31:0] CMD_HMAC_KSTATE = 32'h00000014;
    localparam [31:0] CMD_D_INTR_CHAIN = 32'h00000018;
    localparam [31:0] CMD_LMOTS_KEYGEN_LEAF = 32'h0000000e;
    localparam [31:0] CMD_LMOTS_VERIFY_LEAF = 32'h0000000f;
    localparam [31:0] CTRL_START = 32'h00000001;
    localparam [31:0] CTRL_CLEAR = 32'h00000002;

    localparam [31:0] STATUS_BUSY  = 32'h00000001;
    localparam [31:0] STATUS_DONE  = 32'h00000002;
    localparam [31:0] STATUS_ERROR = 32'h00000004;

    localparam [31:0] ERR_UNSUPPORTED_COMMAND = 32'h00000001;
    localparam [31:0] ERR_BUSY                = 32'h00000002;
    localparam [31:0] ERR_INPUT_LENGTH        = 32'h00000003;
    localparam [31:0] ERR_OUTPUT_LENGTH       = 32'h00000004;
    localparam [31:0] ERR_CHAIN_INDEX         = 32'h00000005;
    localparam [31:0] ERR_CHAIN_RANGE         = 32'h00000006;
    localparam [31:0] ERR_CONTROL             = 32'h00000007;
    localparam [31:0] ERR_KEY_HANDLE          = 32'h00000008;
    localparam [31:0] ERR_SEED_NOT_LOADED     = 32'h00000009;
    localparam [31:0] ERR_INSECURE_DISABLED   = 32'h0000000a;

    localparam [3:0] STATE_IDLE          = 4'd0;
    localparam [3:0] STATE_START_CORE    = 4'd1;
    localparam [3:0] STATE_WAIT_CORE     = 4'd2;
    localparam [3:0] STATE_TASK_WRITE    = 4'd3;
    localparam [3:0] STATE_TASK_LOAD     = 4'd4;
    localparam [3:0] STATE_TASK_ENDPOINT = 4'd5;
    localparam [3:0] STATE_TASK_PREFETCH = 4'd6;

    localparam [3:0] STATE_DUAL_WAIT     = 4'd7;
    localparam [3:0] STATE_DUAL_SETUP1   = 4'd8;

    localparam [3:0] STATE_DINTR_PREFETCH    = 4'd9;
    localparam [3:0] STATE_DINTR_LOAD_START  = 4'd10;
    localparam [3:0] STATE_DINTR_LOAD_SIB    = 4'd11;
    localparam [3:0] STATE_DINTR_KICK        = 4'd12;
    localparam [3:0] STATE_DINTR_CORE        = 4'd13;

    localparam [3:0] STATE_HASH_RAM_LOAD     = 4'd14;
    localparam [3:0] STATE_HASH_RAM_KICK     = 4'd15;

    localparam [4:0] STATE_MQC_COEF         = 5'd16;

    localparam [3:0] ACT_START       = 4'd0;
    localparam [3:0] ACT_DONE_SEED   = 4'd1;
    localparam [3:0] ACT_DONE_CHAIN0 = 4'd2;
    localparam [3:0] ACT_DONE_KWRAP  = 4'd3;
    localparam [3:0] ACT_DONE_KSTATE = 4'd4;
    localparam [3:0] ACT_DONE_MC     = 4'd5;
    localparam [3:0] ACT_START_HMAC  = 4'd6;
    localparam [3:0] ACT_START_WRAP  = 4'd7;
    localparam [3:0] ACT_START_STC   = 4'd8;

    reg [31:0] command_r;
    reg [31:0] input_length_r;
    reg [31:0] output_length_r;
    reg [31:0] arg_q_r;
    reg [31:0] arg_i_r;
    reg [31:0] arg_start_r;
    reg [31:0] arg_steps_r;
    reg [31:0] arg_key_r;
    reg [31:0] identifier_words [0:3];

    reg [31:0] local_seed_staging [0:7];
    reg [255:0] local_seed_r;
    reg local_seed_valid_r;
    reg [31:0] error_r;
    reg [31:0] cycle_count_r;
    reg [31:0] input_words [0:31];
    reg [31:0] output_words [0:7];
    (* ram_style = "block" *) reg [31:0] task_words [0:2151];
    reg [31:0] coefficient_words [0:31];
    reg [11:0] task_addr_r;
    reg [31:0] task_ram_read_r;
    reg task_prefetch_pending_r;
    reg [2:0] task_write_word_r;
    reg [255:0] task_digest_r;
    reg [4:0] state_r;
    reg [1:0] block_index_r;
    reg [1:0] block_count_r;
    reg done_r;
    reg error_status_r;
    reg stream_read_r;
    reg stream_rd_pending_r;
    reg busy_error_pending_r;
    reg core_start_r;
    reg engine_start_r;
    reg [255:0] chain_value_r;
    reg [7:0] chain_j_r;
    reg [7:0] chain_steps_left_r;

    /* verilator lint_off UNUSEDSIGNAL */
    reg core_start0_r;
    reg core_start1_r;
    reg core0_done_latched_r;
    reg core1_done_latched_r;
    reg dual_pblc_delay_r;
    reg [255:0] chain_value0_r;
    reg [255:0] chain_value1_r;
    reg [7:0] chain_j0_r;
    reg [7:0] chain_j1_r;
    reg [7:0] chain_steps_left0_r;
    reg [7:0] chain_steps_left1_r;
    reg [255:0] task_digest0_r;
    reg [255:0] task_digest1_r;
    reg [2:0] task_write_word0_r;
    reg [2:0] task_write_word1_r;
    reg dual_write_sel_r;
    reg verify_dual_load_r;
    reg verify_dc_mode_r;
    reg core0_run_r;
    reg core1_run_r;
    /* verilator lint_on UNUSEDSIGNAL */
    localparam [1:0] BATCH_DERIVE = 2'd0;
    localparam [1:0] BATCH_CHAIN  = 2'd1;
    localparam [1:0] BATCH_PBLC   = 2'd2;
    reg [1:0] batch_phase_r;
    reg [8:0] batch_i_r;
    reg [3:0]  arg_w_r;

    reg  [8:0]  w_p;
    reg  [3:0]  w_coef_bits;
    reg  [7:0]  w_max_step;
    wire [8:0]  w_p_last = w_p - 9'd1;
    wire        w_p_even = !w_p[0];
    always @* begin

        case (arg_w_r)
            4'd1: begin w_p = 9'd265; w_coef_bits = 4'd1; w_max_step = 8'd1;   end
            4'd2: begin w_p = 9'd133; w_coef_bits = 4'd2; w_max_step = 8'd3;   end
            4'd8: begin w_p = 9'd34;  w_coef_bits = 4'd8; w_max_step = 8'd255; end
            default: begin w_p = 9'd67; w_coef_bits = 4'd4; w_max_step = 8'd15; end
        endcase
    end

    wire verify_cmd_w = (command_r == CMD_LMOTS_VERIFY ||
                         command_r == CMD_LMOTS_VERIFY_LEAF);
    wire dual_batch_w = (command_r == CMD_LMOTS_KEYGEN ||
                         command_r == CMD_LMOTS_KEYGEN_LEAF ||
                         command_r == CMD_LMOTS_SIGN ||
                         verify_cmd_w);
    wire [8:0] batch_i1_w = batch_i_r + 9'd1;
    wire dual_active_w = !SINGLE_CORE && dual_batch_w && (batch_phase_r != BATCH_PBLC) &&
        (!verify_cmd_w || verify_dc_mode_r) &&
        (command_r != CMD_LMOTS_SIGN || batch_i1_w < w_p);

    reg [7:0] batch_coefficient_w;
    reg [7:0] batch_coefficient1_w;
    always @* begin
        case (w_coef_bits)
            4'd1: begin
                batch_coefficient_w = {7'b0, coefficient_words[batch_i_r[8:5]][batch_i_r[4:0]]};
                batch_coefficient1_w = {7'b0, coefficient_words[batch_i1_w[8:5]][batch_i1_w[4:0]]};
            end
            4'd2: begin
                batch_coefficient_w = {6'b0, coefficient_words[batch_i_r[8:4]][batch_i_r[3:0] * 2 +: 2]};
                batch_coefficient1_w = {6'b0, coefficient_words[batch_i1_w[8:4]][batch_i1_w[3:0] * 2 +: 2]};
            end
            4'd4: begin
                batch_coefficient_w = {4'b0, coefficient_words[batch_i_r[8:3]][batch_i_r[2:0] * 4 +: 4]};
                batch_coefficient1_w = {4'b0, coefficient_words[batch_i1_w[8:3]][batch_i1_w[2:0] * 4 +: 4]};
            end
            default: begin
                batch_coefficient_w = coefficient_words[batch_i_r[8:2]][batch_i_r[1:0] * 8 +: 8];
                batch_coefficient1_w = coefficient_words[batch_i1_w[8:2]][batch_i1_w[1:0] * 8 +: 8];
            end
        endcase
    end
    reg pblc_final_due_r;
    reg keygen_dleaf_r;
    reg [31:0] arg_leaf_node_r;
    reg [7:0] pblc_block_count_r;
    reg [255:0] pblc_state_r;
    reg [511:0] pblc_buffer_r;
    reg [511:0] pblc_block_r;

    reg [255:0] dintr_left_r;
    reg [255:0] dintr_right_r;
    reg [31:0]  dintr_node_r;

    wire [31:0] dintr_block_node_w = dintr_node_r >> 1;
    wire        dintr_swap_w       = dintr_node_r[0];
    reg [4:0]   dintr_layer_r;
    reg [3:0]   dintr_load_word_r;
    wire dintr_cmd_w = command_r == CMD_D_INTR_CHAIN;

    reg [5:0]   hash_ram_block_r;
    reg [5:0]   hash_ram_word_r;
    reg [575:0] hash_ram_window_r;
    wire hash_ram_cmd_w = command_r == CMD_HASH_ONCE_RAM;
    wire [11:0] hash_ram_total_w = input_length_r[11:0];
    wire [11:0] hash_ram_block_base_w = {hash_ram_block_r, 6'b0};
    wire [11:0] hash_ram_rem_w = (hash_ram_block_base_w < hash_ram_total_w)
        ? (hash_ram_total_w - hash_ram_block_base_w) : 12'd0;
    wire [5:0]  hash_ram_blocks_w =
        (hash_ram_total_w + 12'd9 + 12'd63) >> 6;

    wire [11:0] mqc_block_data_w = (hash_ram_block_r == 6'd0) ? 12'd64 :
        ((hash_ram_total_w > hash_ram_block_base_w)
         ? (hash_ram_total_w - hash_ram_block_base_w) : 12'd0);
    wire [5:0]  hash_ram_rd_words_w =
        mqc_cmd_w ?
            ((hash_ram_block_r == 6'd0) ? 6'd18 :
             ((mqc_block_data_w == 12'd0) ? 6'd0 :
              ((mqc_block_data_w + 12'd5 >= 12'd72) ? 6'd18 :
               ((mqc_block_data_w + 12'd5) >> 2))))
        : ((hash_ram_rem_w >= 12'd64) ? 6'd16
            : ((hash_ram_rem_w + 12'd3) >> 2));
    wire [63:0] hash_ram_bitlen_w = {52'b0, hash_ram_total_w} << 3;

    reg [271:0] mqc_q_be_r;
    reg [15:0]  mqc_checksum_r;
    reg [8:0]   mqc_idx_r;
    wire mqc_cmd_w = command_r == CMD_MSG_Q_COEF;
    wire [2:0]   mqc_ls_w = (arg_w_r == 4'd1) ? 3'd7 : (arg_w_r == 4'd2) ? 3'd6 :
                             (arg_w_r == 4'd4) ? 3'd4 : 3'd0;
    wire [8:0]   mqc_u_w = (arg_w_r == 4'd1) ? 9'd256 :
                            (arg_w_r == 4'd2) ? 9'd128 :
                            (arg_w_r == 4'd4) ? 9'd64 : 9'd32;
    wire [7:0]   mqc_mask_w = (w_coef_bits == 4'd8) ? 8'hff :
                              ((8'd1 << w_coef_bits) - 8'd1);
    wire [4:0]   mqc_shift_w = (mqc_idx_r * w_coef_bits) & 5'd31;
    wire [4:0]   mqc_word_idx_w = (mqc_idx_r * w_coef_bits) >> 5;
    wire [8:0]   mqc_cs_j_w = mqc_idx_r - mqc_u_w;

    wire [3:0]   mqc_q_shift_w = 8 - w_coef_bits - ((mqc_idx_r * w_coef_bits) & 7);
    wire [7:0]   mqc_digit_q_w = (mqc_q_be_r[271 - ((mqc_idx_r * w_coef_bits) >> 3) * 8 -: 8] >>
                                  mqc_q_shift_w);

    wire [3:0]   mqc_cs_shift_w = 8 - w_coef_bits - ((mqc_cs_j_w * w_coef_bits) & 7);
    wire [7:0]   mqc_digit_cs_w = (mqc_q_be_r[15 - ((mqc_cs_j_w * w_coef_bits) >> 3) * 8 -: 8] >>
                                   mqc_cs_shift_w);
    wire [11:0]  mqc_base_w = ((input_length_r[11:0] <= 12'd128) &&
                               (w_p != 9'd265)) ? (12'd32 + {w_p, 3'b0}) : 12'd568;
    wire hash_ram_path_w = hash_ram_cmd_w || mqc_cmd_w;
    wire [11:0] hash_ram_read_base_w =
        (mqc_cmd_w ? mqc_base_w : 12'd32) + {hash_ram_block_r, 4'b0};
    reg [7:0] mqc_digit_w;
    always @* begin
        if (mqc_idx_r < mqc_u_w) begin
            mqc_digit_w = mqc_digit_q_w & mqc_mask_w;
        end else begin
            mqc_digit_w = mqc_digit_cs_w & mqc_mask_w;
        end
    end

    reg [511:0] block_w;
    integer byte_index;

    integer global_index;
    integer length_byte_index;
    reg [7:0] selected_byte;
    reg [63:0] bit_length_w;
    reg [63:0] pblc_bitlen_w;
    reg [511:0] pblc_initial_w;
    reg [511:0] pblc_next_block_w;

    wire core0_busy_w;
    wire core0_done_w;
    wire [255:0] core0_digest_w;
    wire core1_busy_w;
    wire core1_done_w;
    wire [255:0] core1_digest_w;
    reg [511:0] block0_latched_r;
    reg [511:0] block1_latched_r;

    wire core_busy_w = dual_active_w ? (core0_busy_w | core1_busy_w) : core0_busy_w;
    wire core_done_w = dual_active_w ? (core0_done_w & core1_done_w) : core0_done_w;
    wire [255:0] core_digest_w = core0_digest_w;
    wire batch_pblc_w = (command_r == CMD_LMOTS_KEYGEN ||
                         command_r == CMD_LMOTS_KEYGEN_LEAF ||
                         verify_cmd_w) &&
                        batch_phase_r == BATCH_PBLC && !keygen_dleaf_r;
    wire [255:0] batch_endpoint_w = state_r == STATE_TASK_ENDPOINT
        ? chain_value_r : core_digest_w;
    wire single_engine_command_w = command_r == CMD_HASH_ONCE ||
        command_r == CMD_CHAIN || command_r == CMD_DERIVE_CHAIN ||
        command_r == CMD_DERIVE_RANDOMIZER;
    wire engine_busy_w;
    wire engine_done_w;
    wire [255:0] engine_digest_w;
    wire [31:0] engine_cycle_count_w;
    wire unused_kec_ext_busy_w;
    wire unused_kec_ext_done_w;
    wire [255:0] unused_kec_ext_digest_w;
    wire unused_kec_ext1_busy_w;
    wire unused_kec_ext1_done_w;
    wire [255:0] unused_kec_ext1_digest_w;
    wire [255:0] engine_chain_input_w = {
        input_words[0][7:0], input_words[0][15:8], input_words[0][23:16], input_words[0][31:24],
        input_words[1][7:0], input_words[1][15:8], input_words[1][23:16], input_words[1][31:24],
        input_words[2][7:0], input_words[2][15:8], input_words[2][23:16], input_words[2][31:24],
        input_words[3][7:0], input_words[3][15:8], input_words[3][23:16], input_words[3][31:24],
        input_words[4][7:0], input_words[4][15:8], input_words[4][23:16], input_words[4][31:24],
        input_words[5][7:0], input_words[5][15:8], input_words[5][23:16], input_words[5][31:24],
        input_words[6][7:0], input_words[6][15:8], input_words[6][23:16], input_words[6][31:24],
        input_words[7][7:0], input_words[7][15:8], input_words[7][23:16], input_words[7][31:24]
    };
    wire [127:0] engine_identifier_flat_w;
    wire [1023:0] engine_input_flat_w;
    genvar engine_flat_index;
    generate
        for (engine_flat_index = 0; engine_flat_index < 4;
             engine_flat_index = engine_flat_index + 1) begin : g_engine_identifier_flat
            assign engine_identifier_flat_w[engine_flat_index * 32 +: 32] =
                identifier_words[engine_flat_index];
        end
        for (engine_flat_index = 0; engine_flat_index < 32;
             engine_flat_index = engine_flat_index + 1) begin : g_engine_input_flat
            assign engine_input_flat_w[engine_flat_index * 32 +: 32] =
                input_words[engine_flat_index];
        end
    endgenerate
    wire physical_busy_w = state_r != STATE_IDLE || engine_busy_w || engine_start_r ||
        sec_busy_w;
    wire wrapper_busy_w = physical_busy_w || ksd_sign_wait_w;
    wire [31:0] status_w = (wrapper_busy_w ? STATUS_BUSY : 32'b0) |
                           (done_r ? STATUS_DONE : 32'b0) |
                           (error_status_r ? STATUS_ERROR : 32'b0);

    wire        cmd_check_valid_w;
    wire [31:0] cmd_check_error_w;
    wire [3:0]  cmd_check_action_w;
    wire cmd_check_raw_valid_w;
    wire [31:0] cmd_check_raw_error_w;
    wire ksd_command_allowed_w, ksd_sign_wait_w, ksd_sign_dispatch_w;
    wire ksd_sign_rejected_w, ksd_sign_cancelled_w, ksd_registered_w;
    wire [3:0] ksd_txn_state_w;
    wire ksd_mmio_hit_w;
    wire [31:0] ksd_mmio_rdata_w;
    wire ksd_sign_request_w = ctrl_start_w &&
        cmd_check_valid_w && command_r == CMD_LMOTS_SIGN;
    wire ksd_output_hidden_w = !INSECURE_TEST_MODE &&
        (ksd_sign_cancelled_w || ksd_trusted_fault ||
         (bus_valid && bus_write && bus_addr == 10'h240 && bus_wdata[1]));
    /* Cancellation keeps the old SIGN RAM/result epoch hidden. A separately
     * accepted public operation may replace all eight OUTPUT words. Track its
     * acceptance/completion, never infer ownership from writable COMMAND or a
     * stale DONE bit. Every command in this whitelist replaces all 32 bytes. */
    wire public_output_command_w = command_r == CMD_HASH_ONCE || command_r == CMD_CHAIN ||
        command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
        command_r == CMD_LMOTS_VERIFY || command_r == CMD_LMOTS_VERIFY_LEAF ||
        command_r == CMD_D_INTR_CHAIN || command_r == CMD_HASH_ONCE_RAM ||
        command_r == CMD_MSG_Q_COEF;
    reg public_output_pending_r, public_output_ready_r;
    wire ksd_abort_write_w = bus_valid && bus_write && bus_addr == 10'h240 && bus_wdata[1];
    wire public_output_visible_w = public_output_ready_r && !ksd_trusted_fault && !ksd_abort_write_w;
    always @(posedge clk) begin
        if (rst) begin
            public_output_pending_r <= 1'b0;
            public_output_ready_r <= 1'b0;
        end else begin
            if (public_output_pending_r && !physical_busy_w) begin
                if (done_r || error_status_r) public_output_pending_r <= 1'b0;
                if (done_r && !error_status_r) public_output_ready_r <= 1'b1;
            end
            if (ctrl_start_w || ksd_sign_dispatch_w) begin
                public_output_pending_r <= ctrl_start_w && public_output_command_w;
                public_output_ready_r <= 1'b0;
            end
            if (ksd_trusted_fault || ksd_abort_write_w) begin
                public_output_pending_r <= 1'b0;
                public_output_ready_r <= 1'b0;
            end
        end
    end
    assign cmd_check_valid_w = cmd_check_raw_valid_w && ksd_command_allowed_w;
    assign cmd_check_error_w = !cmd_check_raw_valid_w ? cmd_check_raw_error_w : 32'd18;
    lms_ksd_sign_adapter #(.HASH_ID(8'd1), .INSECURE_TEST_MODE(INSECURE_TEST_MODE)) u_ksd_adapter (
        .clk(clk), .rst(rst), .ksd_recover_valid(ksd_recover_valid),
        .ksd_recover_record(ksd_recover_record), .ksd_recover_accept(ksd_recover_accept),
        .ksd_ack_valid(ksd_ack_valid), .ksd_ack_record(ksd_ack_record),
        .ksd_ack_accept(ksd_ack_accept), .ksd_persist_valid(ksd_persist_valid),
        .ksd_persist_record(ksd_persist_record), .ksd_trusted_fault(ksd_trusted_fault),
        .bus_valid(bus_valid), .bus_write(bus_write), .bus_addr(bus_addr),
        .bus_wdata(bus_wdata), .ksd_mmio_hit(ksd_mmio_hit_w), .ksd_mmio_rdata(ksd_mmio_rdata_w),
        .seed_valid(seed_valid_merged_w), .engine_quiescent(!physical_busy_w),
        .command(command_r), .arg_q(arg_q_r), .arg_w(arg_w_r), .identifier(sign_identifier_w),
        .mqc_context(sign_coef_context_r), .sign_request(ksd_sign_request_w),
        .sign_complete(command_r == CMD_LMOTS_SIGN && done_r && !physical_busy_w),
        .command_allowed(ksd_command_allowed_w), .sign_wait(ksd_sign_wait_w),
        .sign_dispatch(ksd_sign_dispatch_w), .sign_rejected(ksd_sign_rejected_w),
        .sign_cancelled(ksd_sign_cancelled_w), .registered(ksd_registered_w), .txn_state(ksd_txn_state_w)
    );
    /* MQC provenance only: no persistent reservation is implied here. */
    reg sign_coef_ready_r;
    reg sign_mqc_pending_r;
    reg [127:0] sign_coef_identifier_r;
    reg [31:0] sign_coef_q_r;
    reg [3:0] sign_coef_w_r;
    reg [255:0] sign_coef_context_r;
    wire [127:0] sign_identifier_w = {identifier_words[3], identifier_words[2],
                                     identifier_words[1], identifier_words[0]};
    wire sign_coef_valid_w = sign_coef_ready_r &&
        sign_coef_identifier_r == sign_identifier_w &&
        sign_coef_q_r == arg_q_r && sign_coef_w_r == arg_w_r;
    always @(posedge clk) begin
        if (rst) begin
            sign_coef_ready_r <= 1'b0;
            sign_mqc_pending_r <= 1'b0;
            sign_coef_identifier_r <= 128'b0;
            sign_coef_q_r <= 32'b0;
            sign_coef_w_r <= 4'b0;
            sign_coef_context_r <= 256'b0;
        end else begin
            if (sign_mqc_pending_r && mqc_cmd_w && state_r == STATE_MQC_COEF &&
                mqc_idx_r == w_p - 9'd1 && !busy_error_pending_r && !error_status_r &&
                (arg_w_r == 1 || arg_w_r == 2 || arg_w_r == 4 || arg_w_r == 8)) begin
                sign_coef_ready_r <= 1'b1;
                sign_mqc_pending_r <= 1'b0;
                sign_coef_identifier_r <= sign_identifier_w;
                sign_coef_q_r <= arg_q_r;
                sign_coef_w_r <= arg_w_r;
                sign_coef_context_r <= mqc_q_be_r[271:16];
            end
            if (bus_valid && bus_write) begin
                if ((bus_addr == REG_CONTROL && (bus_wdata & CTRL_START) != 0) ||
                    (bus_addr == REG_TASK_DATA && task_addr_r < 32) ||
                    (bus_addr == REG_ARG_Q && bus_wdata != sign_coef_q_r) ||
                    (bus_addr == REG_ARG_W && bus_wdata != {28'b0, sign_coef_w_r}) ||
                    (bus_addr >= REG_IDENTIFIER && bus_addr < REG_IDENTIFIER + 16 &&
                     bus_addr[1:0] == 0 &&
                     bus_wdata != sign_coef_identifier_r[bus_addr[3:2] * 32 +: 32])) begin
                    sign_coef_ready_r <= 1'b0;
                    sign_mqc_pending_r <= 1'b0;
                end
                if (bus_addr == REG_CONTROL && (bus_wdata & CTRL_START) != 0)
                    sign_mqc_pending_r <= !wrapper_busy_w && bus_wdata == CTRL_START &&
                        mqc_cmd_w && cmd_check_valid_w;
            end
        end
    end

    lms_hash_cmd_check #(
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .HAS_SECURITY(HAS_SECURITY),
        .MAX_ONCE_BYTES(8'd128),
        .HAS_HASH_ONCE_RAM(1'b1),
        .HAS_STATE_COMMIT(1'b1)
    ) u_cmd_check (
        .command(command_r),
        .input_length(input_length_r),
        .output_length(output_length_r),
        .arg_i(arg_i_r),
        .arg_start(arg_start_r),
        .arg_steps(arg_steps_r),
        .arg_key(arg_key_r),
        .seed_valid(seed_valid_merged_w),
        .k_wrap_valid(k_wrap_valid_merged_w),
        .k_state_valid(k_state_valid_merged_w),
        .sign_coef_valid(sign_coef_valid_w),
        .lmots_sign_y_len(w_p * 32),
        .valid(cmd_check_raw_valid_w),
        .error_code(cmd_check_raw_error_w),
        .action(cmd_check_action_w)
    );

    lms_hash_engine #(
        .HASH_TYPE(0),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE)
    ) u_single_engine (
        .clk(clk),
        .rst(rst),
        .start(engine_start_r),
        .command(command_r),
        .input_length(input_length_r[7:0]),
        .arg_q(arg_q_r),
        .arg_i(arg_i_r[15:0]),
        .arg_start(arg_start_r[7:0]),
        .arg_steps(arg_steps_r),
        .identifier_flat(engine_identifier_flat_w),
        .chain_value_in(engine_chain_input_w),
        .seed_flat(engine_seed_flat_w),
        .input_words_flat(engine_input_flat_w),
        .sha_ext_mode(!single_engine_command_w || sec_core_mode_w),
        .sha_ext_start(sec_core_mode_w ? sec_core_start_w :
            (dual_active_w ? (core_start0_r && core0_run_r) : core_start_r)),
        .sha_ext_init(sec_core_mode_w ? sec_core_init_w :
            (batch_pblc_w ? pblc_block_count_r == 0 :
            command_r == CMD_CHAIN || command_r == CMD_DERIVE_CHAIN ||
            command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
            command_r == CMD_LMOTS_SIGN || verify_cmd_w ||
            block_index_r == 0)),
        .sha_ext_state_load(sec_core_mode_w ? sec_core_state_load_w :
            (batch_pblc_w && pblc_block_count_r != 0)),
        .sha_ext_state_in(sec_core_mode_w ? sec_core_state_in_w : pblc_state_r),
        .sha_ext_block(sec_core_mode_w ? block_w :
            (dual_active_w ? block0_latched_r : block_w)),
        .sha_ext_busy(core0_busy_w),
        .sha_ext_done(core0_done_w),
        .sha_ext_digest(core0_digest_w),
        .sha_ext1_start(core_start1_r && core1_run_r),
        .sha_ext1_init(batch_pblc_w ? pblc_block_count_r == 0 :
            command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
            command_r == CMD_LMOTS_SIGN || verify_cmd_w ||
            block_index_r == 0),
        .sha_ext1_state_load(batch_pblc_w && pblc_block_count_r != 0),
        .sha_ext1_state_in(pblc_state_r),
        .sha_ext1_block(block1_latched_r),
        .sha_ext1_busy(core1_busy_w),
        .sha_ext1_done(core1_done_w),
        .sha_ext1_digest(core1_digest_w),
        .kec_ext_mode(1'b0),
        .kec_ext_start(1'b0),
        .kec_ext_init(1'b0),
        .kec_ext_block(1088'b0),
        .kec_ext_busy(unused_kec_ext_busy_w),
        .kec_ext_done(unused_kec_ext_done_w),
        .kec_ext_digest(unused_kec_ext_digest_w),
        .kec_ext1_start(1'b0),
        .kec_ext1_init(1'b0),
        .kec_ext1_block(1088'b0),
        .kec_ext1_busy(unused_kec_ext1_busy_w),
        .kec_ext1_done(unused_kec_ext1_done_w),
        .kec_ext1_digest(unused_kec_ext1_digest_w),
        .busy(engine_busy_w),
        .done(engine_done_w),
        .digest_out(engine_digest_w),
        .cycle_count(engine_cycle_count_w)
    );

    wire        sec_busy_w;
    wire        sec_done_w;
    wire        sec_error_valid_w;
    wire [31:0] sec_error_code_w;
    wire [31:0] sec_cycles_w;
    wire [255:0] sec_result_data_w;
    /* verilator lint_off UNUSEDSIGNAL */
    wire [7:0]   sec_result_wmask_w;
    wire        sec_result_valid_w;
    wire [31:0] sec_mc_next_value_w;
    wire [255:0] sec_seed_data_w;
    wire        sec_seed_valid_w;
    wire        sec_k_wrap_valid_w;
    wire        sec_k_state_valid_w;
    wire        sec_core_start_w;
    wire        sec_core_init_w;
    wire        sec_core_state_load_w;
    wire [255:0] sec_core_state_in_w;
    wire        sec_is_hmac_w;
    wire [1:0]  sec_wrap_phase_w;
    wire [1:0]  sec_block_index_w;
    wire [1:0]  sec_block_count_w;
    /* verilator lint_off UNUSEDSIGNAL */
    wire        sec_stc_w;
    wire [31:0] sec_stc_tx_w;
    /* verilator lint_on UNUSEDSIGNAL */
    wire [255:0] sec_k_wrap_w;
    wire [255:0] sec_k_state_w;
    wire [255:0] sec_wrap_ct_w;
    wire [255:0] sec_wrap_tag_w;
    wire [255:0] sec_wrap_mu_inner_w;   /* R7: mu-inner digest */
    wire [31:0] sec_bus_rdata_w;

    wire sec_bus_hit_w =
        (bus_addr == 10'h060) ||
        (bus_addr >= 10'h080 && bus_addr < 10'h080 + 32) ||
        (bus_addr >= 10'h0a0 && bus_addr < 10'h0a0 + 48) ||
        (bus_addr >= 10'h0e0 && bus_addr < 10'h0e0 + 32);
    wire sec_bus_valid_w = bus_valid && sec_bus_hit_w;
    wire sec_core_mode_w = sec_busy_w;

    /* verilator lint_off UNUSEDSIGNAL */
    wire ctrl_start_w = !wrapper_busy_w && bus_valid && bus_write &&
        bus_addr == REG_CONTROL && bus_wdata == CTRL_START && cmd_check_valid_w;
    wire seed_latch_en_w   = ctrl_start_w && cmd_check_action_w == ACT_DONE_SEED;
    wire kwrap_latch_en_w  = ctrl_start_w && cmd_check_action_w == ACT_DONE_KWRAP;
    wire kstate_latch_en_w = ctrl_start_w && cmd_check_action_w == ACT_DONE_KSTATE;
    wire mc_step_en_w = ctrl_start_w && cmd_check_action_w == ACT_DONE_MC &&
                        command_r == CMD_MC_STEP;
    wire mc_load_en_w = ctrl_start_w && cmd_check_action_w == ACT_DONE_MC &&
                        command_r != CMD_MC_STEP;
    wire wrap_start_w = ctrl_start_w && cmd_check_action_w == ACT_START_WRAP;
    wire wrap_is_unwrap_w = command_r == CMD_UNWRAP_SEED;
    wire hmac_start_w = ctrl_start_w && cmd_check_action_w == ACT_START_HMAC;

    wire stc_start_w = ctrl_start_w && cmd_check_action_w == ACT_START_STC;
    /* verilator lint_on UNUSEDSIGNAL */

    wire [255:0] engine_seed_flat_w;
    wire        seed_valid_merged_w;
    wire        k_wrap_valid_merged_w;
    wire        k_state_valid_merged_w;

    /* verilator lint_off UNUSEDSIGNAL */
    integer sec_latch_index;
    /* verilator lint_on UNUSEDSIGNAL */
    generate
        if (HAS_SECURITY) begin : g_sec_on
            lms_sha256_sec #(
                .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
                .HASH_TYPE(0),
                .SEED_SHARED(1'b0)
            ) u_sec (
                .clk(clk),
                .rst(rst),
                .bus_valid(sec_bus_valid_w),
                .bus_write(bus_write),
                .bus_addr(bus_addr),
                .bus_wdata(bus_wdata),
                .bus_rdata(sec_bus_rdata_w),
                .reg_write_ok(!wrapper_busy_w),
                .seed_latch_en(seed_latch_en_w),
                .seed_share_in(256'b0),
                .kwrap_latch_en(kwrap_latch_en_w),
                .kstate_latch_en(kstate_latch_en_w),
                .mc_step_en(mc_step_en_w),
                .mc_load_en(mc_load_en_w),
                .mc_load_value(arg_q_r),
                .wrap_start(wrap_start_w),
                .wrap_is_unwrap(wrap_is_unwrap_w),
                .hmac_start(hmac_start_w),
                .input_length(stc_start_w ? 8'd49 : input_length_r[7:0]),
                .stc_start(stc_start_w),
                .stc_state(arg_i_r[15:0]),
                .stc_ctr(arg_q_r),
                .stc_aad(arg_key_r[7:0]),
                .busy(sec_busy_w),
                .done(sec_done_w),
                .error_valid(sec_error_valid_w),
                .error_code(sec_error_code_w),
                .cycles(sec_cycles_w),
                .result_data(sec_result_data_w),
                .result_wmask(sec_result_wmask_w),
                .result_valid(sec_result_valid_w),
                .mc_next_value(sec_mc_next_value_w),
                .seed_data(sec_seed_data_w),
                .seed_valid(sec_seed_valid_w),
                .k_wrap_valid(sec_k_wrap_valid_w),
                .k_state_valid(sec_k_state_valid_w),
                .core_start(sec_core_start_w),
                .core_init(sec_core_init_w),
                .core_state_load(sec_core_state_load_w),
                .core_state_in(sec_core_state_in_w),
                .sec_is_hmac(sec_is_hmac_w),
                .wrap_phase(sec_wrap_phase_w),
                .block_index(sec_block_index_w),
                .block_count(sec_block_count_w),
                .stc_active(sec_stc_w),
                .stc_tx(sec_stc_tx_w),
                .k_wrap(sec_k_wrap_w),
                .k_state(sec_k_state_w),
                .wrap_ct(sec_wrap_ct_w),
                .wrap_tag(sec_wrap_tag_w),
        .wrap_mu_inner(sec_wrap_mu_inner_w),
                .core_busy(core0_busy_w),
                .core_done(core0_done_w),
                .core_digest(core0_digest_w)
            );
            assign engine_seed_flat_w = sec_seed_data_w;
            assign seed_valid_merged_w = sec_seed_valid_w;
            assign k_wrap_valid_merged_w = sec_k_wrap_valid_w;
            assign k_state_valid_merged_w = sec_k_state_valid_w;
        end else begin : g_sec_off

            always @(posedge clk) begin
                if (seed_latch_en_w) begin
                    for (sec_latch_index = 0; sec_latch_index < 8;
                         sec_latch_index = sec_latch_index + 1) begin
                        local_seed_r[255 - sec_latch_index * 32 -: 32] <= {
                            local_seed_staging[sec_latch_index][7:0],
                            local_seed_staging[sec_latch_index][15:8],
                            local_seed_staging[sec_latch_index][23:16],
                            local_seed_staging[sec_latch_index][31:24]
                        };
                        local_seed_staging[sec_latch_index] <= 32'b0;
                    end
                    local_seed_valid_r <= 1'b1;
                end
                if (rst) begin
                    local_seed_r <= 256'b0;
                    local_seed_valid_r <= 1'b0;
                    for (sec_latch_index = 0; sec_latch_index < 8;
                         sec_latch_index = sec_latch_index + 1) begin
                        local_seed_staging[sec_latch_index] <= 32'b0;
                    end
                end
            end
            assign sec_busy_w = 1'b0;
            assign sec_done_w = 1'b0;
            assign sec_error_valid_w = 1'b0;
            assign sec_error_code_w = 32'b0;
            assign sec_cycles_w = 32'b0;
            assign sec_result_data_w = 256'b0;
            assign sec_result_wmask_w = 8'b0;
            assign sec_result_valid_w = 1'b0;
            assign sec_mc_next_value_w = 32'b0;
            assign sec_seed_data_w = 256'b0;
            assign sec_seed_valid_w = 1'b0;
            assign sec_k_wrap_valid_w = 1'b0;
            assign sec_k_state_valid_w = 1'b0;
            assign sec_core_start_w = 1'b0;
            assign sec_core_init_w = 1'b0;
            assign sec_core_state_load_w = 1'b0;
            assign sec_core_state_in_w = 256'b0;
            assign sec_is_hmac_w = 1'b0;
            assign sec_wrap_phase_w = 2'b0;
            assign sec_block_index_w = 2'b0;
            assign sec_block_count_w = 2'b0;
            assign sec_stc_w = 1'b0;
            assign sec_stc_tx_w = 32'b0;
            assign sec_k_wrap_w = 256'b0;
            assign sec_k_state_w = 256'b0;
            assign sec_wrap_ct_w = 256'b0;
            assign sec_wrap_tag_w = 256'b0;
    assign sec_wrap_mu_inner_w = 256'b0;
            assign sec_bus_rdata_w = 32'b0;
            assign engine_seed_flat_w = local_seed_r;
            assign seed_valid_merged_w = local_seed_valid_r;
            assign k_wrap_valid_merged_w = 1'b0;
            assign k_state_valid_merged_w = 1'b0;
        end
    endgenerate

    wire [511:0] sec_body_be_w;
    genvar sec_bd_i;
    generate
        for (sec_bd_i = 0; sec_bd_i < 4; sec_bd_i = sec_bd_i + 1) begin : g_stc_magic
            assign sec_body_be_w[sec_bd_i * 8 +: 8] =
                (sec_bd_i == 0) ? 8'h4c :
                (sec_bd_i == 1) ? 8'h4d :
                (sec_bd_i == 2) ? 8'h53 : 8'h53;   /* "LMSS" */
        end
        for (sec_bd_i = 4; sec_bd_i < 6; sec_bd_i = sec_bd_i + 1) begin : g_stc_state
            assign sec_body_be_w[sec_bd_i * 8 +: 8] =
                (sec_bd_i == 4) ? arg_i_r[15:8] : arg_i_r[7:0];   /* state BE */
        end
        for (sec_bd_i = 6; sec_bd_i < 10; sec_bd_i = sec_bd_i + 1) begin : g_stc_ctr
            assign sec_body_be_w[sec_bd_i * 8 +: 8] =
                arg_q_r[(9 - sec_bd_i) * 8 +: 8];   /* ctr BE */
        end
        for (sec_bd_i = 10; sec_bd_i < 14; sec_bd_i = sec_bd_i + 1) begin : g_stc_tx
            assign sec_body_be_w[sec_bd_i * 8 +: 8] =
                sec_stc_tx_w[(13 - sec_bd_i) * 8 +: 8];   /* tx BE */
        end
        for (sec_bd_i = 14; sec_bd_i < 48; sec_bd_i = sec_bd_i + 1) begin : g_stc_rsv
            assign sec_body_be_w[sec_bd_i * 8 +: 8] = 8'b0;   /* reserved */
        end
        for (sec_bd_i = 48; sec_bd_i < 49; sec_bd_i = sec_bd_i + 1) begin : g_stc_aad
            assign sec_body_be_w[sec_bd_i * 8 +: 8] = arg_key_r[7:0];   /* aad=slot_id */
        end
        for (sec_bd_i = 49; sec_bd_i < 64; sec_bd_i = sec_bd_i + 1) begin : g_stc_z
            assign sec_body_be_w[sec_bd_i * 8 +: 8] = 8'b0;
        end
    endgenerate

    wire [7:0] sec_inner_len_w = sec_stc_w ? 8'd49 : input_length_r[7:0];

    reg task_ram_enable_w;
    reg task_ram_write_w;
    reg [11:0] task_ram_addr_w;
    reg [31:0] task_ram_wdata_w;

    always @* begin
        task_ram_enable_w = 1'b0;
        task_ram_write_w = 1'b0;
        task_ram_addr_w = 12'b0;
        task_ram_wdata_w = 32'b0;

        if (stream_wr_en && !wrapper_busy_w && stream_wr_addr < 2152) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            task_ram_addr_w = stream_wr_addr;
            task_ram_wdata_w = stream_wr_data;
        end else if (stream_rd_en && !wrapper_busy_w && stream_rd_addr < 2152) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = stream_rd_addr;
        end else if (!wrapper_busy_w && bus_valid && bus_write &&
            bus_addr == REG_TASK_DATA && task_addr_r >= 32) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            task_ram_addr_w = task_addr_r;
            task_ram_wdata_w = bus_wdata;
        end else if (task_prefetch_pending_r) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = task_addr_r;
        end else if (state_r == STATE_TASK_WRITE) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            if (dual_batch_w && dual_write_sel_r &&
                batch_phase_r != BATCH_CHAIN) begin

                task_ram_addr_w = 12'd32 + {batch_i1_w, 3'b0} +
                    {9'b0, task_write_word1_r};
                task_ram_wdata_w = {
                    task_digest1_r[255 - (task_write_word1_r * 32 + 24) -: 8],
                    task_digest1_r[255 - (task_write_word1_r * 32 + 16) -: 8],
                    task_digest1_r[255 - (task_write_word1_r * 32 + 8) -: 8],
                    task_digest1_r[255 - task_write_word1_r * 32 -: 8]
                };
            end else if (dual_batch_w &&
                batch_phase_r != BATCH_CHAIN) begin

                task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0} +
                    {9'b0, task_write_word0_r};
                task_ram_wdata_w = {
                    task_digest0_r[255 - (task_write_word0_r * 32 + 24) -: 8],
                    task_digest0_r[255 - (task_write_word0_r * 32 + 16) -: 8],
                    task_digest0_r[255 - (task_write_word0_r * 32 + 8) -: 8],
                    task_digest0_r[255 - task_write_word0_r * 32 -: 8]
                };
            end else begin
                task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0} +
                    {9'b0, task_write_word_r};
                task_ram_wdata_w = {
                    task_digest_r[255 - (task_write_word_r * 32 + 24) -: 8],
                    task_digest_r[255 - (task_write_word_r * 32 + 16) -: 8],
                    task_digest_r[255 - (task_write_word_r * 32 + 8) -: 8],
                    task_digest_r[255 - task_write_word_r * 32 -: 8]
                };
            end
        end else if (state_r == STATE_TASK_PREFETCH && hash_ram_path_w) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = hash_ram_read_base_w;
        end else if (state_r == STATE_HASH_RAM_LOAD) begin

            task_ram_enable_w = 1'b1;
            if (hash_ram_word_r + 1'b1 < hash_ram_rd_words_w) begin
                task_ram_addr_w = hash_ram_read_base_w + {5'b0, hash_ram_word_r} + 12'd1;
            end else begin
                task_ram_addr_w = hash_ram_read_base_w + {5'b0, hash_ram_word_r};
            end
        end else if (state_r == STATE_TASK_PREFETCH) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0};
        end else if (state_r == STATE_TASK_LOAD) begin
            task_ram_enable_w = 1'b1;
            if (verify_dual_load_r) begin
                task_ram_addr_w = 12'd32 + {batch_i1_w, 3'b0} +
                    (task_write_word_r == 3'd7
                        ? 12'd7 : {9'b0, task_write_word_r} + 12'd1);
            end else if (!verify_dual_load_r && task_write_word_r == 3'd7 &&
                         dual_batch_w && verify_cmd_w &&
                         batch_i1_w < w_p) begin

                task_ram_addr_w = 12'd32 + {batch_i1_w, 3'b0};
            end else begin
                task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0} +
                    (task_write_word_r == 3'd7
                        ? 12'd7 : {9'b0, task_write_word_r} + 12'd1);
            end
        end else if (state_r == STATE_DINTR_PREFETCH) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd32;
        end else if (state_r == STATE_DINTR_LOAD_START) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = (dintr_load_word_r == 4'd7) ? 12'd40 :
                               (12'd33 + {8'b0, dintr_load_word_r});
        end else if (state_r == STATE_DINTR_LOAD_SIB) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd40 + {dintr_layer_r, 3'b0} +
                (dintr_load_word_r == 4'd7 ? 4'd7 : {1'b0, dintr_load_word_r} + 4'd1);
        end else if (state_r == STATE_DINTR_CORE ||
                     (state_r == STATE_WAIT_CORE && dintr_cmd_w)) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd40 + {dintr_layer_r + 1'b1, 3'b0};
        end else if (!wrapper_busy_w && done_r && bus_valid &&
                     !bus_write && bus_addr == REG_TASK_DATA &&
                     task_addr_r >= 32 && !stream_read_r) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = task_addr_r;
        end
    end

    always @(posedge clk) begin
        if (task_ram_enable_w) begin
            if (task_ram_write_w) begin
                task_words[task_ram_addr_w] <= task_ram_wdata_w;
            end else begin
                task_ram_read_r <= task_words[task_ram_addr_w];
            end
        end
    end

    always @(posedge clk) begin
        if (rst) begin
            stream_rd_pending_r <= 1'b0;
        end else if (stream_rd_en && !wrapper_busy_w) begin
            stream_rd_pending_r <= 1'b1;
        end else begin
            stream_rd_pending_r <= 1'b0;
        end
    end

    assign stream_busy     = wrapper_busy_w;
    assign stream_rd_valid = stream_rd_pending_r && !ksd_output_hidden_w;
    assign stream_rd_data  = stream_rd_pending_r && !ksd_output_hidden_w ? task_ram_read_r : 32'b0;

    always @* begin

        if (sec_is_hmac_w && sec_wrap_phase_w == 2'd1) begin
            bit_length_w = {29'b0, (32'd64 + {24'b0, sec_inner_len_w})} << 3;
        end else if (sec_is_hmac_w) begin
            bit_length_w = 64'd96 << 3;
        end else begin
            bit_length_w = {29'b0, input_length_r[31:0]} << 3;
        end
        block_w = 512'b0;
        selected_byte = 8'b0;
        global_index = 0;
        length_byte_index = 0;
        pblc_initial_w = 512'b0;
        pblc_next_block_w = pblc_buffer_r;

        pblc_bitlen_w = (64'd22 + ({55'b0, w_p} << 5)) << 3;
        for (byte_index = 0; byte_index < 16; byte_index = byte_index + 1) begin
            pblc_initial_w[511 - byte_index * 8 -: 8] =
                identifier_words[byte_index / 4][(byte_index % 4) * 8 +: 8];
        end
        pblc_initial_w[511 - 16 * 8 -: 8] = arg_q_r[31:24];
        pblc_initial_w[511 - 17 * 8 -: 8] = arg_q_r[23:16];
        pblc_initial_w[511 - 18 * 8 -: 8] = arg_q_r[15:8];
        pblc_initial_w[511 - 19 * 8 -: 8] = arg_q_r[7:0];
        pblc_initial_w[511 - 20 * 8 -: 8] = 8'h80;
        pblc_initial_w[511 - 21 * 8 -: 8] = 8'h80;
        if (pblc_final_due_r) begin

            pblc_next_block_w = 512'b0;
            for (byte_index = 0; byte_index < 22; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - byte_index * 8 -: 8] =
                    pblc_buffer_r[511 - byte_index * 8 -: 8];
            end
            pblc_next_block_w[511 - 22 * 8 -: 8] = 8'h80;
            for (byte_index = 0; byte_index < 8; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (56 + byte_index) * 8 -: 8] =
                    pblc_bitlen_w[(7 - byte_index) * 8 +: 8];
            end
        end else if (dual_batch_w && batch_i_r != w_p_last &&
            (!verify_cmd_w || verify_dc_mode_r)) begin
            for (byte_index = 0; byte_index < 10; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (54 + byte_index) * 8 -: 8] =
                    core1_digest_w[255 - byte_index * 8 -: 8];
            end
        end else if (batch_i_r[0]) begin
            for (byte_index = 0; byte_index < 10; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (54 + byte_index) * 8 -: 8] =
                    batch_endpoint_w[255 - byte_index * 8 -: 8];
            end
        end else if (batch_i_r == w_p_last) begin
            pblc_next_block_w = 512'b0;
            for (byte_index = 0; byte_index < 22; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - byte_index * 8 -: 8] =
                    pblc_buffer_r[511 - byte_index * 8 -: 8];
            end
            for (byte_index = 0; byte_index < 32; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (22 + byte_index) * 8 -: 8] =
                    batch_endpoint_w[255 - byte_index * 8 -: 8];
            end
            pblc_next_block_w[511 - 54 * 8 -: 8] = 8'h80;
            for (byte_index = 0; byte_index < 8; byte_index = byte_index + 1) begin
                pblc_next_block_w[511 - (56 + byte_index) * 8 -: 8] =
                    pblc_bitlen_w[(7 - byte_index) * 8 +: 8];
            end
        end
        for (byte_index = 0; byte_index < 64; byte_index = byte_index + 1) begin
            if (dintr_cmd_w) begin
                                 if (block_index_r == 2'd0) begin
                    if (byte_index < 16) begin
                        selected_byte = identifier_words[byte_index / 4][(byte_index % 4) * 8 +: 8];
                    end else if (byte_index < 20) begin
                        selected_byte = dintr_block_node_w[(19 - byte_index) * 8 +: 8];
                    end else if (byte_index < 22) begin
                        selected_byte = 8'h83;
                    end else if (byte_index < 54) begin
                        selected_byte = dintr_swap_w ?
                            dintr_right_r[255 - (byte_index - 22) * 8 -: 8] :
                            dintr_left_r[255 - (byte_index - 22) * 8 -: 8];
                    end else begin
                        selected_byte = dintr_swap_w ?
                            dintr_left_r[255 - (byte_index - 54) * 8 -: 8] :
                            dintr_right_r[255 - (byte_index - 54) * 8 -: 8];
                    end
                end else begin
                    if (byte_index < 22) begin
                        selected_byte = dintr_swap_w ?
                            dintr_left_r[255 - (10 + byte_index) * 8 -: 8] :
                            dintr_right_r[255 - (10 + byte_index) * 8 -: 8];
                    end else if (byte_index == 22) begin
                        selected_byte = 8'h80;
                    end else if (byte_index == 62) begin
                        selected_byte = 8'h02;
                    end else if (byte_index == 63) begin
                        selected_byte = 8'hb0;
                    end else begin
                        selected_byte = 8'h00;
                    end
                end
            end else if (hash_ram_cmd_w) begin

                global_index = hash_ram_block_base_w + byte_index;
                if (global_index < hash_ram_total_w) begin
                    selected_byte = hash_ram_window_r[575 - byte_index * 8 -: 8];
                end else if (global_index == hash_ram_total_w) begin
                    selected_byte = 8'h80;
                end else if (global_index >= hash_ram_blocks_w * 64 - 8) begin
                    length_byte_index = global_index - (hash_ram_blocks_w * 64 - 8);
                    selected_byte = hash_ram_bitlen_w[(7 - length_byte_index) * 8 +: 8];
                end else begin
                    selected_byte = 8'h00;
                end
            end else if (mqc_cmd_w) begin

                global_index = hash_ram_block_base_w + byte_index;
                if (global_index < hash_ram_total_w) begin
                    if (hash_ram_block_r == 6'd0 && byte_index < 54) begin
                        selected_byte = hash_ram_window_r[575 - byte_index * 8 -: 8];
                    end else begin
                        selected_byte = hash_ram_window_r[575 - (byte_index + 2) * 8 -: 8];
                    end
                end else if (global_index == hash_ram_total_w) begin
                    selected_byte = 8'h80;
                end else if (global_index >= hash_ram_blocks_w * 64 - 8) begin
                    length_byte_index = global_index - (hash_ram_blocks_w * 64 - 8);
                    selected_byte = hash_ram_bitlen_w[(7 - length_byte_index) * 8 +: 8];
                end else begin
                    selected_byte = 8'h00;
                end
            end else if (((command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
                  command_r == CMD_LMOTS_SIGN || verify_cmd_w) &&
                 batch_phase_r == BATCH_CHAIN)) begin
                if (byte_index < 16) begin
                    selected_byte = identifier_words[byte_index / 4][(byte_index % 4) * 8 +: 8];
                end else if (byte_index < 20) begin
                    selected_byte = arg_q_r[(19 - byte_index) * 8 +: 8];
                end else if (byte_index < 22) begin
                    selected_byte = arg_i_r[(21 - byte_index) * 8 +: 8];
                end else if (byte_index == 22) begin
                    selected_byte = chain_j_r;
                end else if (byte_index < 55) begin
                    selected_byte = chain_value_r[255 - (byte_index - 23) * 8 -: 8];
                end else if (byte_index == 55) begin
                    selected_byte = 8'h80;
                end else if (byte_index == 62) begin
                    selected_byte = 8'h01;
                end else if (byte_index == 63) begin
                    selected_byte = 8'hb8;
                end else begin
                    selected_byte = 8'h00;
                end
                        end else if (((command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
                           command_r == CMD_LMOTS_SIGN) &&
                          batch_phase_r == BATCH_DERIVE)) begin
                if (byte_index < 16) begin
                    selected_byte = identifier_words[byte_index / 4][(byte_index % 4) * 8 +: 8];
                end else if (byte_index < 20) begin
                    selected_byte = arg_q_r[(19 - byte_index) * 8 +: 8];
                end else if (byte_index < 22) begin
                    selected_byte = arg_i_r[(21 - byte_index) * 8 +: 8];
                end else if (byte_index == 22) begin
                    selected_byte = 8'hff;
                end else if (byte_index < 55) begin
                    selected_byte = engine_seed_flat_w[255 - (byte_index - 23) * 8 -: 8];
                end else if (byte_index == 55) begin
                    selected_byte = 8'h80;
                end else if (byte_index == 62) begin
                    selected_byte = 8'h01;
                end else if (byte_index == 63) begin
                    selected_byte = 8'hb8;
                end else begin
                    selected_byte = 8'h00;
                end
            end else if (HAS_SECURITY && sec_core_mode_w && sec_is_hmac_w) begin

                global_index = sec_block_index_w * 64 + byte_index;
                if (sec_wrap_phase_w == 2'd1) begin
                    if (global_index < 64) begin
                        selected_byte = (global_index < 32)
                            ? (sec_k_state_w[255 - global_index * 8 -: 8] ^ 8'h36)
                            : 8'h36;
                    end else if (global_index < 64 + {24'b0, sec_inner_len_w}) begin
                        if (sec_stc_w) begin

                            selected_byte = sec_body_be_w[(global_index - 64) * 8 +: 8];
                        end else begin
                            selected_byte = input_words[(global_index - 64) / 4]
                                                     [((global_index - 64) % 4) * 8 +: 8];
                        end
                    end else if (global_index == 64 + {24'b0, sec_inner_len_w}) begin
                        selected_byte = 8'h80;
                    end else if (global_index >= sec_block_count_w * 64 - 8) begin
                        length_byte_index = global_index - (sec_block_count_w * 64 - 8);
                        selected_byte = bit_length_w[(7 - length_byte_index) * 8 +: 8];
                    end else begin
                        selected_byte = 8'h00;
                    end
                end else begin
                    if (global_index < 64) begin
                        selected_byte = (global_index < 32)
                            ? (sec_k_state_w[255 - global_index * 8 -: 8] ^ 8'h5c)
                            : 8'h5c;
                    end else if (global_index < 96) begin
                        selected_byte = sec_wrap_tag_w[255 - (global_index - 64) * 8 -: 8];
                    end else if (global_index == 96) begin
                        selected_byte = 8'h80;
                    end else if (global_index >= sec_block_count_w * 64 - 8) begin
                        length_byte_index = global_index - (sec_block_count_w * 64 - 8);
                        selected_byte = bit_length_w[(7 - length_byte_index) * 8 +: 8];
                    end else begin
                        selected_byte = 8'h00;
                    end
                end
            end else if (HAS_SECURITY && sec_core_mode_w && !sec_is_hmac_w) begin

                if (sec_wrap_phase_w == 2'd0) begin
                    if (sec_block_index_w == 2'd0) begin
                        selected_byte = (byte_index < 32)
                            ? (sec_k_wrap_w[255 - byte_index * 8 -: 8] ^ 8'h36)
                            : 8'h36;
                    end else begin
                        case (byte_index)
                            8'd0:  selected_byte = 8'h4c;  /* L */
                            8'd1:  selected_byte = 8'h4d;  /* M */
                            8'd2:  selected_byte = 8'h53;  /* S */
                            8'd3:  selected_byte = 8'h57;  /* W */
                            8'd4:  selected_byte = 8'h52;  /* R */
                            8'd5:  selected_byte = 8'h41;  /* A */
                            8'd6:  selected_byte = 8'h50;  /* P */
                            8'd7:  selected_byte = 8'h2d;  /* - */
                            8'd8:  selected_byte = 8'h45;  /* E */
                            8'd9:  selected_byte = 8'h4e;  /* N */
                            8'd10: selected_byte = 8'h43;  /* C */
                            8'd11: selected_byte = 8'h80;
                            8'd62: selected_byte = 8'h02;  /* 75*8 = 0x0258 */
                            8'd63: selected_byte = 8'h58;
                            default: selected_byte = 8'h00;
                        endcase
                    end
                end else if (sec_wrap_phase_w == 2'd1) begin
                    if (sec_block_index_w == 2'd0) begin
                        selected_byte = (byte_index < 32)
                            ? (sec_k_wrap_w[255 - byte_index * 8 -: 8] ^ 8'h5c)
                            : 8'h5c;
                    end else begin
                        if (byte_index < 32) begin
                            selected_byte = sec_wrap_mu_inner_w[255 - byte_index * 8 -: 8];
                        end else if (byte_index == 32) begin
                            selected_byte = 8'h80;
                        end else if (byte_index == 62) begin
                            selected_byte = 8'h03;
                        end else if (byte_index == 63) begin
                            selected_byte = 8'h00;
                        end else begin
                            selected_byte = 8'h00;
                        end
                    end
                end else if (sec_wrap_phase_w == 2'd2) begin
                    if (sec_block_index_w == 2'd0) begin
                        selected_byte = (byte_index < 32)
                            ? (sec_k_wrap_w[255 - byte_index * 8 -: 8] ^ 8'h36)
                            : 8'h36;
                    end else begin
                        if (byte_index < 32) begin
                            selected_byte = sec_wrap_ct_w[255 - byte_index * 8 -: 8];
                        end else if (byte_index == 32) begin
                            selected_byte = 8'h80;
                        end else if (byte_index == 62) begin
                            selected_byte = 8'h03;
                        end else if (byte_index == 63) begin
                            selected_byte = 8'h00;
                        end else begin
                            selected_byte = 8'h00;
                        end
                    end
                end else begin
                    if (sec_block_index_w == 2'd0) begin
                        selected_byte = (byte_index < 32)
                            ? (sec_k_wrap_w[255 - byte_index * 8 -: 8] ^ 8'h5c)
                            : 8'h5c;
                    end else begin
                        if (byte_index < 32) begin
                            selected_byte = sec_wrap_tag_w[255 - byte_index * 8 -: 8];
                        end else if (byte_index == 32) begin
                            selected_byte = 8'h80;
                        end else if (byte_index == 62) begin
                            selected_byte = 8'h03;
                        end else if (byte_index == 63) begin
                            selected_byte = 8'h00;
                        end else begin
                            selected_byte = 8'h00;
                        end
                    end
                end
            end else if (command_r == CMD_LMOTS_KEYGEN ||
                         (command_r == CMD_LMOTS_KEYGEN_LEAF && !keygen_dleaf_r) ||
                         (verify_cmd_w && !keygen_dleaf_r)) begin
                selected_byte = pblc_block_r[511 - byte_index * 8 -: 8];
            end else if (keygen_dleaf_r) begin

                global_index = block_index_r * 64 + byte_index;
                if (global_index < 54) begin
                    selected_byte = input_words[global_index / 4][(global_index % 4) * 8 +: 8];
                end else if (global_index == 54) begin
                    selected_byte = 8'h80;
                end else if (global_index >= 64 - 8) begin
                    length_byte_index = global_index - (64 - 8);
                    if (length_byte_index == 6) selected_byte = 8'h01;
                    else if (length_byte_index == 7) selected_byte = 8'hb0;
                    else selected_byte = 8'h00;
                end else begin
                    selected_byte = 8'h00;
                end
            end else begin
                global_index = block_index_r * 64 + byte_index;
                if (global_index < input_length_r) begin
                    selected_byte = input_words[global_index / 4][(global_index % 4) * 8 +: 8];
                end else if (global_index == input_length_r) begin
                    selected_byte = 8'h80;
                end else if (global_index >= block_count_r * 64 - 8) begin
                    length_byte_index = global_index - (block_count_r * 64 - 8);
                    selected_byte = bit_length_w[(7 - length_byte_index) * 8 +: 8];
                end else begin
                    selected_byte = 8'h00;
                end
            end
            block_w[511 - byte_index * 8 -: 8] = selected_byte;
        end
    end

    integer output_index;
    integer bj;
    always @(posedge clk) begin
        core_start_r <= 1'b0;
        core_start0_r <= 1'b0;
        core_start1_r <= 1'b0;
        engine_start_r <= 1'b0;
        task_prefetch_pending_r <= 1'b0;

        if (sec_done_w) begin

            cycle_count_r <= sec_cycles_w;
            if (busy_error_pending_r) begin
                done_r <= 1'b0;
                error_status_r <= 1'b1;
                error_r <= ERR_BUSY;
            end else if (sec_error_valid_w) begin
                done_r <= 1'b0;
                error_status_r <= 1'b1;
                error_r <= sec_error_code_w;
            end else begin
                done_r <= 1'b1;
                error_status_r <= 1'b0;
                error_r <= 32'b0;
            end
            if (sec_result_valid_w) begin
                if (sec_stc_w) begin

                    output_words[0] <= sec_stc_tx_w;
                    output_words[1] <= sec_result_data_w[255:224];
                    output_words[2] <= sec_result_data_w[223:192];
                    output_words[3] <= sec_result_data_w[191:160];
                    output_words[4] <= sec_result_data_w[159:128];
                    output_words[5] <= 32'b0;
                    output_words[6] <= 32'b0;
                    output_words[7] <= 32'b0;
                end else begin
                    for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                        output_words[output_index] <=
                            sec_result_data_w[255 - output_index * 32 -: 32];
                    end
                end
            end
        end

        if (engine_done_w) begin
            cycle_count_r <= engine_cycle_count_w;
            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                output_words[output_index] <= {
                    engine_digest_w[255 - (output_index * 32 + 24) -: 8],
                    engine_digest_w[255 - (output_index * 32 + 16) -: 8],
                    engine_digest_w[255 - (output_index * 32 + 8) -: 8],
                    engine_digest_w[255 - output_index * 32 -: 8]
                };
            end
            if (busy_error_pending_r) begin
                done_r <= 1'b0;
                error_status_r <= 1'b1;
                error_r <= ERR_BUSY;
            end else begin
                done_r <= 1'b1;
                error_status_r <= 1'b0;
                error_r <= 32'b0;
            end
        end

        if ((bus_valid && bus_write) || ksd_sign_dispatch_w) begin
            if (bus_addr == REG_CONTROL || ksd_sign_dispatch_w) begin
                if (wrapper_busy_w && !ksd_sign_dispatch_w) begin
                    if ((bus_wdata & CTRL_START) != 0) begin
                        busy_error_pending_r <= 1'b1;
                    end
                end else if (bus_wdata == CTRL_CLEAR && !ksd_sign_dispatch_w) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b0;
                    error_r <= 32'b0;
                    cycle_count_r <= 32'b0;
                    busy_error_pending_r <= 1'b0;
                end else if (bus_wdata == CTRL_START || ksd_sign_dispatch_w) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b0;
                    error_r <= 32'b0;
                    cycle_count_r <= 32'd1;
                    busy_error_pending_r <= 1'b0;

                    if (!ksd_sign_dispatch_w && !cmd_check_valid_w) begin
                        error_status_r <= 1'b1;
                        error_r <= cmd_check_error_w;
                    end else if (!INSECURE_TEST_MODE && command_r == CMD_LMOTS_SIGN && !ksd_sign_dispatch_w) begin
                        /* Request only: the controller dispatch starts work. */
                    end else begin
                        case (cmd_check_action_w)
                            ACT_START: begin
                                block_index_r <= 2'd0;
                                keygen_dleaf_r <= 1'b0;
                                if (dintr_cmd_w) begin

                                    dintr_left_r <= 256'b0;
                                    dintr_right_r <= 256'b0;
                                    dintr_node_r <= arg_leaf_node_r;
                                    dintr_layer_r <= 5'd0;
                                    dintr_load_word_r <= 4'd0;
                                    block_count_r <= 2'd2;
                                    state_r <= STATE_DINTR_PREFETCH;
                                end else if (hash_ram_path_w) begin

                                    hash_ram_block_r <= 6'd0;
                                    hash_ram_word_r <= 6'd0;
                                    hash_ram_window_r <= 576'b0;
                                    if (mqc_cmd_w) begin
                                        mqc_q_be_r <= 272'b0;
                                        mqc_checksum_r <= 16'd0;
                                        mqc_idx_r <= 9'd0;
                                    end
                                    state_r <= STATE_TASK_PREFETCH;
                                end else if (single_engine_command_w) begin
                                    engine_start_r <= 1'b1;
                                end else if (command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
                                    command_r == CMD_LMOTS_SIGN) begin
                                    batch_phase_r <= BATCH_DERIVE;
                                    batch_i_r <= 9'd0;
                                    arg_i_r <= 32'd0;
                                    pblc_block_count_r <= 8'd0;
                                    pblc_state_r <= 256'b0;
                                    pblc_buffer_r <= pblc_initial_w;
                                    block_count_r <= 2'd1;
                                end else if (verify_cmd_w) begin
                                    batch_phase_r <= BATCH_CHAIN;
                                    batch_i_r <= 9'd0;
                                    arg_i_r <= 32'd0;
                                    task_write_word_r <= 3'd0;
                                    pblc_block_count_r <= 8'd0;
                                    pblc_state_r <= 256'b0;
                                    pblc_buffer_r <= pblc_initial_w;
                                    block_count_r <= 2'd1;
                                    state_r <= STATE_TASK_PREFETCH;
                                end
                                if (!single_engine_command_w &&
                                    !verify_cmd_w && !dintr_cmd_w && !hash_ram_path_w) begin
                                    state_r <= STATE_START_CORE;
                                end
                            end
                            ACT_DONE_SEED: begin

                                done_r <= 1'b1;
                            end
                            ACT_DONE_CHAIN0: begin
                                for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                    output_words[output_index] <= input_words[output_index];
                                end
                                done_r <= 1'b1;
                            end
                            ACT_DONE_KWRAP: begin

                                done_r <= 1'b1;
                            end
                            ACT_DONE_KSTATE: begin

                                done_r <= 1'b1;
                            end
                            ACT_DONE_MC: begin

                                output_words[0] <= sec_mc_next_value_w;
                                done_r <= 1'b1;
                            end
                            ACT_START_HMAC: begin

                            end
                            ACT_START_WRAP: begin

                            end
                            ACT_START_STC: begin

                            end
                            default: begin
                                error_status_r <= 1'b1;
                                error_r <= ERR_UNSUPPORTED_COMMAND;
                            end
                        endcase
                    end
                end else if (bus_wdata != 0) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b1;
                    error_r <= ERR_CONTROL;
                    cycle_count_r <= 32'd1;
                end
            end else if (!wrapper_busy_w) begin
                if (bus_addr == REG_COMMAND) begin
                    command_r <= bus_wdata;
                end else if (bus_addr == REG_INPUT_LENGTH) begin
                    input_length_r <= bus_wdata;
                end else if (bus_addr == REG_OUTPUT_LENGTH) begin
                    output_length_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_Q) begin
                    arg_q_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_I) begin
                    arg_i_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_START) begin
                    arg_start_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_STEPS) begin
                    arg_steps_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_KEY) begin
                    arg_key_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_LEAF_NODE) begin
                    arg_leaf_node_r <= bus_wdata;
                end else if (bus_addr == REG_ARG_W) begin
                    arg_w_r <= bus_wdata[3:0];
                end else if (!stream_wr_en && !stream_rd_en &&
                             bus_addr == REG_TASK_ADDR && bus_wdata < 2152) begin
                    task_addr_r <= bus_wdata[11:0];
                    if (bus_wdata >= 32) begin
                        task_prefetch_pending_r <= 1'b1;
                    end
                end else if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w &&
                             bus_valid && bus_write && bus_addr == REG_TASK_DATA &&
                             task_addr_r >= 32) begin

                    task_addr_r <= task_addr_r + 12'd1;
                end else if (!stream_wr_en && !stream_rd_en &&
                             bus_addr == REG_TASK_DATA) begin
                    if (task_addr_r < 32) begin
                        coefficient_words[task_addr_r[4:0]] <= bus_wdata;
                    end
                end else if (bus_addr >= REG_IDENTIFIER && bus_addr < REG_IDENTIFIER + 16 &&
                             bus_addr[1:0] == 2'b00) begin
                    identifier_words[bus_addr[3:2]] <= bus_wdata;
                end else if (bus_addr >= REG_INPUT_BASE && bus_addr < REG_INPUT_BASE + 128 &&
                             bus_addr[1:0] == 2'b00) begin
                    input_words[bus_addr[6:2]] <= bus_wdata;
                end else if (!HAS_SECURITY && INSECURE_TEST_MODE && bus_addr >= REG_SEED_BASE &&
                             bus_addr < REG_SEED_BASE + 32 && bus_addr[1:0] == 2'b00) begin

                    local_seed_staging[bus_addr[4:2]] <= bus_wdata;
                end
            end
        end

        if (mqc_cmd_w && state_r == STATE_MQC_COEF) begin
            case (mqc_word_idx_w)
                    5'd0: case (w_coef_bits)
                        4'd1: coefficient_words[0][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[0][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[0][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[0][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd1: case (w_coef_bits)
                        4'd1: coefficient_words[1][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[1][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[1][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[1][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd2: case (w_coef_bits)
                        4'd1: coefficient_words[2][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[2][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[2][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[2][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd3: case (w_coef_bits)
                        4'd1: coefficient_words[3][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[3][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[3][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[3][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd4: case (w_coef_bits)
                        4'd1: coefficient_words[4][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[4][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[4][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[4][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd5: case (w_coef_bits)
                        4'd1: coefficient_words[5][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[5][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[5][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[5][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd6: case (w_coef_bits)
                        4'd1: coefficient_words[6][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[6][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[6][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[6][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    5'd7: case (w_coef_bits)
                        4'd1: coefficient_words[7][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[7][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[7][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[7][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                    default: case (w_coef_bits)
                        4'd1: coefficient_words[8][mqc_shift_w] <= mqc_digit_w[0];
                        4'd2: coefficient_words[8][mqc_shift_w +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[8][mqc_shift_w +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[8][mqc_shift_w +: 8] <= mqc_digit_w;
                    endcase
                endcase
        end

        if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w && done_r && bus_valid &&
            !bus_write && bus_addr == REG_TASK_DATA &&
            task_addr_r >= 32 && !stream_read_r) begin

            task_addr_r <= task_addr_r + 12'd1;
            stream_read_r <= 1'b1;
        end else if (!bus_valid) begin
            stream_read_r <= 1'b0;
        end

        if (state_r == STATE_START_CORE) begin
            core_start_r <= 1'b1;
            cycle_count_r <= cycle_count_r + 1'b1;
            if (dual_active_w) begin

                if (chain_steps_left0_r != 0 || batch_phase_r == BATCH_DERIVE) begin
                    core_start0_r <= 1'b1;
                    core0_run_r <= 1'b1;
                end else begin

                    core0_done_latched_r <= 1'b1;
                end
                block0_latched_r <= block_w;
                state_r <= STATE_DUAL_SETUP1;
            end else begin
                state_r <= STATE_WAIT_CORE;
            end
        end else if (state_r == STATE_DUAL_SETUP1) begin

            block1_latched_r <= block0_latched_r;
            block1_latched_r[511 - 20*8 -: 8] <= {7'b0, batch_i1_w[8]};
            block1_latched_r[511 - 21*8 -: 8] <= batch_i1_w[7:0];
            if (batch_phase_r != BATCH_DERIVE && chain_steps_left1_r != 0) begin

                block1_latched_r[511 - 22*8 -: 8] <= chain_j1_r;
                for (bj = 23; bj < 55; bj = bj + 1) begin
                    block1_latched_r[511 - bj*8 -: 8] <=
                        chain_value1_r[255 - (bj - 23)*8 -: 8];
                end
            end
            core_start1_r <= 1'b1;
            if (chain_steps_left1_r != 0 || batch_phase_r == BATCH_DERIVE) begin
                core1_run_r <= 1'b1;
            end else begin

                core1_done_latched_r <= 1'b1;
            end
            state_r <= STATE_DUAL_WAIT;
        end else if (state_r == STATE_DUAL_WAIT) begin

            cycle_count_r <= cycle_count_r + 1'b1;
            if (core0_done_w) core0_done_latched_r <= 1'b1;
            if (core1_done_w) core1_done_latched_r <= 1'b1;

            if (core0_done_w) core0_run_r <= 1'b0;
            if (core1_done_w) core1_run_r <= 1'b0;
            if ((core0_done_latched_r || core0_done_w) &&
                (core1_done_latched_r || core1_done_w)) begin
                core0_done_latched_r <= 1'b0;
                core1_done_latched_r <= 1'b0;

                if (command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF ||
                    command_r == CMD_LMOTS_SIGN || verify_cmd_w) begin
                    if (batch_phase_r == BATCH_DERIVE) begin
                        chain_value0_r <= core0_digest_w;
                        chain_value1_r <= core1_digest_w;
                        if (command_r == CMD_LMOTS_SIGN) begin

                            chain_value_r <= core0_digest_w;
                            chain_j0_r <= 8'd0;
                            chain_j1_r <= 8'd0;
                            chain_j_r   <= 8'd0;
                            chain_steps_left0_r <= batch_coefficient_w;
                            chain_steps_left1_r <= batch_coefficient1_w;
                            batch_phase_r <= BATCH_CHAIN;
                            state_r <= STATE_START_CORE;
                        end else begin
                            chain_value_r <= core0_digest_w;
                            chain_j0_r <= 8'd0;
                            chain_j1_r <= 8'd0;
                            chain_j_r   <= 8'd0;
                            chain_steps_left0_r <= w_max_step;
                            chain_steps_left1_r <= w_max_step;
                            batch_phase_r <= BATCH_CHAIN;
                            state_r <= STATE_START_CORE;
                        end
                    end else if (chain_steps_left0_r > 1 || chain_steps_left1_r > 1) begin

                        if (chain_steps_left0_r > 0) begin
                            chain_value0_r <= core0_digest_w;
                            chain_value_r   <= core0_digest_w;
                            chain_j0_r <= chain_j0_r + 1'b1;
                            chain_j_r   <= chain_j0_r + 1'b1;
                            chain_steps_left0_r <= chain_steps_left0_r - 1'b1;
                        end
                        if (chain_steps_left1_r > 0) begin
                            chain_value1_r <= core1_digest_w;
                            chain_j1_r <= chain_j1_r + 1'b1;
                            chain_steps_left1_r <= chain_steps_left1_r - 1'b1;
                        end
                        state_r <= STATE_START_CORE;
                    end else if (command_r == CMD_LMOTS_SIGN) begin

                        task_digest0_r <= core0_digest_w;
                        task_digest1_r <= core1_digest_w;
                        task_write_word0_r <= 3'd0;
                        task_write_word1_r <= 3'd0;
                        dual_write_sel_r <= 1'b0;
                        batch_phase_r <= BATCH_DERIVE;
                        state_r <= STATE_TASK_WRITE;
                    end else begin

                        for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                            pblc_buffer_r[511 - (22 + output_index)*8 -: 8] <=
                                core0_digest_w[255 - output_index*8 -: 8];
                        end
                        task_digest0_r <= core0_digest_w;
                        task_digest1_r <= core1_digest_w;
                        task_write_word0_r <= 3'd0;
                        task_write_word1_r <= 3'd0;
                        dual_write_sel_r <= 1'b0;
                        dual_pblc_delay_r <= 1'b1;
                    end
                end
            end
            if (dual_pblc_delay_r) begin

                pblc_block_r <= pblc_next_block_w;
                for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                    pblc_buffer_r[511 - output_index*8 -: 8] <=
                        core1_digest_w[255 - (10 + output_index)*8 -: 8];
                end
                dual_pblc_delay_r <= 1'b0;
                batch_phase_r <= BATCH_PBLC;
                state_r <= STATE_START_CORE;
            end
        end else if (state_r == STATE_WAIT_CORE) begin
            cycle_count_r <= cycle_count_r + 1'b1;
            if (core_done_w) begin
                if (dintr_cmd_w) begin

                    if (block_index_r == 2'd0) begin
                        block_index_r <= 2'd1;
                        state_r <= STATE_DINTR_KICK;
                    end else if (dintr_layer_r + 1'b1 < {1'b0, arg_steps_r[4:0]}) begin
                        dintr_left_r <= core_digest_w;
                        dintr_node_r <= dintr_node_r >> 1;
                        dintr_layer_r <= dintr_layer_r + 1'b1;
                        dintr_load_word_r <= 4'd0;
                        block_index_r <= 2'd0;
                        state_r <= STATE_DINTR_LOAD_SIB;
                    end else begin
                        for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                            output_words[output_index] <= {
                                core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                core_digest_w[255 - output_index * 32 -: 8]
                            };
                        end
                        state_r <= STATE_IDLE;
                        done_r <= 1'b1;
                    end
                end else if (hash_ram_path_w) begin

                    if (hash_ram_block_r + 1'b1 < hash_ram_blocks_w) begin
                        hash_ram_block_r <= hash_ram_block_r + 1'b1;
                        hash_ram_word_r <= 6'd0;
                        block_index_r <= 2'd1;
                        state_r <= STATE_TASK_PREFETCH;
                    end else if (mqc_cmd_w) begin

                        mqc_q_be_r[271:16] <= core_digest_w;
                        mqc_checksum_r <= 16'd0;
                        mqc_idx_r <= 9'd0;
                        for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                            output_words[output_index] <= {
                                core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                core_digest_w[255 - output_index * 32 -: 8]
                            };
                        end
                        state_r <= STATE_MQC_COEF;
                    end else begin
                        for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                            output_words[output_index] <= {
                                core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                core_digest_w[255 - output_index * 32 -: 8]
                            };
                        end
                        state_r <= STATE_IDLE;
                        done_r <= 1'b1;
                    end
                end else if (keygen_dleaf_r) begin

                    keygen_dleaf_r <= 1'b0;
                    for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                        output_words[output_index] <= {
                            core_digest_w[255 - (output_index * 32 + 24) -: 8],
                            core_digest_w[255 - (output_index * 32 + 16) -: 8],
                            core_digest_w[255 - (output_index * 32 + 8) -: 8],
                            core_digest_w[255 - output_index * 32 -: 8]
                        };
                    end
                    state_r <= STATE_IDLE;
                    done_r <= 1'b1;
                end else if (verify_cmd_w) begin
                    if (batch_phase_r == BATCH_CHAIN && chain_steps_left_r > 1) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= chain_j_r + 1'b1;
                        chain_steps_left_r <= chain_steps_left_r - 1'b1;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN &&
                                 (batch_i_r[0] || batch_i_r == w_p_last)) begin
                        pblc_block_r <= pblc_next_block_w;
                        if (batch_i_r[0]) begin
                            pblc_buffer_r <= 512'b0;
                            for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                                pblc_buffer_r[511 - output_index * 8 -: 8] <=
                                    core_digest_w[255 - (10 + output_index) * 8 -: 8];
                            end
                        end
                        batch_phase_r <= BATCH_PBLC;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN) begin
                        for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                            pblc_buffer_r[511 - (22 + output_index) * 8 -: 8] <=
                                core_digest_w[255 - output_index * 8 -: 8];
                        end
                        batch_i_r <= batch_i_r + 1'b1;
                        arg_i_r <= arg_i_r + 1'b1;
                        task_write_word_r <= 3'd0;
                        state_r <= STATE_TASK_PREFETCH;
                    end else if (batch_i_r == w_p_last || pblc_final_due_r) begin
                        for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                            output_words[output_index] <= {
                                core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                core_digest_w[255 - output_index * 32 -: 8]
                            };
                        end
                        pblc_final_due_r <= 1'b0;
                        if (command_r == CMD_LMOTS_VERIFY_LEAF) begin

                            keygen_dleaf_r <= 1'b1;
                            state_r <= STATE_TASK_PREFETCH;
                        end else begin
                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end
                    end else begin
                        pblc_state_r <= core_digest_w;
                        pblc_block_count_r <= pblc_block_count_r + 1'b1;
                        if (w_p_even && batch_i_r ==
                            (verify_dc_mode_r ? w_p - 9'd2 : w_p - 9'd1)) begin

                            pblc_final_due_r <= 1'b1;
                            pblc_block_r <= 512'b0;
                            for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                                pblc_block_r[511 - output_index * 8 -: 8] <=
                                    pblc_buffer_r[511 - output_index * 8 -: 8];
                            end
                            pblc_block_r[511 - 22 * 8 -: 8] <= 8'h80;
                            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                pblc_block_r[511 - (56 + output_index) * 8 -: 8] <=
                                    pblc_bitlen_w[(7 - output_index) * 8 +: 8];
                            end
                            state_r <= STATE_START_CORE;
                        end else begin
                            batch_i_r <= batch_i_r + (verify_dc_mode_r ? 9'd2 : 9'd1);
                            arg_i_r <= arg_i_r + (verify_dc_mode_r ? 32'd2 : 32'd1);
                            task_write_word_r <= 3'd0;
                            batch_phase_r <= BATCH_CHAIN;
                            state_r <= STATE_TASK_PREFETCH;
                        end
                    end
                end else if (command_r == CMD_LMOTS_SIGN) begin
                    if (batch_phase_r == BATCH_DERIVE && batch_coefficient_w == 0) begin

                        task_digest_r <= core_digest_w;
                        task_write_word_r <= 3'd0;
                        batch_phase_r <= BATCH_CHAIN;
                        state_r <= STATE_TASK_WRITE;
                    end else if (batch_phase_r == BATCH_DERIVE) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= 8'd0;
                        chain_steps_left_r <= batch_coefficient_w;
                        batch_phase_r <= BATCH_CHAIN;
                        state_r <= STATE_START_CORE;
                    end else if (chain_steps_left_r > 1) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= chain_j_r + 1'b1;
                        chain_steps_left_r <= chain_steps_left_r - 1'b1;
                        state_r <= STATE_START_CORE;
                    end else begin
                        task_digest_r <= core_digest_w;
                        task_write_word_r <= 3'd0;
                        state_r <= STATE_TASK_WRITE;
                    end
                end else if (command_r == CMD_LMOTS_KEYGEN || command_r == CMD_LMOTS_KEYGEN_LEAF) begin
                    if (batch_phase_r == BATCH_DERIVE) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= 8'd0;
                        chain_steps_left_r <= w_max_step;
                        batch_phase_r <= BATCH_CHAIN;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN && chain_steps_left_r > 1) begin
                        chain_value_r <= core_digest_w;
                        chain_j_r <= chain_j_r + 1'b1;
                        chain_steps_left_r <= chain_steps_left_r - 1'b1;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN &&
                                 (batch_i_r[0] || batch_i_r == w_p_last)) begin
                        pblc_block_r <= pblc_next_block_w;
                        if (batch_i_r[0]) begin
                            pblc_buffer_r <= 512'b0;
                            for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                                pblc_buffer_r[511 - output_index * 8 -: 8] <=
                                    core_digest_w[255 - (10 + output_index) * 8 -: 8];
                            end
                        end
                        batch_phase_r <= BATCH_PBLC;
                        state_r <= STATE_START_CORE;
                    end else if (batch_phase_r == BATCH_CHAIN) begin
                        for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                            pblc_buffer_r[511 - (22 + output_index) * 8 -: 8] <=
                                core_digest_w[255 - output_index * 8 -: 8];
                        end
                        batch_i_r <= batch_i_r + 1'b1;
                        arg_i_r <= arg_i_r + 1'b1;
                        batch_phase_r <= BATCH_DERIVE;
                        state_r <= STATE_START_CORE;
                    end else if (batch_i_r == w_p_last || pblc_final_due_r) begin
                        pblc_final_due_r <= 1'b0;
                        if (command_r == CMD_LMOTS_KEYGEN_LEAF) begin

                            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                output_words[output_index] <= {
                                    core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                    core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                    core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                    core_digest_w[255 - output_index * 32 -: 8]
                                };
                            end
                            state_r <= STATE_TASK_PREFETCH;
                        end else begin
                            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                output_words[output_index] <= {
                                    core_digest_w[255 - (output_index * 32 + 24) -: 8],
                                    core_digest_w[255 - (output_index * 32 + 16) -: 8],
                                    core_digest_w[255 - (output_index * 32 + 8) -: 8],
                                    core_digest_w[255 - output_index * 32 -: 8]
                                };
                            end
                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end
                    end else begin
                        pblc_state_r <= core_digest_w;
                        pblc_block_count_r <= pblc_block_count_r + 1'b1;
                        if (w_p_even && batch_i_r == w_p - 9'd2) begin

                            pblc_final_due_r <= 1'b1;
                            pblc_block_r <= 512'b0;
                            for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                                pblc_block_r[511 - output_index * 8 -: 8] <=
                                    pblc_buffer_r[511 - output_index * 8 -: 8];
                            end
                            pblc_block_r[511 - 22 * 8 -: 8] <= 8'h80;
                            for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                                pblc_block_r[511 - (56 + output_index) * 8 -: 8] <=
                                    pblc_bitlen_w[(7 - output_index) * 8 +: 8];
                            end
                            state_r <= STATE_START_CORE;
                        end else begin
                            batch_i_r <= batch_i_r + (dual_batch_w ? 9'd2 : 9'd1);
                            arg_i_r <= arg_i_r + (dual_batch_w ? 32'd2 : 32'd1);
                            batch_phase_r <= BATCH_DERIVE;
                            state_r <= STATE_START_CORE;
                        end
                    end
                end else if (block_index_r + 1'b1 < block_count_r) begin
                    block_index_r <= block_index_r + 1'b1;
                    state_r <= STATE_START_CORE;
                end else begin
                    for (output_index = 0; output_index < 8; output_index = output_index + 1) begin
                        output_words[output_index] <= {
                            core_digest_w[255 - (output_index * 32 + 24) -: 8],
                            core_digest_w[255 - (output_index * 32 + 16) -: 8],
                            core_digest_w[255 - (output_index * 32 + 8) -: 8],
                            core_digest_w[255 - output_index * 32 -: 8]
                        };
                    end
                    state_r <= STATE_IDLE;
                    if (busy_error_pending_r) begin
                        done_r <= 1'b0;
                        error_status_r <= 1'b1;
                        error_r <= ERR_BUSY;
                    end else begin
                        done_r <= 1'b1;
                        error_status_r <= 1'b0;
                        error_r <= 32'b0;
                    end
                end
            end
        end else if (state_r == STATE_TASK_WRITE) begin
            cycle_count_r <= cycle_count_r + 1'b1;
            if (dual_batch_w && batch_phase_r != BATCH_CHAIN) begin

                if (!dual_write_sel_r) begin
                    if (task_write_word0_r == 3'd7) begin
                        task_write_word0_r <= 3'd0;
                        if (batch_i_r == w_p_last) begin

                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end else begin
                            dual_write_sel_r <= 1'b1;
                        end
                    end else begin
                        task_write_word0_r <= task_write_word0_r + 1'b1;
                    end
                end else begin
                    if (task_write_word1_r == 3'd7) begin
                        task_write_word1_r <= 3'd0;
                        dual_write_sel_r <= 1'b0;
                        if (w_p_even && batch_i_r == w_p - 9'd2) begin

                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end else begin

                            batch_i_r <= batch_i_r + 9'd2;
                            arg_i_r <= arg_i_r + 32'd2;
                            batch_phase_r <= BATCH_DERIVE;
                            state_r <= STATE_START_CORE;
                        end
                    end else begin
                        task_write_word1_r <= task_write_word1_r + 1'b1;
                    end
                end
            end else if (task_write_word_r == 3'd7) begin
                if (batch_i_r == w_p_last) begin
                    state_r <= STATE_IDLE;
                    done_r <= 1'b1;
                end else begin
                    batch_i_r <= batch_i_r + 1'b1;
                    arg_i_r <= arg_i_r + 1'b1;
                    batch_phase_r <= BATCH_DERIVE;
                    state_r <= STATE_START_CORE;
                end
            end else begin
                task_write_word_r <= task_write_word_r + 1'b1;
            end
        end else if (state_r == STATE_TASK_PREFETCH) begin
            if (hash_ram_path_w) begin

                cycle_count_r <= cycle_count_r + 1'b1;
                state_r <= STATE_HASH_RAM_LOAD;
            end else if (command_r == CMD_LMOTS_KEYGEN_LEAF ||
                (command_r == CMD_LMOTS_VERIFY_LEAF && keygen_dleaf_r)) begin

                input_words[0] <= identifier_words[0];
                input_words[1] <= identifier_words[1];
                input_words[2] <= identifier_words[2];
                input_words[3] <= identifier_words[3];
                input_words[4] <= {arg_leaf_node_r[7:0], arg_leaf_node_r[15:8],
                                   arg_leaf_node_r[23:16], arg_leaf_node_r[31:24]};

                input_words[5] <= {output_words[0][15:8], output_words[0][7:0], 8'h82, 8'h82};
                input_words[6]  <= {output_words[1][15:8], output_words[1][7:0],
                                    output_words[0][31:24], output_words[0][23:16]};
                input_words[7]  <= {output_words[2][15:8], output_words[2][7:0],
                                    output_words[1][31:24], output_words[1][23:16]};
                input_words[8]  <= {output_words[3][15:8], output_words[3][7:0],
                                    output_words[2][31:24], output_words[2][23:16]};
                input_words[9]  <= {output_words[4][15:8], output_words[4][7:0],
                                    output_words[3][31:24], output_words[3][23:16]};
                input_words[10] <= {output_words[5][15:8], output_words[5][7:0],
                                    output_words[4][31:24], output_words[4][23:16]};
                input_words[11] <= {output_words[6][15:8], output_words[6][7:0],
                                    output_words[5][31:24], output_words[5][23:16]};
                input_words[12] <= {output_words[7][15:8], output_words[7][7:0],
                                    output_words[6][31:24], output_words[6][23:16]};
                input_words[13] <= {16'b0, output_words[7][31:24], output_words[7][23:16]};
                keygen_dleaf_r <= 1'b1;
                block_count_r <= 2'd1;
                block_index_r <= 2'd0;
                state_r <= STATE_START_CORE;
            end else begin
                cycle_count_r <= cycle_count_r + 1'b1;
                state_r <= STATE_TASK_LOAD;
            end
        end else if (state_r == STATE_TASK_LOAD) begin
            cycle_count_r <= cycle_count_r + 1'b1;
            if (verify_dual_load_r) begin
                chain_value1_r[255 - task_write_word_r * 32 -: 32] <= {
                    task_ram_read_r[7:0], task_ram_read_r[15:8],
                    task_ram_read_r[23:16], task_ram_read_r[31:24] };
            end else begin
                chain_value_r[255 - task_write_word_r * 32 -: 32] <= {
                    task_ram_read_r[7:0], task_ram_read_r[15:8],
                    task_ram_read_r[23:16], task_ram_read_r[31:24] };
            end
            if (task_write_word_r == 3'd7) begin
                if (dual_batch_w && verify_cmd_w && !verify_dual_load_r &&
                    !batch_i_r[0] &&
                    batch_i1_w < w_p &&
                    batch_coefficient_w != w_max_step && batch_coefficient1_w != w_max_step) begin
                    verify_dual_load_r <= 1'b1;
                    task_write_word_r <= 3'd0;
                end else if (dual_batch_w && verify_cmd_w && verify_dual_load_r) begin
                    chain_j0_r <= batch_coefficient_w;
                    chain_j1_r <= batch_coefficient1_w;
                    chain_j_r   <= batch_coefficient_w;
                    chain_steps_left0_r <= w_max_step - batch_coefficient_w;
                    chain_steps_left1_r <= w_max_step - batch_coefficient1_w;
                    verify_dual_load_r <= 1'b0;
                    verify_dc_mode_r <= 1'b1;
                    batch_phase_r <= BATCH_CHAIN;
                    state_r <= STATE_START_CORE;
                end else begin
                    if (dual_batch_w && verify_cmd_w) begin
                        verify_dual_load_r <= 1'b0;
                        verify_dc_mode_r <= 1'b0;
                    end
                    chain_j_r <= batch_coefficient_w;
                    chain_steps_left_r <= w_max_step - batch_coefficient_w;
                    if (batch_coefficient_w == w_max_step)
                        state_r <= STATE_TASK_ENDPOINT;
                    else
                        state_r <= STATE_START_CORE;
                end
            end else begin
                task_write_word_r <= task_write_word_r + 1'b1;
            end
        end else if (state_r == STATE_DINTR_PREFETCH) begin

            cycle_count_r <= cycle_count_r + 1'b1;
            state_r <= STATE_DINTR_LOAD_START;
        end else if (state_r == STATE_DINTR_LOAD_START) begin

            cycle_count_r <= cycle_count_r + 1'b1;
            dintr_left_r[255 - dintr_load_word_r * 32 -: 32] <= {
                task_ram_read_r[7:0], task_ram_read_r[15:8],
                task_ram_read_r[23:16], task_ram_read_r[31:24] };
            if (dintr_load_word_r == 4'd7) begin
                dintr_load_word_r <= 4'd0;
                state_r <= STATE_DINTR_LOAD_SIB;
            end else begin
                dintr_load_word_r <= dintr_load_word_r + 1'b1;
            end
        end else if (state_r == STATE_DINTR_LOAD_SIB) begin

            cycle_count_r <= cycle_count_r + 1'b1;
            dintr_right_r[255 - dintr_load_word_r * 32 -: 32] <= {
                task_ram_read_r[7:0], task_ram_read_r[15:8],
                task_ram_read_r[23:16], task_ram_read_r[31:24] };
            if (dintr_load_word_r == 4'd7) begin
                dintr_load_word_r <= 4'd0;
                state_r <= STATE_DINTR_KICK;
            end else begin
                dintr_load_word_r <= dintr_load_word_r + 1'b1;
            end
        end else if (state_r == STATE_DINTR_KICK) begin

            cycle_count_r <= cycle_count_r + 1'b1;
            core_start_r <= 1'b1;
            state_r <= STATE_WAIT_CORE;
        end else if (state_r == STATE_HASH_RAM_LOAD) begin

            cycle_count_r <= cycle_count_r + 1'b1;
            if (hash_ram_word_r == hash_ram_rd_words_w) begin
                hash_ram_word_r <= 6'd0;
                state_r <= STATE_HASH_RAM_KICK;
            end else begin

                hash_ram_window_r[575 - hash_ram_word_r * 32 -: 32] <= {
                    task_ram_read_r[7:0], task_ram_read_r[15:8],
                    task_ram_read_r[23:16], task_ram_read_r[31:24] };
                hash_ram_word_r <= hash_ram_word_r + 1'b1;
            end
        end else if (state_r == STATE_HASH_RAM_KICK) begin

            cycle_count_r <= cycle_count_r + 1'b1;
            core_start_r <= 1'b1;
            state_r <= STATE_WAIT_CORE;
        end else if (state_r == STATE_MQC_COEF) begin

            cycle_count_r <= cycle_count_r + 1'b1;
            if (mqc_idx_r < mqc_u_w) begin
                mqc_checksum_r <= mqc_checksum_r + (w_max_step - mqc_digit_w);
                if (mqc_idx_r == mqc_u_w - 9'd1) begin
                    mqc_q_be_r[15:0] <= (mqc_checksum_r + (w_max_step - mqc_digit_w)) << mqc_ls_w;
                end
            end
            if (mqc_idx_r == w_p - 9'd1) begin
                mqc_idx_r <= 9'd0;
                state_r <= STATE_IDLE;
                done_r <= 1'b1;
            end else begin
                mqc_idx_r <= mqc_idx_r + 9'd1;
            end
        end else if (state_r == STATE_TASK_ENDPOINT) begin
            cycle_count_r <= cycle_count_r + 1'b1;
            if (batch_i_r[0] || batch_i_r == w_p_last) begin
                pblc_block_r <= pblc_next_block_w;
                if (batch_i_r[0]) begin
                    pblc_buffer_r <= 512'b0;
                    for (output_index = 0; output_index < 22; output_index = output_index + 1) begin
                        pblc_buffer_r[511 - output_index * 8 -: 8] <=
                            chain_value_r[255 - (10 + output_index) * 8 -: 8];
                    end
                end
                batch_phase_r <= BATCH_PBLC;
                state_r <= STATE_START_CORE;
            end else begin
                for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                    pblc_buffer_r[511 - (22 + output_index) * 8 -: 8] <=
                        chain_value_r[255 - output_index * 8 -: 8];
                end
                batch_i_r <= batch_i_r + 1'b1;
                arg_i_r <= arg_i_r + 1'b1;
                task_write_word_r <= 3'd0;
                state_r <= STATE_TASK_PREFETCH;
            end
        end

        if (ksd_sign_rejected_w) begin
            done_r <= 1'b0;
            error_status_r <= 1'b1;
            error_r <= 32'd18;
        end
        if (rst) begin
            command_r <= 32'b0;
            input_length_r <= 32'b0;
            output_length_r <= 32'b0;
            arg_q_r <= 32'b0;
            arg_i_r <= 32'b0;
            arg_start_r <= 32'b0;
            arg_steps_r <= 32'b0;
            arg_key_r <= 32'b0;
            error_r <= 32'b0;
            cycle_count_r <= 32'b0;
            state_r <= STATE_IDLE;
            block_index_r <= 2'b0;
            block_count_r <= 2'b0;
            done_r <= 1'b0;
            error_status_r <= 1'b0;
            busy_error_pending_r <= 1'b0;
            core_start_r <= 1'b0;
            engine_start_r <= 1'b0;
            chain_value_r <= 256'b0;
            chain_j_r <= 8'b0;
            chain_steps_left_r <= 8'b0;
            batch_phase_r <= BATCH_DERIVE;
            batch_i_r <= 9'b0;
            arg_w_r <= 4'd4;
            pblc_final_due_r <= 1'b0;
            pblc_block_count_r <= 8'b0;
            pblc_state_r <= 256'b0;
            pblc_buffer_r <= 512'b0;
            pblc_block_r <= 512'b0;
            task_addr_r <= 12'b0;
            task_prefetch_pending_r <= 1'b0;
            stream_read_r <= 1'b0;
            keygen_dleaf_r <= 1'b0;
            core_start0_r <= 1'b0;
            core_start1_r <= 1'b0;
            core0_done_latched_r <= 1'b0;
            core1_done_latched_r <= 1'b0;
            dual_pblc_delay_r <= 1'b0;
            chain_value0_r <= 256'b0;
            chain_value1_r <= 256'b0;
            chain_j0_r <= 8'b0;
            chain_j1_r <= 8'b0;
            chain_steps_left0_r <= 8'b0;
            chain_steps_left1_r <= 8'b0;
            task_digest0_r <= 256'b0;
            task_digest1_r <= 256'b0;
            task_write_word0_r <= 3'b0;
            task_write_word1_r <= 3'b0;
            dual_write_sel_r <= 1'b0;
            verify_dual_load_r <= 1'b0;
            verify_dc_mode_r <= 1'b0;
            core0_run_r <= 1'b0;
            core1_run_r <= 1'b0;
            block0_latched_r <= 512'b0;
            block1_latched_r <= 512'b0;
            arg_leaf_node_r <= 32'b0;
            task_write_word_r <= 3'b0;
            task_digest_r <= 256'b0;
            dintr_left_r <= 256'b0;
            dintr_right_r <= 256'b0;
            dintr_node_r <= 32'b0;
            dintr_layer_r <= 5'b0;
            dintr_load_word_r <= 4'b0;
            hash_ram_block_r <= 6'b0;
            hash_ram_word_r <= 6'b0;
            hash_ram_window_r <= 576'b0;
            mqc_q_be_r <= 272'b0;
            mqc_checksum_r <= 16'b0;
            mqc_idx_r <= 9'b0;
            for (output_index = 0; output_index < 32; output_index = output_index + 1) begin
                coefficient_words[output_index] <= 32'b0;
            end
        end
    end

    always @* begin
        bus_rdata = 32'b0;
        if (bus_valid && !bus_write) begin
            if (sec_bus_valid_w) begin

                bus_rdata = sec_bus_rdata_w;
            end else begin
                case (bus_addr)
                REG_VERSION:       bus_rdata = VERSION;
                REG_CAPABILITY:    bus_rdata = CAPABILITY;
                REG_COMMAND:       bus_rdata = command_r;
                REG_STATUS:        bus_rdata = status_w;
                REG_ERROR:         bus_rdata = error_r;
                REG_INPUT_LENGTH:  bus_rdata = input_length_r;
                REG_OUTPUT_LENGTH: bus_rdata = output_length_r;
                REG_CYCLE_COUNT:   bus_rdata = cycle_count_r;
                REG_ARG_Q:         bus_rdata = arg_q_r;
                REG_ARG_I:         bus_rdata = arg_i_r;
                REG_ARG_START:     bus_rdata = arg_start_r;
                REG_ARG_STEPS:     bus_rdata = arg_steps_r;
                REG_ARG_KEY:       bus_rdata = arg_key_r;
                REG_ARG_LEAF_NODE: bus_rdata = arg_leaf_node_r;
                REG_ARG_W:         bus_rdata = {28'b0, arg_w_r};
                REG_TASK_ADDR:     bus_rdata = {20'b0, task_addr_r};
                REG_TASK_DATA: begin
                    if (task_addr_r < 32) begin
                        bus_rdata = coefficient_words[task_addr_r[4:0]];
                    end else begin
                        bus_rdata = task_ram_read_r;
                    end
                end
                default: begin
                    if (bus_addr >= REG_IDENTIFIER && bus_addr < REG_IDENTIFIER + 16 &&
                        bus_addr[1:0] == 2'b00) begin
                        bus_rdata = identifier_words[bus_addr[3:2]];
                    end else if (bus_addr >= REG_INPUT_BASE && bus_addr < REG_INPUT_BASE + 128 &&
                        bus_addr[1:0] == 2'b00) begin
                        bus_rdata = input_words[bus_addr[6:2]];
                    end else if (bus_addr >= REG_OUTPUT_BASE && bus_addr < REG_OUTPUT_BASE + 32 &&
                                 bus_addr[1:0] == 2'b00) begin
                        bus_rdata = output_words[bus_addr[4:2]];
                    end

                end
            endcase
            end
            if (ksd_mmio_hit_w) bus_rdata = ksd_mmio_rdata_w;
            if (ksd_output_hidden_w) begin
                if ((bus_addr == REG_TASK_DATA && task_addr_r >= 32) ||
                    (bus_addr >= REG_OUTPUT_BASE && bus_addr < REG_OUTPUT_BASE + 32 &&
                     !public_output_visible_w))
                    bus_rdata = 32'b0;
                if (command_r == CMD_LMOTS_SIGN && !physical_busy_w) begin
                    if (bus_addr == REG_STATUS) bus_rdata = STATUS_ERROR;
                    if (bus_addr == REG_ERROR) bus_rdata = 32'd18;
                end
            end
        end
    end

    wire unused_core_busy = core_busy_w;

endmodule

`default_nettype wire
