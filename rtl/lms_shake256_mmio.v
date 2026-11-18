`default_nettype none

//

//

//   CMD_DERIVE_RANDOMIZER  C = SHAKE256(I||q||0x8585||SEED)
//

//   x_q[i] = H(I||u32(q)||u16(i)||0xff||SEED)  55B
//   C      = H(I||u32(q)||u16(0x8585)||SEED)   54B

//

(* keep_hierarchy = "yes" *)
module lms_shake256_mmio #(
    parameter [31:0] SHAKE_BASE = 32'h1600_0000,
    parameter INSECURE_TEST_MODE = 0,
    parameter HAS_SECURITY = 1,
    parameter RANDOM_DELAY = 0
    ,parameter DERIVE_SHUFFLE = 0
    ,parameter ALLOW_XQ_DERIVE = 0
    ,parameter SINGLE_CORE = 0
    ,parameter MASKED = 0
    ,parameter TRNG_SIM_MODE = 0
    ,parameter DBG_CORE1_SKEW = 0
    ,parameter DBG_DROP_CORE1_DONE = 0
    ,parameter DBG_STEPS1_STUCK = 0
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
    output reg  [31:0] bus_rdata,
    output wire        mem_hit,

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

    /* verilator lint_off WIDTHTRUNC */
    /* verilator lint_off WIDTHEXPAND */
    /* verilator lint_off UNUSEDPARAM */
    /* verilator lint_off UNUSEDSIGNAL */

    localparam DISABLE_FOLD = 0;
    localparam [31:0] VERSION = 32'h00000001;

    localparam [31:0] CAPABILITY =
        32'h00000001 |                                  /* bit0:  SHAKE256 */
        32'h00000002 |                                  /* bit1:  HASH_ONCE */
        32'h00000004 |                                  /* bit2:  CHAIN */
        (INSECURE_TEST_MODE ? 32'h00000008 : 32'b0) |    /* bit3: diagnostic DERIVE_CHAIN */
        32'h00000010 |

        32'h00000020 |
        32'h00000040 |                                  /* bit6:  LMOTS_SIGN */
        32'h00000080 |                                  /* bit7:  LMOTS_VERIFY */
        (HAS_SECURITY ? 32'h00000100 : 32'h00000000) |
        (HAS_SECURITY ? 32'h00000200 : 32'h00000000) |
        (HAS_SECURITY ? 32'h00000400 : 32'h00000000) |
        32'h00000800 |                                  /* bit11: LMOTS_KEYGEN_LEAF */
        32'h00001000 |
        32'h00002000 |
        32'h00004000 |
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
    localparam [9:0] REG_IDENTIFIER    = 10'h040;  /* 16B */
    localparam [9:0] REG_SIM_MC        = 10'h060;
    localparam [9:0] REG_SEED_BASE     = 10'h080;  /* 32B */
    localparam [9:0] REG_WRAPPED_BASE  = 10'h0a0;
    localparam [9:0] REG_KWRAP_BASE    = 10'h0e0;
    localparam [9:0] REG_INPUT_BASE    = 10'h100;  /* 32 words = 128B */
    localparam [9:0] REG_OUTPUT_BASE   = 10'h200;  /* 8 words = 32B */

    localparam [9:0] REG_DBG_ADDR      = 10'h220;
    localparam [9:0] REG_DBG_DATA      = 10'h224;
    localparam [9:0] REG_TIMEOUT0      = 10'h228;
    localparam [9:0] REG_TIMEOUT1      = 10'h22C;

    localparam [9:0] REG_CAP_CTL       = 10'h230;
    localparam [9:0] REG_CAP_IDX       = 10'h234;
    localparam [9:0] REG_CAP_DATA      = 10'h238;

    localparam [31:0] CMD_HASH_ONCE = 32'h00000001;
    localparam [31:0] CMD_CHAIN = 32'h00000002;
    localparam [31:0] CMD_SEED_LOAD = 32'h00000003;
    localparam [31:0] CMD_DERIVE_CHAIN = 32'h00000004;
    localparam [31:0] CMD_DERIVE_RANDOMIZER = 32'h00000005;
    localparam [31:0] CMD_LMOTS_KEYGEN = 32'h00000006;
    localparam [31:0] CMD_LMOTS_SIGN = 32'h00000007;
    localparam [31:0] CMD_LMOTS_VERIFY = 32'h00000008;
    localparam [31:0] CMD_LMOTS_KEYGEN_LEAF = 32'h0000000e;
    localparam [31:0] CMD_LMOTS_VERIFY_LEAF = 32'h0000000f;
    localparam [31:0] CMD_MC_STEP       = 32'h00000010;
    localparam [31:0] CMD_MC_LOAD       = 32'h00000011;
    localparam [31:0] CMD_WRAP_SEED     = 32'h00000012;
    localparam [31:0] CMD_UNWRAP_SEED   = 32'h00000013;
    localparam [31:0] CMD_HMAC_KSTATE   = 32'h00000014;
    localparam [31:0] CMD_STATE_COMMIT  = 32'h00000015;
    localparam [31:0] CMD_D_INTR_CHAIN = 32'h00000018;
    localparam [31:0] CMD_HASH_ONCE_RAM = 32'h00000019;
    localparam [31:0] CMD_MSG_Q_COEF = 32'h0000001a;
    localparam [31:0] CTRL_START = 32'h00000001;
    localparam [31:0] CTRL_CLEAR = 32'h00000002;

    localparam [3:0] STATE_IDLE          = 4'd0;
    localparam [3:0] STATE_START_CORE    = 4'd1;
    localparam [3:0] STATE_WAIT_CORE     = 4'd2;
    localparam [3:0] STATE_TASK_WRITE    = 4'd3;
    localparam [3:0] STATE_TASK_LOAD     = 4'd4;
    localparam [3:0] STATE_TASK_PREFETCH = 4'd6;
    localparam [3:0] STATE_DUAL_SETUP1   = 4'd8;
    localparam [3:0] STATE_DUAL_WAIT     = 4'd9;
    localparam [3:0] STATE_PBLC_FINAL    = 4'd10;

    localparam [3:0] STATE_DINTR_PREFETCH    = 4'd11;
    localparam [3:0] STATE_DINTR_LOAD_START  = 4'd12;
    localparam [3:0] STATE_DINTR_LOAD_SIB    = 4'd13;
    localparam [3:0] STATE_DINTR_CORE        = 4'd14;
    localparam [3:0] STATE_DINTR_KICK        = 4'd15;

    localparam [4:0] STATE_RND_DELAY        = 5'd18;

    localparam [3:0] STATE_HASH_RAM_LOAD     = 4'd5;
    localparam [3:0] STATE_HASH_RAM_KICK     = 4'd7;

    localparam [4:0] STATE_MQC_COEF          = 5'd17;
    localparam [1:0] BATCH_DERIVE = 2'd0;
    localparam [1:0] BATCH_CHAIN  = 2'd1;
    localparam [1:0] BATCH_PBLC   = 2'd2;

    localparam [9:0] REG_TASK_ADDR     = 10'h038;
    localparam [9:0] REG_TASK_DATA     = 10'h03c;
    /* R6 Stage 1: read-only result window for LM-OTS Sign y (relative to y base 32). */
    localparam [9:0] REG_RESULT_EPOCH   = 10'h300;
    localparam [9:0] REG_RESULT_COUNT   = 10'h304;
    localparam [9:0] REG_RESULT_STATUS  = 10'h308;
    localparam [9:0] REG_RESULT_LENGTH  = 10'h30c;
    localparam [9:0] REG_RESULT_ADDR    = 10'h310;
    localparam [9:0] REG_RESULT_DATA    = 10'h314;
    localparam [9:0] REG_RESULT_RELEASE = 10'h318;
    localparam [9:0] REG_RESULT_ERROR   = 10'h31c;
    localparam [31:0] ERR_RESULT_NOT_READY = 32'h00000010;
    localparam [9:0] REG_ARG_LEAF_NODE = 10'h050;
    localparam [9:0] REG_ARG_W         = 10'h054;

    localparam [3:0] ACT_START       = 4'd0;
    localparam [3:0] ACT_DONE_SEED   = 4'd1;
    localparam [3:0] ACT_DONE_CHAIN0 = 4'd2;
    localparam [3:0] ACT_DONE_KWRAP  = 4'd3;
    localparam [3:0] ACT_DONE_KSTATE = 4'd4;
    localparam [3:0] ACT_DONE_MC     = 4'd5;
    localparam [3:0] ACT_START_HMAC  = 4'd6;
    localparam [3:0] ACT_START_WRAP  = 4'd7;
    localparam [3:0] ACT_START_STC   = 4'd8;

    localparam [31:0] STATUS_BUSY  = 32'h00000001;
    localparam [31:0] STATUS_DONE  = 32'h00000002;
    localparam [31:0] STATUS_ERROR = 32'h00000004;

    localparam [31:0] ERR_UNSUPPORTED_COMMAND = 32'h00000001;
    localparam [31:0] ERR_CORE_TIMEOUT = 32'h0000_00EE;
    localparam [31:0] ERR_BUSY                = 32'h00000002;
    localparam [31:0] ERR_INPUT_LENGTH        = 32'h00000003;
    localparam [31:0] ERR_CONTROL             = 32'h00000007;
    localparam [31:0] ERR_SEED_NOT_LOADED     = 32'h00000009;
    localparam [31:0] ERR_INSECURE_DISABLED   = 32'h0000000a;
    localparam [31:0] ERR_MASK_NOT_READY      = 32'h000000e1;

    localparam [1:0] TASK_NONE  = 2'd0;
    localparam [1:0] TASK_CHAIN = 2'd1;
    localparam [1:0] TASK_DERIVE = 2'd2;
    localparam [1:0] TASK_RANDOMIZER = 2'd3;

    localparam [3:0] ST_IDLE       = 4'd0;
    localparam [3:0] ST_ABSORB     = 4'd1;
    localparam [3:0] ST_WAIT_CORE  = 4'd2;
    localparam [3:0] ST_DONE       = 4'd3;

    reg [31:0] command_r;
    reg [31:0] input_length_r;
    reg [31:0] output_length_r;
    reg [31:0] arg_q_r;
    reg [15:0] arg_i_r;
    reg [7:0]  arg_start_r;
    reg [31:0] arg_steps_r;
    reg [31:0] identifier_words [0:3];

    reg [31:0] input_words [0:31];
    reg [31:0] output_words [0:7];
    reg [31:0] error_r;
    reg        done_r;
    reg        engine_start_r;

    reg [31:0] arg_key_r;
    reg [31:0] arg_leaf_node_r;
    reg [3:0]  arg_w_r;
    reg [4:0]  state_r;

    reg [15:0] rnd_lfsr_r;
    reg [9:0]  rnd_delay_r;
    reg [1:0]  block_index_r;
    reg [1:0]  block_count_r;
    reg [31:0] cycle_count_r;
    reg [17:0] wait_core_to_r;

    reg        mon_kick_busy_r;
    reg        mon_steps_jump_r;
    reg        mon_wait_long_r;
    reg  [7:0] mon_first_cycle_r;
    reg  [7:0] steps0_prev_r;

    reg  [7:0] fw_stage_r;
    reg        error_status_r;
    reg        busy_error_pending_r;
    reg        keygen_dleaf_r;

    reg  [8:0]  w_p;
    reg  [3:0]  w_coef_bits;
    reg  [7:0]  w_max_step;
    reg  [6:0]  w_pblc_last_block;
    reg  [7:0]  w_pblc_last_bytes;
    reg  [5:0]  w_pblc_last_rd;
    always @* begin
        case (arg_w_r)
            4'd1: begin w_p = 9'd265; w_coef_bits = 4'd1; w_max_step = 8'd1;
                        w_pblc_last_block = 7'd62; w_pblc_last_bytes = 8'd70; w_pblc_last_rd = 6'd18; end
            4'd2: begin w_p = 9'd133; w_coef_bits = 4'd2; w_max_step = 8'd3;
                        w_pblc_last_block = 7'd31; w_pblc_last_bytes = 8'd62; w_pblc_last_rd = 6'd16; end
            4'd8: begin w_p = 9'd34;  w_coef_bits = 4'd8; w_max_step = 8'd255;
                        w_pblc_last_block = 7'd8;  w_pblc_last_bytes = 8'd22; w_pblc_last_rd = 6'd6;  end
            default: begin w_p = 9'd67; w_coef_bits = 4'd4; w_max_step = 8'd15;
                        w_pblc_last_block = 7'd15; w_pblc_last_bytes = 8'd126; w_pblc_last_rd = 6'd32; end
        endcase
    end

    reg [255:0] chain_value0_r;
    reg [255:0] chain_value1_r;
    reg [255:0] chain_value0_b_r;
    reg [255:0] chain_value1_b_r;
    reg [7:0]  chain_j_r;
    reg [7:0]  chain_j0_r;
    reg [7:0]  chain_j1_r;
    reg [7:0]  chain_steps_left0_r;
    reg [7:0]  chain_steps_left1_r;
    reg [1:0]  batch_phase_r;
    reg [8:0]  batch_i_r;
    reg [2:0]  task_write_word_r;
    reg [2:0]  task_write_word0_r;
    reg [2:0]  task_write_word1_r;
    reg [255:0] task_digest0_r;
    reg [255:0] task_digest1_r;

    reg        core0_done_latched_r;
    reg        core1_done_latched_r;
    reg        dual_write_sel_r;
    reg        verify_dual_load_r;
    reg [1087:0] batch_block1_r;
    reg [1087:0] batch_block_b1_r;

    reg [63:0] timeout_snap_r;
    reg        dual_core1_active_r;
    reg        chain0_zero_r;
    reg        chain1_zero_r;
    reg [11:0] task_addr_r;
    reg [31:0] task_ram_read_r;
    /* R6 Stage 1 result port state. Port B is read-only and only covers the
     * y region (task_words[32 .. 32+length-1]); count is in chains, not words. */
    reg [31:0] result_epoch_r;
    reg [8:0]  result_count_r;
    reg        result_active_r;
    reg        result_done_r;
    reg        result_error_r;
    reg [11:0] result_length_r;
    reg [11:0] result_addr_r;
    reg [31:0] result_read_r;
    reg        result_read_valid_r;
    wire [11:0] result_abs_addr_w = 12'd32 + result_addr_r;
    wire [11:0] result_committed_words_w = {result_count_r, 3'b0};
    wire        result_addr_valid_w = result_active_r &&
                                      (result_addr_r < result_length_r) &&
                                      (result_addr_r < result_committed_words_w);
    reg        stream_read_r;
    reg        stream_rd_pending_r;
    reg        task_prefetch_pending_r;
    (* ram_style = "block" *) reg [31:0] task_words [0:2151];

    reg [31:0] coefficient_words [0:31];

    reg [6:0]    pblc_final_block_r;
    reg [5:0]    pblc_final_word_r;
    reg [1119:0] pblc_final_window_r;

    reg [255:0] dintr_left_r;
    reg [255:0] dintr_right_r;
    reg [31:0]  dintr_node_r;
    reg [4:0]   dintr_layer_r;
    reg [3:0]   dintr_load_word_r;
    wire dintr_cmd_w = command_r == CMD_D_INTR_CHAIN;

    wire [175:0] pblc_head_w = {
        8'h80,                          /* byte21 */
        8'h80,                          /* byte20 */
        arg_q_r[7:0],                   /* byte19 */
        arg_q_r[15:8],                  /* byte18 */
        arg_q_r[23:16],                 /* byte17 */
        arg_q_r[31:24],                 /* byte16 */
        identifier_flat_w[15*8 +: 8], identifier_flat_w[14*8 +: 8],
        identifier_flat_w[13*8 +: 8], identifier_flat_w[12*8 +: 8],
        identifier_flat_w[11*8 +: 8], identifier_flat_w[10*8 +: 8],
        identifier_flat_w[9*8 +: 8],  identifier_flat_w[8*8 +: 8],
        identifier_flat_w[7*8 +: 8],  identifier_flat_w[6*8 +: 8],
        identifier_flat_w[5*8 +: 8],  identifier_flat_w[4*8 +: 8],
        identifier_flat_w[3*8 +: 8],  identifier_flat_w[2*8 +: 8],
        identifier_flat_w[1*8 +: 8],  identifier_flat_w[0*8 +: 8]};

    wire [11:0] pblc_final_base_w =
        (pblc_final_block_r == 7'd0) ? 12'd32 :
        (12'd26 + {5'b0, pblc_final_block_r} * 12'd34);
    wire [5:0] pblc_final_rd_words =
        (pblc_final_block_r == w_pblc_last_block) ? w_pblc_last_rd : 6'd35;

    reg [1087:0] pblc_last_block_w;
    integer pblc_lb;
    always @* begin
        pblc_last_block_w = 1088'b0;
        for (pblc_lb = 0; pblc_lb < 136; pblc_lb = pblc_lb + 1) begin
            if (pblc_lb < w_pblc_last_bytes)
                pblc_last_block_w[pblc_lb * 8 +: 8] = pblc_final_window_r[16 + pblc_lb * 8 +: 8];
            else if (pblc_lb == w_pblc_last_bytes)
                pblc_last_block_w[pblc_lb * 8 +: 8] = 8'h1f;
            else if (pblc_lb == 135)
                pblc_last_block_w[pblc_lb * 8 +: 8] = 8'h80;
        end
    end

    wire hash_ram_cmd_w = command_r == CMD_HASH_ONCE_RAM;

    wire mqc_multi_w = mqc_cmd_w;
    wire hash_ram_path_w = hash_ram_cmd_w || mqc_multi_w;
    wire mqc_block0_w = mqc_multi_w && (hash_ram_block_r == 4'd0);
    reg  [3:0] hash_ram_block_r;
    reg  [5:0] hash_ram_word_r;
    reg  [3:0] hash_ram_full_r;
    reg  [7:0] hash_ram_rem_r;
    reg        hash_ram_kicked_r;
    wire hash_ram_is_last_w = (hash_ram_block_r == hash_ram_full_r);
    wire [7:0] hash_ram_data_bytes_w = hash_ram_is_last_w ?
        (hash_ram_rem_r == 8'd0 ? 8'd0 : hash_ram_rem_r) : 8'd136;
    wire [5:0] hash_ram_rd_words_w =
        hash_ram_is_last_w ?
            (hash_ram_rem_r == 8'd0 ? 6'd0 :
             (mqc_multi_w ? (({1'b0, hash_ram_rem_r} + 7'd5) >> 2)
                          : ({1'b0, hash_ram_rem_r[7:2]} +
                             (|hash_ram_rem_r[1:0] ? 6'd1 : 6'd0))))
        : ((mqc_multi_w && (hash_ram_block_r != 4'd0)) ? 6'd35
           : (mqc_block0_w ? 6'd35 : 6'd34));

    wire mqc_short_w = mqc_multi_w && (input_length_r <= 12'd128);
    wire [11:0] mqc_base_w = mqc_short_w ?
        ((w_p == 9'd265) ? 12'd568 : (12'd32 + {w_p, 3'b0})) : 12'd568;
    wire [11:0] hash_ram_base_w =
        (mqc_multi_w ? mqc_base_w : 12'd32) + {8'b0, hash_ram_block_r} * 12'd34;

    reg [1087:0] hash_ram_block_w;
    integer hram_lb;
    always @* begin
        hash_ram_block_w = 1088'b0;
        for (hram_lb = 0; hram_lb < 136; hram_lb = hram_lb + 1) begin
            if (hram_lb[7:0] < hash_ram_data_bytes_w)
                hash_ram_block_w[hram_lb * 8 +: 8] =

                    (mqc_multi_w && (mqc_block0_w ? (hram_lb >= 54) : 1'b1)) ?
                        pblc_final_window_r[(hram_lb + 2) * 8 +: 8] :
                        pblc_final_window_r[hram_lb * 8 +: 8];
            else if (hram_lb[7:0] == hash_ram_data_bytes_w)
                hash_ram_block_w[hram_lb * 8 +: 8] =
                    (hash_ram_data_bytes_w == 8'd135) ? 8'h9f : 8'h1f;
            else if (hram_lb == 135)
                hash_ram_block_w[hram_lb * 8 +: 8] = 8'h80;
        end
    end

    wire mqc_cmd_w = command_r == CMD_MSG_Q_COEF;
    reg  [255:0] mqc_q_be_r;
    reg  [15:0] mqc_cs_be_r;
    reg  [15:0] mqc_checksum_r;
    reg  [8:0]  mqc_idx_r;
    reg  [4:0]  mqc_shift_r;
    reg  [8:0]  mqc_word_idx_r;
    wire [15:0] mqc_cs_final_w =
        (mqc_checksum_r + (w_max_step - mqc_digit_w)) << mqc_ls_w;
    reg  [8:0]  mqc_u_w;
    reg  [3:0]  mqc_ls_w;
    reg  [3:0]  mqc_log2w_w;          /* log2(w):0/1/2/3 */
    reg  [2:0]  mqc_bp3w_w;           /* 3-log2(w):3/2/1/0(byte_idx = i >> (3-log2w)) */
    reg  [2:0]  mqc_dib_mask_w;
    wire        mqc_last_w = (mqc_idx_r == w_p - 9'd1);
    always @* begin
        case (arg_w_r)
            4'd1: begin mqc_u_w = 9'd256; mqc_ls_w = 4'd7; mqc_log2w_w = 4'd0; mqc_bp3w_w = 3'd3; mqc_dib_mask_w = 3'd7; end
            4'd2: begin mqc_u_w = 9'd128; mqc_ls_w = 4'd6; mqc_log2w_w = 4'd1; mqc_bp3w_w = 3'd2; mqc_dib_mask_w = 3'd3; end
            4'd8: begin mqc_u_w = 9'd32;  mqc_ls_w = 4'd0; mqc_log2w_w = 4'd3; mqc_bp3w_w = 3'd0; mqc_dib_mask_w = 3'd0; end
            default: begin mqc_u_w = 9'd64; mqc_ls_w = 4'd4; mqc_log2w_w = 4'd2; mqc_bp3w_w = 3'd1; mqc_dib_mask_w = 3'd1; end
        endcase
    end

    wire [8:0]  mqc_q_byte_idx_w = mqc_idx_r >> mqc_bp3w_w;
    wire [7:0]  mqc_q_byte_w = mqc_q_be_r[255 - {4'b0, mqc_q_byte_idx_w} * 8'd8 -: 8];
    wire [3:0]  mqc_q_shift_w = ((~mqc_idx_r[2:0]) & mqc_dib_mask_w) << mqc_log2w_w;
    wire [7:0]  mqc_digit_q_w = mqc_q_byte_w >> mqc_q_shift_w;
    wire [8:0]  mqc_cs_j_w = mqc_idx_r - mqc_u_w;
    wire [7:0]  mqc_cs_byte_idx_w = mqc_cs_j_w >> mqc_bp3w_w;
    wire [7:0]  mqc_cs_byte_w = mqc_cs_be_r[15 - {6'b0, mqc_cs_byte_idx_w} * 8'd8 -: 8];
    wire [3:0]  mqc_cs_shift_w = ((~mqc_cs_j_w[2:0]) & mqc_dib_mask_w) << mqc_log2w_w;
    wire [7:0]  mqc_digit_cs_w = mqc_cs_byte_w >> mqc_cs_shift_w;

    wire [7:0] mqc_mask_w =
        (w_coef_bits == 4'd8) ? 8'hff : (8'h01 << w_coef_bits) - 8'h01;
    reg [7:0] mqc_digit_w;
    always @* begin
        if (mqc_idx_r < mqc_u_w)
            mqc_digit_w = mqc_digit_q_w & mqc_mask_w;
        else
            mqc_digit_w = mqc_digit_cs_w & mqc_mask_w;
    end

    wire [1087:0] batch_rate_block_w;
    wire [1087:0] batch_rate_block_b_w;
    wire          batch_rate_init_w;

    wire [255:0] dleaf_kq_w = {output_words[7], output_words[6], output_words[5], output_words[4],
                               output_words[3], output_words[2], output_words[1], output_words[0]};

    reg [2:0] batch_task_type_w;

    reg [1087:0] batch_block_r;
    reg [1087:0] batch_block_b_r;
    reg          core0_kick_r;
    reg          core1_kick_r;

    reg          core0_kick_q;
    reg          c0_req_seen;
    reg          c1_req_seen;
    reg          core1_kick_q;
    reg          core0_init_r;
    reg          core1_init_r;
    reg  [15:0]  dbg_rd_sel_r;

    wire verify_cmd_w = (command_r == CMD_LMOTS_VERIFY ||
                         command_r == CMD_LMOTS_VERIFY_LEAF);
    wire         batch_cmd_w = command_r == CMD_LMOTS_KEYGEN ||
        command_r == CMD_LMOTS_SIGN || verify_cmd_w ||
        command_r == CMD_LMOTS_KEYGEN_LEAF;
    wire [8:0] batch_i1_w = batch_i_r + 9'd1;

    reg  [15:0] der_lfsr_r;
    reg  [8:0]  der_b_r;
    wire [8:0]  der_b_w = ((der_lfsr_r[7:0] % (w_p - 9'd1)) + 9'd1);   /* b in [1,p-1] */

    wire batch_start_w = (!INSECURE_TEST_MODE && command_r == CMD_LMOTS_SIGN) ?
        ksd_sign_dispatch_w : (ctrl_start_w && cmd_check_valid_w &&
        cmd_check_action_w == ACT_START && batch_cmd_w);
    function automatic [8:0] der_perm(input [8:0] der_x);
        reg [9:0] der_s, der_s1, der_s2;
        begin
            if (!DERIVE_SHUFFLE || verify_cmd_w) begin
                der_perm = der_x;
            end else begin
                der_s  = {1'b0, der_x} + der_b_r;                    /* ≤ 2p-2 */
                der_s1 = (der_s >= {1'b0, w_p}) ? der_s - {1'b0, w_p} : der_s;
                der_s2 = (der_s1 >= {1'b0, w_p}) ? der_s1 - {1'b0, w_p} : der_s1;
                der_perm = der_s2[8:0];
            end
        end
    endfunction

    wire [8:0] der_perm_bi_w   = der_perm(batch_i_r);
    wire [8:0] der_perm_bi1_w  = der_perm(batch_i1_w);
    wire [8:0] der_perm_fold_w = der_perm(fold_next_i_w);
    always @(posedge clk) begin
        if (rst) der_lfsr_r <= 16'hACE1;
        else     der_lfsr_r <= {der_lfsr_r[14:0],
                                der_lfsr_r[15] ^ der_lfsr_r[13] ^
                                der_lfsr_r[12] ^ der_lfsr_r[10]};
    end

    /* verilator lint_off BLKSEQ */
    always @(posedge clk) begin
        if (rst) der_b_r <= 9'd1;
        else if (batch_start_w) der_b_r = der_b_w;
    end
    /* verilator lint_on BLKSEQ */

    reg [7:0] batch_coefficient_w;
    reg [7:0] batch_coefficient1_w;
    always @* begin
        case (w_coef_bits)
            4'd1: begin
                batch_coefficient_w = {7'b0, coefficient_words[der_perm_bi_w[8:5]][der_perm_bi_w[4:0]]};
                batch_coefficient1_w = {7'b0, coefficient_words[der_perm_bi1_w[8:5]][der_perm_bi1_w[4:0]]};
            end
            4'd2: begin
                batch_coefficient_w = {6'b0, coefficient_words[der_perm_bi_w[8:4]][der_perm_bi_w[3:0] * 2 +: 2]};
                batch_coefficient1_w = {6'b0, coefficient_words[der_perm_bi1_w[8:4]][der_perm_bi1_w[3:0] * 2 +: 2]};
            end
            4'd4: begin
                batch_coefficient_w = {4'b0, coefficient_words[der_perm_bi_w[8:3]][der_perm_bi_w[2:0] * 4 +: 4]};
                batch_coefficient1_w = {4'b0, coefficient_words[der_perm_bi1_w[8:3]][der_perm_bi1_w[2:0] * 4 +: 4]};
            end
            default: begin
                batch_coefficient_w = coefficient_words[der_perm_bi_w[8:2]][der_perm_bi_w[1:0] * 8 +: 8];
                batch_coefficient1_w = coefficient_words[der_perm_bi1_w[8:2]][der_perm_bi1_w[1:0] * 8 +: 8];
            end
        endcase
    end

    wire core1_should_run = !SINGLE_CORE &&
        (batch_i1_w < w_p) &&
        (batch_phase_r == BATCH_DERIVE || chain_steps_left1_r != 8'd0);

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
    wire ksd_sign_request_w = ctrl_request_w && mask_ready_w &&
        cmd_check_valid_w && command_r == CMD_LMOTS_SIGN;
    wire ksd_output_hidden_w = !INSECURE_TEST_MODE &&
        (ksd_sign_cancelled_w || ksd_trusted_fault ||
         (bus_valid && bus_write && bus_addr[9:0] == 10'h240 && bus_wdata[1]));
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
    wire ksd_abort_write_w = bus_valid && bus_write && bus_addr[9:0] == 10'h240 && bus_wdata[1];
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
    lms_ksd_sign_adapter #(.HASH_ID(8'd2), .INSECURE_TEST_MODE(INSECURE_TEST_MODE)) u_ksd_adapter (
        .clk(clk), .rst(rst), .ksd_recover_valid(ksd_recover_valid),
        .ksd_recover_record(ksd_recover_record), .ksd_recover_accept(ksd_recover_accept),
        .ksd_ack_valid(ksd_ack_valid), .ksd_ack_record(ksd_ack_record),
        .ksd_ack_accept(ksd_ack_accept), .ksd_persist_valid(ksd_persist_valid),
        .ksd_persist_record(ksd_persist_record), .ksd_trusted_fault(ksd_trusted_fault),
        .bus_valid(bus_valid), .bus_write(bus_write), .bus_addr(bus_addr[9:0]),
        .bus_wdata(bus_wdata), .ksd_mmio_hit(ksd_mmio_hit_w), .ksd_mmio_rdata(ksd_mmio_rdata_w),
        .seed_valid(sec_seed_valid_w), .engine_quiescent(!physical_busy_w),
        .command(command_r), .arg_q(arg_q_r), .arg_w(arg_w_r), .identifier(sign_identifier_w),
        .mqc_context(sign_coef_context_r), .sign_request(ksd_sign_request_w),
        .sign_complete(command_r == CMD_LMOTS_SIGN && done_r && !physical_busy_w),
        .command_allowed(ksd_command_allowed_w), .sign_wait(ksd_sign_wait_w),
        .sign_dispatch(ksd_sign_dispatch_w), .sign_rejected(ksd_sign_rejected_w),
        .sign_cancelled(ksd_sign_cancelled_w), .registered(ksd_registered_w), .txn_state(ksd_txn_state_w)
    );
    /* Hardware coefficient provenance. This protects SIGN's digest/checksum
     * input; it is deliberately NOT evidence that a reservation is durable.
     * Public VERIFY may still supply coefficients, but any such write destroys
     * SIGN provenance. CLEAR and identical context writes remain legal between
     * MQC and SIGN, as required by the existing MMIO client. */
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
                sign_coef_context_r <= mqc_q_be_r;
            end
            if (bus_valid && bus_write) begin
                if ((bus_addr[9:0] == REG_CONTROL && (bus_wdata & CTRL_START) != 0) ||
                    (bus_addr[9:0] == REG_TASK_DATA && task_addr_r < 32) ||
                    (bus_addr[9:0] == REG_ARG_Q && bus_wdata != sign_coef_q_r) ||
                    (bus_addr[9:0] == REG_ARG_W && bus_wdata != {28'b0, sign_coef_w_r}) ||
                    (bus_addr[9:0] >= REG_IDENTIFIER && bus_addr[9:0] < REG_IDENTIFIER + 16 &&
                     bus_addr[1:0] == 0 &&
                     bus_wdata != sign_coef_identifier_r[bus_addr[3:2] * 32 +: 32])) begin
                    sign_coef_ready_r <= 1'b0;
                    sign_mqc_pending_r <= 1'b0;
                end
                if (bus_addr[9:0] == REG_CONTROL && (bus_wdata & CTRL_START) != 0)
                    sign_mqc_pending_r <= !wrapper_busy_w && mqc_cmd_w && cmd_check_valid_w;
            end
        end
    end

    lms_hash_cmd_check #(
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .HAS_SECURITY(HAS_SECURITY),
        .MAX_ONCE_BYTES(8'd128),
        .HAS_HASH_ONCE_RAM(1'b1),
        .MAX_ONCE_BYTES_RAM(12'd2048),
        .HAS_STATE_COMMIT(1'b1),
        .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE)
    ) u_cmd_check (
        .command(command_r),
        .input_length(input_length_r),
        .output_length(output_length_r),
        .arg_i({16'b0, arg_i_r}),
        .arg_start({24'b0, arg_start_r}),
        .arg_steps(arg_steps_r),
        .arg_key(arg_key_r),
        .seed_valid(sec_seed_valid_w),
        .k_wrap_valid(sec_k_wrap_valid_w),
        .k_state_valid(sec_k_state_valid_w),
        .sign_coef_valid(sign_coef_valid_w),
        .lmots_sign_y_len(w_p * 32),
        .valid(cmd_check_raw_valid_w),
        .error_code(cmd_check_raw_error_w),
        .action(cmd_check_action_w)
    );

    wire        sec_busy_w;
    wire        sec_done_w;
    wire        sec_error_valid_w;
    wire [31:0] sec_error_code_w;
    wire [31:0] sec_cycles_w;
    wire [255:0] sec_result_data_w;
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
    wire        sec_stc_w;
    wire [31:0] sec_stc_tx_w;
    wire [255:0] sec_k_wrap_w;
    wire [255:0] sec_k_state_w;
    wire [255:0] sec_wrap_ct_w;
    wire [255:0] sec_wrap_tag_w;
    wire [255:0] sec_wrap_mu_inner_w;
    wire [31:0]  sec_bus_rdata_w;

    wire sec_bus_hit_w =
        (bus_addr[9:0] == 10'h060) ||
        (bus_addr[9:0] >= 10'h080 && bus_addr[9:0] < 10'h080 + 32) ||
        (bus_addr[9:0] >= 10'h0a0 && bus_addr[9:0] < 10'h0a0 + 48) ||
        (bus_addr[9:0] >= 10'h0e0 && bus_addr[9:0] < 10'h0e0 + 32);
    wire sec_bus_valid_w = bus_valid && sec_bus_hit_w;

    wire ctrl_request_w = !wrapper_busy_w && bus_valid && bus_write &&
        bus_addr[9:0] == REG_CONTROL && (bus_wdata & CTRL_START) != 32'b0;
    wire mask_ready_w = !MASKED ||
        (rnd_block_valid_w && mask_seed_share_valid_w && !mask_drbg_fail_w);
    wire ctrl_start_w = ctrl_request_w && mask_ready_w && cmd_check_valid_w;

    wire rnd_apply_w = RANDOM_DELAY &&
                       (command_r == CMD_DERIVE_RANDOMIZER ||
                        (command_r == CMD_DERIVE_CHAIN && arg_steps_r == 32'd0));
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

    wire sec_cmd_pending_w = (command_r == CMD_MC_STEP || command_r == CMD_MC_LOAD ||
                              command_r == CMD_WRAP_SEED || command_r == CMD_UNWRAP_SEED ||
                              command_r == CMD_HMAC_KSTATE || command_r == CMD_STATE_COMMIT ||
                              command_r == CMD_SEED_LOAD);

    wire [255:0] sec_seed_flat_w;
    wire [255:0] sec_seed_flat_b_w;
    wire [255:0] sec_seed_data_b_w;

    wire [255:0] seed_flat_a_w = HAS_SECURITY ? sec_seed_flat_w : seed_a_r;
    wire [255:0] seed_flat_b_w = HAS_SECURITY ? sec_seed_flat_b_w : seed_b_r;

    wire        seed_dbg_en_w = INSECURE_TEST_MODE && bus_valid && !bus_write &&
                                (bus_addr[9:0] >= 10'h1c0) && (bus_addr[9:0] < 10'h1e0);
    wire [255:0] seed_xor_w = seed_dbg_en_w ? (sec_seed_data_w ^ sec_seed_data_b_w) : 256'b0;

    reg  [1087:0] sec_block0_w;
    reg  [1087:0] sec_block1_w;
    wire [1087:0] sec_block_w;
    integer sec_b0_i;
    integer sec_b1_i;

    generate
        if (HAS_SECURITY) begin : g_sec_on
            assign sec_block_w = (sec_block_index_w == 2'd0) ? sec_block0_w : sec_block1_w;
            assign sec_seed_flat_w = {
                sec_seed_data_w[231:224], sec_seed_data_w[239:232], sec_seed_data_w[247:240], sec_seed_data_w[255:248],
                sec_seed_data_w[199:192], sec_seed_data_w[207:200], sec_seed_data_w[215:208], sec_seed_data_w[223:216],
                sec_seed_data_w[167:160], sec_seed_data_w[175:168], sec_seed_data_w[183:176], sec_seed_data_w[191:184],
                sec_seed_data_w[135:128], sec_seed_data_w[143:136], sec_seed_data_w[151:144], sec_seed_data_w[159:152],
                sec_seed_data_w[103:96],  sec_seed_data_w[111:104], sec_seed_data_w[119:112], sec_seed_data_w[127:120],
                sec_seed_data_w[71:64],   sec_seed_data_w[79:72],   sec_seed_data_w[87:80],   sec_seed_data_w[95:88],
                sec_seed_data_w[39:32],   sec_seed_data_w[47:40],   sec_seed_data_w[55:48],   sec_seed_data_w[63:56],
                sec_seed_data_w[7:0],     sec_seed_data_w[15:8],    sec_seed_data_w[23:16],   sec_seed_data_w[31:24]};

            assign sec_seed_flat_b_w = {
                sec_seed_data_b_w[231:224], sec_seed_data_b_w[239:232], sec_seed_data_b_w[247:240], sec_seed_data_b_w[255:248],
                sec_seed_data_b_w[199:192], sec_seed_data_b_w[207:200], sec_seed_data_b_w[215:208], sec_seed_data_b_w[223:216],
                sec_seed_data_b_w[167:160], sec_seed_data_b_w[175:168], sec_seed_data_b_w[183:176], sec_seed_data_b_w[191:184],
                sec_seed_data_b_w[135:128], sec_seed_data_b_w[143:136], sec_seed_data_b_w[151:144], sec_seed_data_b_w[159:152],
                sec_seed_data_b_w[103:96],  sec_seed_data_b_w[111:104], sec_seed_data_b_w[119:112], sec_seed_data_b_w[127:120],
                sec_seed_data_b_w[71:64],   sec_seed_data_b_w[79:72],   sec_seed_data_b_w[87:80],   sec_seed_data_b_w[95:88],
                sec_seed_data_b_w[39:32],   sec_seed_data_b_w[47:40],   sec_seed_data_b_w[55:48],   sec_seed_data_b_w[63:56],
                sec_seed_data_b_w[7:0],     sec_seed_data_b_w[15:8],    sec_seed_data_b_w[23:16],   sec_seed_data_b_w[31:24]};

    lms_sha256_sec #(
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .HASH_TYPE(1),
        .SEED_SHARED(MASKED)
    ) u_sec (
        .clk(clk),
        .rst(rst),
        .bus_valid(sec_bus_valid_w),
        .bus_write(bus_write),
        .bus_addr(bus_addr[9:0]),
        .bus_wdata(bus_wdata),
        .bus_rdata(sec_bus_rdata_w),
        .reg_write_ok(!wrapper_busy_w),
        .seed_latch_en(seed_latch_en_w),
        .seed_share_in(seed_share_w),
        .kwrap_latch_en(kwrap_latch_en_w),
        .kstate_latch_en(kstate_latch_en_w),
        .mc_step_en(mc_step_en_w),
        .mc_load_en(mc_load_en_w),
        .mc_load_value(arg_q_r),
        .wrap_start(wrap_start_w),
        .wrap_is_unwrap(wrap_is_unwrap_w),
        .hmac_start(hmac_start_w),
        .input_length(input_length_r[7:0]),
        .stc_start(stc_start_w),
        .stc_state(arg_i_r),
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
        .seed_data_b(sec_seed_data_b_w),
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
        .core_busy(kec_ext_busy_w),
        .core_done(kec_ext_done_w),
        .core_digest(kec_digest_be_w)
    );

    wire         sec_mu_inner_phase_w = !sec_is_hmac_w && (sec_wrap_phase_w == 2'd0);
    wire         sec_inner_w   = sec_is_hmac_w ? (sec_wrap_phase_w == 2'd1)
                                               : ((sec_wrap_phase_w == 2'd0) ||
                                                  (sec_wrap_phase_w == 2'd2));
    wire [255:0] sec_key_w     = sec_is_hmac_w ? sec_k_state_w : sec_k_wrap_w;
    wire [7:0]   sec_pad_w     = sec_inner_w ? 8'h36 : 8'h5c;
    wire [7:0]   sec_msg_len_w = sec_mu_inner_phase_w ? 8'd11 :
                                 (sec_is_hmac_w && sec_inner_w) ?
                                 (sec_stc_w ? 8'd49 : input_length_r[7:0]) : 8'd32;

    wire [1087:0] sec_body_be_w;
    genvar sec_bd_i;
    for (sec_bd_i = 0; sec_bd_i < 4; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_magic
        assign sec_body_be_w[sec_bd_i * 8 +: 8] =
            (sec_bd_i == 0) ? 8'h4c : (sec_bd_i == 1) ? 8'h4d :
            (sec_bd_i == 2) ? 8'h53 : 8'h53;   /* "LMSS" */
    end
    for (sec_bd_i = 4; sec_bd_i < 6; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_state
        assign sec_body_be_w[sec_bd_i * 8 +: 8] =
            (sec_bd_i == 4) ? arg_i_r[15:8] : arg_i_r[7:0];   /* state BE */
    end
    for (sec_bd_i = 6; sec_bd_i < 10; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_ctr
        assign sec_body_be_w[sec_bd_i * 8 +: 8] =
            arg_q_r[(9 - sec_bd_i) * 8 +: 8];
    end
    for (sec_bd_i = 10; sec_bd_i < 14; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_tx
        assign sec_body_be_w[sec_bd_i * 8 +: 8] =
            sec_stc_tx_w[(13 - sec_bd_i) * 8 +: 8];
    end
    for (sec_bd_i = 14; sec_bd_i < 48; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_rsv
        assign sec_body_be_w[sec_bd_i * 8 +: 8] = 8'b0;   /* reserved */
    end
    for (sec_bd_i = 48; sec_bd_i < 49; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_aad
        assign sec_body_be_w[sec_bd_i * 8 +: 8] = arg_key_r[7:0];   /* aad=slot_id */
    end
    for (sec_bd_i = 49; sec_bd_i < 136; sec_bd_i = sec_bd_i + 1) begin : g_sec_body_z
        assign sec_body_be_w[sec_bd_i * 8 +: 8] = 8'b0;
    end

    wire [1087:0] sec_input_be_w;
    wire [1087:0] sec_wrap_ct_be_w;
    wire [1087:0] sec_wrap_tag_be_w;
    genvar sec_be_i;
    for (sec_be_i = 0; sec_be_i < 32; sec_be_i = sec_be_i + 1) begin : g_sec_be
            assign sec_wrap_ct_be_w[sec_be_i * 8 +: 8]  = sec_wrap_ct_w[255 - sec_be_i * 8 -: 8];
            assign sec_wrap_tag_be_w[sec_be_i * 8 +: 8] = sec_wrap_tag_w[255 - sec_be_i * 8 -: 8];
        end
        for (sec_be_i = 32; sec_be_i < 136; sec_be_i = sec_be_i + 1) begin : g_sec_be_z
            assign sec_wrap_ct_be_w[sec_be_i * 8 +: 8]  = 8'b0;
            assign sec_wrap_tag_be_w[sec_be_i * 8 +: 8] = 8'b0;
        end
        wire [1087:0] sec_mu_inner_be_w;
        for (sec_be_i = 0; sec_be_i < 32; sec_be_i = sec_be_i + 1) begin : g_sec_mu_be
            assign sec_mu_inner_be_w[sec_be_i * 8 +: 8] =
                sec_wrap_mu_inner_w[255 - sec_be_i * 8 -: 8];
        end
        for (sec_be_i = 32; sec_be_i < 136; sec_be_i = sec_be_i + 1) begin : g_sec_mu_be_z
            assign sec_mu_inner_be_w[sec_be_i * 8 +: 8] = 8'b0;
        end
        for (sec_be_i = 0; sec_be_i < 128; sec_be_i = sec_be_i + 1) begin : g_sec_in_be
            assign sec_input_be_w[sec_be_i * 8 +: 8] =
                input_flat_w[(sec_be_i / 4) * 32 + (sec_be_i % 4) * 8 +: 8];
        end
        for (sec_be_i = 128; sec_be_i < 136; sec_be_i = sec_be_i + 1) begin : g_sec_in_be_z
            assign sec_input_be_w[sec_be_i * 8 +: 8] = 8'b0;
        end

    wire [1087:0] sec_inner_msg_be_w;
    assign sec_inner_msg_be_w = sec_stc_w ? sec_body_be_w : sec_input_be_w;

    always @* begin
        sec_block0_w = 1088'b0;
        begin
            for (sec_b0_i = 0; sec_b0_i < 136; sec_b0_i = sec_b0_i + 1) begin
                if (sec_b0_i < 32)
                    sec_block0_w[sec_b0_i * 8 +: 8] =
                        sec_key_w[255 - sec_b0_i * 8 -: 8] ^ sec_pad_w;
                else
                    sec_block0_w[sec_b0_i * 8 +: 8] = sec_pad_w;
            end
        end
    end

    wire [1087:0] sec_label_w;
    for (sec_be_i = 0; sec_be_i < 136; sec_be_i = sec_be_i + 1) begin : g_sec_label
        if (sec_be_i == 0)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h4c;  /* L */
        else if (sec_be_i == 1)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h4d;  /* M */
        else if (sec_be_i == 2)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h53;  /* S */
        else if (sec_be_i == 3)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h57;  /* W */
        else if (sec_be_i == 4)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h52;  /* R */
        else if (sec_be_i == 5)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h41;  /* A */
        else if (sec_be_i == 6)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h50;  /* P */
        else if (sec_be_i == 7)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h2d;  /* - */
        else if (sec_be_i == 8)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h45;  /* E */
        else if (sec_be_i == 9)  assign sec_label_w[sec_be_i * 8 +: 8] = 8'h4e;  /* N */
        else if (sec_be_i == 10) assign sec_label_w[sec_be_i * 8 +: 8] = 8'h43;  /* C */
        else assign sec_label_w[sec_be_i * 8 +: 8] = 8'h00;
    end
    always @* begin
        sec_block1_w = 1088'b0;
        for (sec_b1_i = 0; sec_b1_i < 136; sec_b1_i = sec_b1_i + 1) begin
            if (sec_b1_i < sec_msg_len_w) begin
                if (sec_mu_inner_phase_w)
                    sec_block1_w[sec_b1_i * 8 +: 8] = sec_label_w[sec_b1_i * 8 +: 8];
                else if (sec_inner_w)
                    sec_block1_w[sec_b1_i * 8 +: 8] = sec_is_hmac_w ?
                        sec_inner_msg_be_w[sec_b1_i * 8 +: 8] :
                        sec_wrap_ct_be_w[sec_b1_i * 8 +: 8];
                else
                    sec_block1_w[sec_b1_i * 8 +: 8] =
                        (!sec_is_hmac_w && (sec_wrap_phase_w == 2'd1)) ?
                        sec_mu_inner_be_w[sec_b1_i * 8 +: 8] :
                        sec_wrap_tag_be_w[sec_b1_i * 8 +: 8];
            end else if (sec_b1_i == sec_msg_len_w) begin
                sec_block1_w[sec_b1_i * 8 +: 8] = 8'h1f;
            end else if (sec_b1_i == 135) begin
                sec_block1_w[sec_b1_i * 8 +: 8] = 8'h80;
            end
        end
    end
        end else begin : g_sec_off

            reg [31:0] sec_seed_words [0:7];
            reg        sec_seed_valid_r;
            integer    sec_wi;
            always @(posedge clk) begin
                if (rst) begin
                    sec_seed_valid_r <= 1'b0;
                    for (sec_wi = 0; sec_wi < 8; sec_wi = sec_wi + 1) begin
                        sec_seed_words[sec_wi] <= 32'b0;
                    end
                end else begin
                    if (bus_valid && bus_write &&
                        bus_addr[9:0] >= 10'h080 && bus_addr[9:0] < 10'h080 + 32) begin
                        sec_seed_words[(bus_addr[9:0] - 10'h080) >> 2] <= bus_wdata;
                    end
                    if (ctrl_start_w && cmd_check_action_w == ACT_DONE_SEED) begin
                        sec_seed_valid_r <= 1'b1;
                    end
                end
            end
            assign sec_seed_data_w = {sec_seed_words[0], sec_seed_words[1], sec_seed_words[2],
                                      sec_seed_words[3], sec_seed_words[4], sec_seed_words[5],
                                      sec_seed_words[6], sec_seed_words[7]};
            assign sec_seed_data_b_w = 256'b0;
            assign sec_seed_valid_w = sec_seed_valid_r;
            assign sec_seed_flat_w = sec_seed_data_w;
            assign sec_seed_flat_b_w = 256'b0;
            assign sec_busy_w = 1'b0;
            assign sec_done_w = 1'b0;
            assign sec_error_valid_w = 1'b0;
            assign sec_error_code_w = 32'b0;
            assign sec_cycles_w = 32'b0;
            assign sec_result_data_w = 256'b0;
            assign sec_result_wmask_w = 8'b0;
            assign sec_result_valid_w = 1'b0;
            assign sec_mc_next_value_w = 32'b0;
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
            assign sec_block_w = 1088'b0;
        end
    endgenerate

    always @(posedge clk) begin
        if (rst) begin
            rnd_block_r          <= 1088'b0;
            rnd_block_missing_r  <= 1'b0;
        end else begin
            if (bus_valid && bus_write && bus_addr[9:0] == REG_CONTROL &&
                bus_wdata == CTRL_CLEAR) begin
                rnd_block_missing_r <= 1'b0;
            end else if (ctrl_request_w && MASKED && !rnd_block_valid_w) begin
                rnd_block_missing_r <= 1'b1;
            end
            if (rnd_block_ack_w) begin
                rnd_block_r <= rnd_block_w;
            end
        end
    end

    wire sec_core_mode_w = sec_busy_w;
    wire kec_ext_mode_w =
        ((batch_cmd_w || dintr_cmd_w || hash_ram_cmd_w || mqc_cmd_w) && state_r != STATE_IDLE) ||
        sec_core_mode_w;

    wire         engine_busy_w;
    wire         engine_done_w;
    wire [255:0] engine_digest_w;
    wire [31:0]  engine_cycle_w;
    wire         unused_sha_ext_busy_w;
    wire         unused_sha_ext_done_w;
    wire [255:0] unused_sha_ext_digest_w;
    wire         unused_sha_ext1_busy_w;
    wire         unused_sha_ext1_done_w;
    wire [255:0] unused_sha_ext1_digest_w;
    wire         unused_kec_ext_busy_w;
    wire         unused_kec_ext_done_w;
    wire [255:0] unused_kec_ext_digest_w;

    wire [255:0] chain_value_in_w = {
        input_words[0][7:0], input_words[0][15:8], input_words[0][23:16], input_words[0][31:24],
        input_words[1][7:0], input_words[1][15:8], input_words[1][23:16], input_words[1][31:24],
        input_words[2][7:0], input_words[2][15:8], input_words[2][23:16], input_words[2][31:24],
        input_words[3][7:0], input_words[3][15:8], input_words[3][23:16], input_words[3][31:24],
        input_words[4][7:0], input_words[4][15:8], input_words[4][23:16], input_words[4][31:24],
        input_words[5][7:0], input_words[5][15:8], input_words[5][23:16], input_words[5][31:24],
        input_words[6][7:0], input_words[6][15:8], input_words[6][23:16], input_words[6][31:24],
        input_words[7][7:0], input_words[7][15:8], input_words[7][23:16], input_words[7][31:24]
    };

    wire [127:0] identifier_flat_w;
    wire [1023:0] input_flat_w;
    genvar flat_index;
    generate
        for (flat_index = 0; flat_index < 4; flat_index = flat_index + 1) begin : g_identifier_flat
            assign identifier_flat_w[flat_index * 32 +: 32] = identifier_words[flat_index];
        end
        for (flat_index = 0; flat_index < 32; flat_index = flat_index + 1) begin : g_input_flat
            assign input_flat_w[flat_index * 32 +: 32] = input_words[flat_index];
        end
    endgenerate

    wire [63:0] mask_share_w;

    wire [255:0] mask_seed_share_w;

    wire [1087:0] rnd_block_w;
    wire          rnd_block_valid_w;
    wire          rnd_block_ack_w;
    reg  [1087:0] rnd_block_r;
    reg           rnd_block_missing_r;

    wire        mask_drbg_health_w;
    wire        mask_drbg_fail_w;
    wire        mask_drbg_valid_w;
    wire        mask_seed_share_valid_w;
    wire [15:0] mask_reseed_count_w;

    generate
    if (MASKED) begin : g_mask_rng
        wire [63:0] mask_drbg_word_w;

        lms_mask_rng #(
            .TRNG_SIM_MODE(TRNG_SIM_MODE),
            .RESEED_TAKES(64)
        ) u_mask_rng (
            .clk(clk),
            .rst(rst),
            .mask_word(mask_drbg_word_w),
            .mask_valid(mask_drbg_valid_w),
            .seed_share(mask_seed_share_w),
            .seed_share_valid(mask_seed_share_valid_w),
            .rnd_block(rnd_block_w),
            .rnd_block_valid(rnd_block_valid_w),
            .rnd_block_ack(rnd_block_ack_w),
            .rnd_fail(mask_drbg_fail_w),
            .health_fail(mask_drbg_health_w),
            .reseed_count(mask_reseed_count_w)
        );

        assign mask_share_w    = mask_drbg_word_w;

        assign rnd_block_ack_w = ctrl_start_w && rnd_block_valid_w;

    end else begin : g_no_mask
        assign mask_share_w         = 64'b0;
        assign mask_seed_share_w    = 256'b0;
        assign rnd_block_w          = 1088'b0;
        assign rnd_block_valid_w    = 1'b0;
        assign rnd_block_ack_w      = 1'b0;
        assign mask_drbg_health_w   = 1'b0;
        assign mask_drbg_fail_w     = 1'b0;
        assign mask_drbg_valid_w    = 1'b0;
        assign mask_seed_share_valid_w = 1'b0;
        assign mask_reseed_count_w  = 16'd0;
    end
    endgenerate

    wire [255:0] seed_share_w = MASKED ? mask_seed_share_w : 256'b0;
    reg [255:0] seed_a_r;
    reg [255:0] seed_b_r;
    reg         seed_share_pending_r;

    always @(posedge clk) begin
        if (rst) begin
            seed_share_pending_r <= 1'b0;
            seed_a_r <= 256'b0;
            seed_b_r <= 256'b0;
        end else if (!HAS_SECURITY) begin
            if (ctrl_start_w && cmd_check_action_w == ACT_DONE_SEED) begin
                seed_share_pending_r <= 1'b1;
            end
            if (seed_share_pending_r) begin
                seed_share_pending_r <= 1'b0;
                seed_a_r <= MASKED ? (sec_seed_flat_w ^ seed_share_w) : sec_seed_flat_w;
                seed_b_r <= MASKED ? seed_share_w : 256'b0;
            end
        end
    end

    lms_hash_engine #(
        .HASH_TYPE(2'd1),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .SINGLE_CORE(SINGLE_CORE),
        .RANDOM_DELAY(RANDOM_DELAY),
        .MASKED(MASKED)                 ,
        .DBG_CORE1_SKEW(DBG_CORE1_SKEW),
        .DBG_DROP_CORE1_DONE(DBG_DROP_CORE1_DONE)
    ) u_engine (
        .clk(clk),
        .rst(rst),
        .start(engine_start_r),
        .command(command_r),
        .input_length(input_length_r[7:0]),
        .arg_q(arg_q_r),
        .arg_i(arg_i_r),
        .arg_start(arg_start_r),
        .arg_steps(arg_steps_r),
        .identifier_flat(identifier_flat_w),
        .chain_value_in(chain_value_in_w),
        .seed_flat(seed_flat_a_w),
        .seed_b(seed_flat_b_w),
        .input_words_flat(input_flat_w),
        .rnd_share(mask_share_w),
        .rnd_block(rnd_block_r),
        .sha_ext_mode(1'b0),
        .sha_ext_start(1'b0),
        .sha_ext_init(1'b0),
        .sha_ext_state_load(1'b0),
        .sha_ext_state_in(256'b0),
        .sha_ext_block(512'b0),
        .sha_ext_busy(unused_sha_ext_busy_w),
        .sha_ext_done(unused_sha_ext_done_w),
        .sha_ext_digest(unused_sha_ext_digest_w),
        .sha_ext1_start(1'b0),
        .sha_ext1_init(1'b0),
        .sha_ext1_state_load(1'b0),
        .sha_ext1_state_in(256'b0),
        .sha_ext1_block(512'b0),
        .sha_ext1_busy(unused_sha_ext1_busy_w),
        .sha_ext1_done(unused_sha_ext1_done_w),
        .sha_ext1_digest(unused_sha_ext1_digest_w),
        .kec_ext_mode(kec_ext_mode_w),
        .kec_ext_start(kec_start_w),
        .kec_ext_init(kec_init_w),
        .kec_ext_block(kec_block_w),
        .kec_ext_block_b(kec_block_b_w),
        .kec_ext_digest_public(kec_digest_public_w),
        .kec_ext_busy(kec_ext_busy_w),
        .kec_ext_done(kec_ext_done_w),
        .kec_ext_digest(kec_ext_digest_w),
        .kec_ext_digest_a(kec_ext_digest_a_w),
        .kec_ext_digest_b(kec_ext_digest_b_w),
        .kec_ext1_start(kec1_start_w),
        .kec_ext1_init(kec1_init_w),
        .kec_ext1_block(kec1_block_w),
        .kec_ext1_block_b(batch_block_b1_r),
        .kec_ext1_digest_public(kec1_digest_public_w),
        .kec_ext1_busy(kec_ext1_busy_w),
        .kec_ext1_done(kec_ext1_done_w),
        .kec_ext1_digest(kec_ext1_digest_w),
        .kec_ext1_digest_a(kec_ext1_digest_a_w),
        .kec_ext1_digest_b(kec_ext1_digest_b_w),
        .dbg_eng(eng_dbg),
        .busy(engine_busy_w),
        .done(engine_done_w),
        .digest_out(engine_digest_w),
        .cycle_count(engine_cycle_w)
    );

reg [17:0] busy_to_cnt_r;
reg        busy_to_mask_r;
always @(posedge clk) begin
    if (rst) begin
        busy_to_cnt_r  <= 18'd0;
        busy_to_mask_r <= 1'b0;
    end else if (state_r == STATE_IDLE) begin
        busy_to_cnt_r  <= 18'd0;
        busy_to_mask_r <= 1'b0;
    end else if (busy_to_cnt_r >= 18'd200000) begin
        busy_to_mask_r <= 1'b1;
    end else begin
        busy_to_cnt_r <= busy_to_cnt_r + 18'd1;
    end
end
// Keep command writes protected from the pending START through the final
// background write, including during single-core operation.
wire physical_busy_w = engine_start_r || engine_busy_w || (state_r != STATE_IDLE) || sec_busy_w || bg_busy_w;
wire wrapper_busy_w = physical_busy_w || ksd_sign_wait_w;

    wire busy_report_w = wrapper_busy_w;

    wire kec_ext_busy_w;
    wire kec_ext_done_w;
    wire [255:0] kec_ext_digest_w;
    wire [255:0] kec_ext_digest_a_w;
    wire [255:0] kec_ext_digest_b_w;
    reg  kec_digest_public_w;
    reg  kec1_digest_public_w;
    reg  kec_start_w;
    reg  kec_init_w;
    reg [1087:0] kec_block_w;
    reg [1087:0] kec_block_b_w;
    wire kec_ext1_busy_w;
    wire kec_ext1_done_w;
    wire [255:0] kec_ext1_digest_w;
    wire [255:0] kec_ext1_digest_a_w;
    wire [255:0] kec_ext1_digest_b_w;
    reg  kec1_start_w;
    reg  kec1_init_w;
    reg [1087:0] kec1_block_w;

    wire [255:0] kec_digest_be_w = {
        kec_ext_digest_w[7:0],   kec_ext_digest_w[15:8],  kec_ext_digest_w[23:16], kec_ext_digest_w[31:24],
        kec_ext_digest_w[39:32], kec_ext_digest_w[47:40], kec_ext_digest_w[55:48], kec_ext_digest_w[63:56],
        kec_ext_digest_w[71:64], kec_ext_digest_w[79:72], kec_ext_digest_w[87:80], kec_ext_digest_w[95:88],
        kec_ext_digest_w[103:96], kec_ext_digest_w[111:104], kec_ext_digest_w[119:112], kec_ext_digest_w[127:120],
        kec_ext_digest_w[135:128], kec_ext_digest_w[143:136], kec_ext_digest_w[151:144], kec_ext_digest_w[159:152],
        kec_ext_digest_w[167:160], kec_ext_digest_w[175:168], kec_ext_digest_w[183:176], kec_ext_digest_w[191:184],
        kec_ext_digest_w[199:192], kec_ext_digest_w[207:200], kec_ext_digest_w[215:208], kec_ext_digest_w[223:216],
        kec_ext_digest_w[231:224], kec_ext_digest_w[239:232], kec_ext_digest_w[247:240], kec_ext_digest_w[255:248]};
    wire address_hit = bus_valid && bus_addr[31:10] == SHAKE_BASE[31:10];
    assign mem_hit = address_hit;

    wire [255:0] chain_digest_be_w;
    wire [255:0] chain_digest_be_a_w;
    wire [255:0] chain_digest_be_b_w;
    wire [255:0] core0_next_value_w = kec_digest_public_w ? kec_digest_be_w : kec_ext_digest_a_w;
    wire [255:0] core0_next_value_b_w = kec_digest_public_w ? 256'b0 : kec_ext_digest_b_w;
    wire [255:0] core1_next_value_w = kec1_digest_public_w ? chain_digest_be_w : chain_digest_be_a_w;
    wire [255:0] core1_next_value_b_w = kec1_digest_public_w ? 256'b0 : chain_digest_be_b_w;

    always @* begin
        if (dintr_cmd_w && state_r == STATE_DINTR_LOAD_SIB)
            batch_task_type_w = 3'd6;
        else if (keygen_dleaf_r || fold_dleaf_w)
            batch_task_type_w = 3'd4;
        else if (fold_dc_w)
            batch_task_type_w = 3'd1;
        else if (fold_derive_any_w || fold_first_w)
            batch_task_type_w = 3'd2;
        else if (batch_phase_r == BATCH_CHAIN)
            batch_task_type_w = 3'd1;                  /* CHAIN */
        else
            batch_task_type_w = 3'd2;
    end
    wire batch_derive_phase_w = (batch_phase_r == BATCH_DERIVE) ||
                                fold_derive_any_w || fold_first_w;

    wire        dintr_swap_w       = dintr_node_r[0];
    wire [31:0] dintr_block_node_w = dintr_node_r >> 1;
    wire [31:0] dleaf_node_w = dintr_cmd_w ? dintr_block_node_w : arg_leaf_node_r;

    reg  core1_busy_d_r;
    reg  core1_done_seen_r;
    wire core1_fell_w = core1_busy_d_r & ~kec_ext1_busy_w;
    wire core1_done_eff_w = kec_ext1_done_w | core1_done_seen_r;
    always @(posedge clk) begin
        if (rst) begin
            core1_busy_d_r   <= 1'b0;
            core1_done_seen_r <= 1'b0;
        end else begin
            core1_busy_d_r <= kec_ext1_busy_w;
            if ((state_r == STATE_IDLE) || core1_kick_r) begin
                core1_done_seen_r <= 1'b0;
            end else if (kec_ext1_done_w || core1_fell_w) begin
                core1_done_seen_r <= 1'b1;
            end
        end
    end

    wire cores_done_w = (core0_done_latched_r || kec_ext_done_w) &&
                        (!dual_core1_active_r || core1_done_latched_r || core1_done_eff_w);

    wire [7:0] steps1_more_w = (DBG_STEPS1_STUCK != 0) ? DBG_STEPS1_STUCK[7:0]
                                                       : chain_steps_left1_r;
    wire chain_more_w = (chain_steps_left0_r > 8'd1) ||
                        ((steps1_more_w > 8'd1) && !SINGLE_CORE && dual_core1_active_r);
    wire fold_step_w = (!DISABLE_FOLD) && ((state_r == STATE_WAIT_CORE) && batch_cmd_w && !keygen_dleaf_r &&
                       (batch_phase_r == BATCH_CHAIN) && chain_more_w && cores_done_w);

    wire fold_dc_w = (!DISABLE_FOLD) && ((state_r == STATE_WAIT_CORE) && batch_cmd_w && !keygen_dleaf_r &&
                     (batch_phase_r == BATCH_DERIVE) && cores_done_w);

    wire bg_q_full_w = bg_q_valid[0] && bg_q_valid[1];

    wire sign_next_pair_done_w = (state_r == STATE_WAIT_CORE) && (command_r == CMD_LMOTS_SIGN) &&
                                 !keygen_dleaf_r && (batch_phase_r == BATCH_CHAIN) &&
                                 !chain_more_w && cores_done_w &&

                                 (!dual_core1_active_r || kec_ext1_done_w ||
                                  (steps1_more_w == 8'd0));
    wire sign_next_pair_stall_w = sign_next_pair_done_w && bg_q_full_w;
    wire sign_next_pair_w = sign_next_pair_done_w && !bg_q_full_w;

    wire bg_push_w = sign_next_pair_w;
    wire [255:0] bg_digest0_sel_w = chain0_zero_r ? chain_value0_r : kec_digest_be_w;
    wire [255:0] bg_digest1_sel_w = chain1_zero_r ? chain_value1_r : chain_digest_be_w;
    wire fold_derive_w = (!DISABLE_FOLD) && ((state_r == STATE_TASK_WRITE) && !verify_cmd_w &&
        ((!dual_write_sel_r && task_write_word0_r == 3'd7 && !dual_core1_active_r &&
          batch_i_r != (w_p - 9'd1)) ||
         (dual_write_sel_r && task_write_word1_r == 3'd7 && batch_i1_w != (w_p - 9'd1))));
    wire fold_derive_any_w = fold_derive_w || sign_next_pair_w;

    wire [8:0] fold_next_i_w = SINGLE_CORE
        ? ((batch_i_r >= (w_p - 9'd2)) ? (w_p - 9'd1) : (batch_i_r + 9'd1))
        : ((batch_i_r >= (w_p - 9'd3)) ? (w_p - 9'd1) : (batch_i_r + 9'd2));

    wire fold_first_w = (!DISABLE_FOLD) && ((state_r == STATE_IDLE) && batch_cmd_w && !verify_cmd_w);

    wire fold_dleaf_w = (!DISABLE_FOLD) && ((state_r == STATE_WAIT_CORE) && (batch_phase_r == BATCH_PBLC) &&
                        kec_ext_done_w && (pblc_final_block_r == w_pblc_last_block) &&
                        (command_r == CMD_LMOTS_KEYGEN_LEAF ||
                         command_r == CMD_LMOTS_VERIFY_LEAF));

    wire [255:0] dleaf_kq_fold_w = {
        kec_digest_be_w[255 - (7*32+24) -: 8], kec_digest_be_w[255 - (7*32+16) -: 8],
        kec_digest_be_w[255 - (7*32+8)  -: 8], kec_digest_be_w[255 - 7*32      -: 8],
        kec_digest_be_w[255 - (6*32+24) -: 8], kec_digest_be_w[255 - (6*32+16) -: 8],
        kec_digest_be_w[255 - (6*32+8)  -: 8], kec_digest_be_w[255 - 6*32      -: 8],
        kec_digest_be_w[255 - (5*32+24) -: 8], kec_digest_be_w[255 - (5*32+16) -: 8],
        kec_digest_be_w[255 - (5*32+8)  -: 8], kec_digest_be_w[255 - 5*32      -: 8],
        kec_digest_be_w[255 - (4*32+24) -: 8], kec_digest_be_w[255 - (4*32+16) -: 8],
        kec_digest_be_w[255 - (4*32+8)  -: 8], kec_digest_be_w[255 - 4*32      -: 8],
        kec_digest_be_w[255 - (3*32+24) -: 8], kec_digest_be_w[255 - (3*32+16) -: 8],
        kec_digest_be_w[255 - (3*32+8)  -: 8], kec_digest_be_w[255 - 3*32      -: 8],
        kec_digest_be_w[255 - (2*32+24) -: 8], kec_digest_be_w[255 - (2*32+16) -: 8],
        kec_digest_be_w[255 - (2*32+8)  -: 8], kec_digest_be_w[255 - 2*32      -: 8],
        kec_digest_be_w[255 - (1*32+24) -: 8], kec_digest_be_w[255 - (1*32+16) -: 8],
        kec_digest_be_w[255 - (1*32+8)  -: 8], kec_digest_be_w[255 - 1*32      -: 8],
        kec_digest_be_w[255 - (0*32+24) -: 8], kec_digest_be_w[255 - (0*32+16) -: 8],
        kec_digest_be_w[255 - (0*32+8)  -: 8], kec_digest_be_w[255 - 0*32      -: 8]};

    wire [255:0] dintr_right_bg_w = (state_r == STATE_DINTR_LOAD_SIB && dintr_load_word_r == 4'd7)
        ? {dintr_right_r[255:32],
           task_ram_read_r[7:0], task_ram_read_r[15:8],
           task_ram_read_r[23:16], task_ram_read_r[31:24]}
        : dintr_right_r;

    wire fold_load_w = (state_r == STATE_TASK_LOAD) && verify_dual_load_r &&
                       (task_write_word_r == 3'd7);
    wire [255:0] chain_value1_full_w = fold_load_w
        ? {chain_value1_r[255:32],
           task_ram_read_r[7:0], task_ram_read_r[15:8],
           task_ram_read_r[23:16], task_ram_read_r[31:24]}
        : chain_value1_r;

    wire [255:0] bg_chain_value0_w = (fold_step_w || fold_dc_w) ? core0_next_value_w
                                                                 : chain_value0_r;
    wire [255:0] bg_chain_value0_b_w = (fold_step_w || fold_dc_w) ? core0_next_value_b_w :
                                      (fold_load_w ? 256'b0 : chain_value0_b_r);
    wire [7:0]   bg_chain_j0_w     = fold_step_w ? (chain_j0_r + 8'd1) :
                                     (fold_dc_w ? 8'd0 :
                                      (fold_load_w ? batch_coefficient_w : chain_j0_r));
    wire [255:0] bg_chain_value1_w = (fold_step_w || fold_dc_w) ? core1_next_value_w
                                                                 : chain_value1_full_w;
    wire [255:0] bg_chain_value1_b_w = (fold_step_w || fold_dc_w) ? core1_next_value_b_w :
                                      (fold_load_w ? 256'b0 : chain_value1_b_r);
    wire [7:0]   bg_chain_j1_w     = fold_step_w ? (chain_j1_r + 8'd1) :
                                     (fold_dc_w ? 8'd0 :
                                      (fold_load_w ? batch_coefficient1_w : chain_j1_r));
    wire [8:0]   bg_batch_i_w      = fold_derive_any_w ? der_perm_fold_w :
                                     (fold_first_w ? (DERIVE_SHUFFLE ? der_b_w : 9'd0)
                                                   : der_perm_bi_w);

    wire [8:0]   bg_batch_i1_w     = (bg_batch_i_w == (w_p - 9'd1)) ? 9'd0 : bg_batch_i_w + 9'd1;

    reg fold_settle_r;

    reg [255:0] bg_q_d0 [0:1];
    reg [255:0] bg_q_d1 [0:1];
    reg [11:0]  bg_q_addr [0:1];
    reg [4:0]   bg_q_words [0:1];
    wire [8:0]  bg_pair_chains_w = (bg_q_words[0] == 5'd16) ? 9'd2 : 9'd1;
    wire [9:0]  result_count_next_w = {1'b0, result_count_r} + {1'b0, bg_pair_chains_w};
    reg         bg_q_valid [0:1];

    reg         bg_q_wrap [0:1];
    reg         bg_drain_active_r;
    reg [3:0]   bg_drain_idx_r;
    /* R6 Stage 1 result state machine: one owner for epoch/count/status/addr.
     * The consumer may set RESULT_ADDR or RELEASE while the engine is busy;
     * the pair-commit pulse is generated from the actual last background-write
     * word, not from the hash-core done or the push event. */
    wire r6_sign_start_w = INSECURE_TEST_MODE ?
        (ctrl_start_w && cmd_check_valid_w && command_r == CMD_LMOTS_SIGN) : ksd_sign_dispatch_w;
    wire r6_release_w = bus_valid && bus_write && bus_addr[9:0] == REG_RESULT_RELEASE;
    wire r6_addr_write_w = bus_valid && bus_write && bus_addr[9:0] == REG_RESULT_ADDR;
    /* R6 Stage 1b: RESULT_DATA reads auto-increment RESULT_ADDR, so a consumer
     * can burst an 8-word chain after one address write (same idea as
     * REG_TASK_DATA's auto-increment stream, but restricted to the y window). */
    wire r6_data_read_w = bus_valid && !bus_write && bus_addr[9:0] == REG_RESULT_DATA;
    /* The SoC holds bus_valid for two clocks per CPU read; increment once, on
     * the falling edge, after the consumer has sampled the stable data. */
    reg  r6_data_read_d;
    wire r6_data_read_end_w = r6_data_read_d && !r6_data_read_w;
    always @(posedge clk) begin
        if (rst) begin
            r6_data_read_d <= 1'b0;
        end else begin
            r6_data_read_d <= r6_data_read_w;
        end
    end
    wire r6_pair_expected_w = (bg_q_addr[0] ==
                               (12'd32 + {result_count_r, 3'b0}));
    wire r6_pair_commit_base_w = bg_drain_active_r &&
                                 ({1'b0, bg_drain_idx_r} + 5'd1 >= bg_q_words[0]) &&
                                 r6_pair_expected_w;
    wire r6_pair_commit_w = r6_pair_commit_base_w && !r6_commit_seen_r;
    reg  r6_commit_seen_r;
    wire r6_invalid_read_w = bus_valid && !bus_write &&
                             bus_addr[9:0] == REG_RESULT_DATA &&
                             result_active_r && !result_addr_valid_w;
    always @(posedge clk) begin
        if (rst) begin
            result_epoch_r  <= 32'b0;
            result_count_r  <= 9'b0;
            result_active_r <= 1'b0;
            result_done_r   <= 1'b0;
            result_error_r  <= 1'b0;
            result_length_r <= 12'b0;
            result_addr_r   <= 12'b0;
            r6_commit_seen_r <= 1'b0;
        end else if (r6_sign_start_w) begin
            result_epoch_r  <= result_epoch_r + 32'd1;
            result_count_r  <= 9'd0;
            result_active_r <= 1'b1;
            result_done_r   <= 1'b0;
            result_error_r  <= 1'b0;
            result_length_r <= {w_p, 3'b0};
            result_addr_r   <= 12'd0;
            r6_commit_seen_r <= 1'b0;
        end else if (r6_release_w) begin
            result_active_r <= 1'b0;
            result_done_r   <= 1'b0;
            result_error_r  <= 1'b0;
            result_count_r  <= 9'd0;
            result_addr_r   <= 12'd0;
            r6_commit_seen_r <= 1'b0;
        end else begin
            if (!bg_drain_active_r) begin
                r6_commit_seen_r <= 1'b0;
            end
            if (r6_addr_write_w && bus_wdata < 2152) begin
                result_addr_r <= bus_wdata[11:0];
            end else if (r6_data_read_end_w && result_addr_valid_w) begin
                /* Increment once per CPU read, after the data was sampled;
                 * clamp at the last word. */
                if (result_addr_r + 12'd1 < result_length_r) begin
                    result_addr_r <= result_addr_r + 12'd1;
                end
            end
            if (r6_pair_commit_w && result_active_r) begin
                r6_commit_seen_r <= 1'b1;
                result_count_r <= result_count_next_w[8:0];
                if (result_count_next_w >= {1'b0, w_p}) begin
                    result_done_r <= 1'b1;
                end
            end
            if (r6_invalid_read_w) begin
                result_error_r <= 1'b1;
            end
        end
    end

    wire bg_busy_w = bg_drain_active_r || bg_q_valid[0] || bg_q_valid[1];

    lms_shake256_blockgen u_batch_blockgen (
        .task_type(batch_task_type_w),
        .input_words_flat(input_flat_w),
        .identifier_flat(identifier_flat_w),
        .arg_q(arg_q_r),
        .arg_i({7'b0, bg_batch_i_w}),
        .chain_j(bg_chain_j0_w),
        .chain_value(bg_chain_value0_w),
        .chain_value_b(bg_chain_value0_b_w),
        .derive_phase(batch_derive_phase_w),
        .input_length(input_length_r[7:0]),
        .seed_a(seed_flat_a_w),
        .seed_b(seed_flat_b_w),
        .arg_leaf_node(dleaf_node_w),
        .dleaf_kq(fold_dleaf_w ? dleaf_kq_fold_w : dleaf_kq_w),
        .pblc_buffer(1088'b0),
        .pblc_fill(8'b0),
        .pblc_phase(1'b0),
        .dintr_left(dintr_cmd_w && dintr_swap_w ? dintr_right_bg_w : dintr_left_r),
        .dintr_right(dintr_cmd_w && dintr_swap_w ? dintr_left_r : dintr_right_bg_w),
        .rate_block(batch_rate_block_w),
        .rate_block_b(batch_rate_block_b_w),
        .rnd_block(rnd_block_r),
        .rate_init(batch_rate_init_w),
        .core_digest(kec_ext1_digest_w),
        .core_digest_a(kec_ext1_digest_a_w),
        .core_digest_b(kec_ext1_digest_b_w),
        .core_digest_c(256'b0),
        .digest_bigendian(chain_digest_be_w),
        .digest_bigendian_a(chain_digest_be_a_w),
        .digest_bigendian_b(chain_digest_be_b_w)
    );

    reg [1087:0] core1_block_w;
    reg [1087:0] core1_block_b_w;
    always @* begin
        core1_block_w = batch_rate_block_w;
        core1_block_b_w = batch_rate_block_b_w;
        core1_block_w[20 * 8 +: 8] = {7'b0, bg_batch_i1_w[8]} ^ rnd_block_r[20 * 8 +: 8];
        core1_block_w[21 * 8 +: 8] = bg_batch_i1_w[7:0] ^ rnd_block_r[21 * 8 +: 8];
        if ((batch_phase_r != BATCH_DERIVE && !fold_derive_any_w && !fold_first_w) || fold_dc_w) begin
            core1_block_w[22 * 8 +: 8] = bg_chain_j1_w ^ rnd_block_r[22 * 8 +: 8];
            for (bj = 0; bj < 32; bj = bj + 1) begin
                core1_block_w[(23 + bj) * 8 +: 8] = bg_chain_value1_w[255 - bj * 8 -: 8];
                core1_block_b_w[(23 + bj) * 8 +: 8] = bg_chain_value1_b_w[255 - bj * 8 -: 8];
            end
        end
    end

    always @* begin
        kec_digest_public_w = 1'b0;
        kec1_digest_public_w = 1'b0;
        if (sec_core_mode_w) begin
            kec_start_w  = sec_core_start_w;
            kec_init_w   = sec_core_init_w;
            kec_block_w  = sec_block_w;
            kec_block_b_w = 1088'b0;
            kec1_start_w = 1'b0;
            kec1_init_w  = 1'b0;
            kec1_block_w = 1088'b0;
            kec_digest_public_w = 1'b1;
        end else begin
            kec_start_w  = core0_kick_r && !c0_req_seen;
            kec_init_w   = core0_init_r;
            kec_block_w  = batch_block_r;
            kec_block_b_w = batch_block_b_r;
            kec1_start_w = core1_kick_r && !c1_req_seen;
            kec1_init_w  = core1_init_r;
            kec1_block_w = batch_block1_r;
            if (batch_cmd_w) begin
                if (batch_phase_r == BATCH_DERIVE) begin

                    kec_digest_public_w  = (command_r == CMD_LMOTS_SIGN) && (batch_coefficient_w  == 8'd0);
                    kec1_digest_public_w = (command_r == CMD_LMOTS_SIGN) && (batch_coefficient1_w == 8'd0);
                end else if (batch_phase_r == BATCH_CHAIN) begin
                    kec_digest_public_w  = (chain_steps_left0_r <= 8'd1);
                    kec1_digest_public_w = (chain_steps_left1_r <= 8'd1);
                end else begin
                    kec_digest_public_w  = 1'b1;
                    kec1_digest_public_w = 1'b1;
                end
            end else if (dintr_cmd_w || mqc_cmd_w || hash_ram_cmd_w) begin
                kec_digest_public_w = 1'b1;
            end
        end
    end

`ifndef SYNTHESIS
    reg dbg_b_ok_reported;
    reg dbg_b_zero_reported;
    always @(posedge clk) begin
        if (rst) begin
            dbg_b_ok_reported   <= 1'b0;
            dbg_b_zero_reported <= 1'b0;
        end else begin
            if (MASKED && batch_cmd_w && !sec_core_mode_w && !dbg_b_ok_reported && kec_start_w &&
                (batch_phase_r == BATCH_CHAIN) && (|kec_block_b_w)) begin
                dbg_b_ok_reported <= 1'b1;
                $display("ASSERT-OK: batch CHAIN block_b != 0 (mask R connected)");
            end
            if (MASKED && batch_cmd_w && !sec_core_mode_w && !dbg_b_zero_reported && kec_start_w &&
                (batch_phase_r == BATCH_CHAIN) && (kec_block_b_w == 1088'b0)) begin
                dbg_b_zero_reported <= 1'b1;
                $fatal(1, "ASSERT-FAIL: batch CHAIN block_b == 0 (mask missing)");
            end
        end
    end
`endif

    integer dl_k;
    integer out_oi;
    integer pblc_i;
    integer bj;
    always @(posedge clk) begin
        if (rst) begin
            command_r <= 32'b0;
            input_length_r <= 32'b0;
            output_length_r <= 32'b0;
            arg_q_r <= 32'b0;
            arg_i_r <= 16'b0;
            arg_start_r <= 8'b0;
            arg_steps_r <= 32'b0;
            error_r <= 32'b0;
            done_r <= 1'b0;
            engine_start_r <= 1'b0;
            arg_key_r <= 32'b0;
            arg_leaf_node_r <= 32'b0;
            arg_w_r <= 4'd4;
            state_r <= STATE_IDLE;
            block_index_r <= 2'b0;
            block_count_r <= 2'b0;
            cycle_count_r <= 32'b0;
            wait_core_to_r <= 18'd0;
            timeout_snap_r <= 64'b0;
            error_status_r <= 1'b0;
            busy_error_pending_r <= 1'b0;
            keygen_dleaf_r <= 1'b0;
            rnd_lfsr_r <= 16'hACE1;
            rnd_delay_r <= 10'd0;
            chain_value0_r <= 256'b0;
            chain_value1_r <= 256'b0;
            chain_value0_b_r <= 256'b0;
            chain_value1_b_r <= 256'b0;
            chain_j_r <= 8'b0;
            chain_j0_r <= 8'b0;
            chain_j1_r <= 8'b0;
            chain_steps_left0_r <= 8'b0;
            chain_steps_left1_r <= 8'b0;
            batch_phase_r <= BATCH_DERIVE;
            batch_i_r <= 9'b0;
            task_write_word_r <= 3'b0;
            task_write_word0_r <= 3'b0;
            task_write_word1_r <= 3'b0;
            task_digest0_r <= 256'b0;
            task_digest1_r <= 256'b0;
            batch_block_r <= 1088'b0;
            batch_block_b_r <= 1088'b0;
            batch_block1_r <= 1088'b0;
            batch_block_b1_r <= 1088'b0;
            core0_kick_r <= 1'b0;
            core1_kick_r <= 1'b0;
            core0_kick_q <= 1'b0;
            core1_kick_q <= 1'b0;
            core0_init_r <= 1'b0;
            core1_init_r <= 1'b0;
            core0_done_latched_r <= 1'b0;
            core1_done_latched_r <= 1'b0;
            dual_write_sel_r <= 1'b0;
            verify_dual_load_r <= 1'b0;
            dual_core1_active_r <= 1'b0;
            chain0_zero_r <= 1'b0;
            chain1_zero_r <= 1'b0;
            fold_settle_r <= 1'b0;
            task_prefetch_pending_r <= 1'b0;
            pblc_final_block_r <= 7'd0;
            pblc_final_word_r <= 6'd0;
            pblc_final_window_r <= 1120'b0;
            dintr_left_r <= 256'b0;
            dintr_right_r <= 256'b0;
            dintr_node_r <= 32'b0;
            dintr_layer_r <= 5'b0;
            dintr_load_word_r <= 4'b0;
        end else begin
            engine_start_r <= 1'b0;
            task_prefetch_pending_r <= 1'b0;

            core0_kick_q <= core0_kick_r;
            core1_kick_q <= core1_kick_r;
            if (!core0_kick_r) c0_req_seen <= 1'b0; else if (kec_start_w) c0_req_seen <= 1'b1;
            if (!core1_kick_r) c1_req_seen <= 1'b0; else if (kec1_start_w) c1_req_seen <= 1'b1;

            if (kec_ext_done_w) core0_kick_q <= 1'b0;
            if (core1_done_eff_w) core1_kick_q <= 1'b0;

            rnd_lfsr_r <= {rnd_lfsr_r[14:0],
                           rnd_lfsr_r[15] ^ rnd_lfsr_r[13] ^
                           rnd_lfsr_r[12] ^ rnd_lfsr_r[10]};

            if (state_r == STATE_RND_DELAY) begin
                if (rnd_delay_r == 10'd0) begin
                    engine_start_r <= 1'b1;
                    state_r <= STATE_IDLE;
                end else begin
                    rnd_delay_r <= rnd_delay_r - 10'd1;
                end
            end

            if (engine_done_w) begin
                for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                    output_words[out_oi[2:0]] <= {
                        engine_digest_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                        engine_digest_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                        engine_digest_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                        engine_digest_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                end
                done_r <= 1'b1;
            end

            if (sec_done_w) begin

                if (busy_error_pending_r) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b1;
                    error_r <= ERR_BUSY;
                end else begin
                    done_r <= 1'b1;
                end
                cycle_count_r <= sec_cycles_w;
                if (busy_error_pending_r) begin

                end else if (sec_error_valid_w) begin
                    error_status_r <= 1'b1;
                    error_r <= sec_error_code_w;
                end else begin
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
                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                            output_words[out_oi] <= sec_result_data_w[255 - out_oi * 32 -: 32];
                        end
                    end
                end
            end

            if (!wrapper_busy_w && bus_valid && bus_write) begin
                case (bus_addr[9:0])
                    REG_COMMAND: command_r <= bus_wdata;
                    REG_INPUT_LENGTH: input_length_r <= bus_wdata;
                    REG_OUTPUT_LENGTH: output_length_r <= bus_wdata;
                    REG_ARG_Q: arg_q_r <= bus_wdata;
                    REG_ARG_I: arg_i_r <= bus_wdata[15:0];
                    REG_ARG_START: arg_start_r <= bus_wdata[7:0];
                    REG_ARG_STEPS: arg_steps_r <= bus_wdata;
                    REG_ARG_KEY: arg_key_r <= bus_wdata;
                    REG_ARG_LEAF_NODE: arg_leaf_node_r <= bus_wdata;
                    REG_ARG_W: arg_w_r <= bus_wdata[3:0];
                    REG_TASK_ADDR: begin

                        if (!stream_wr_en && !stream_rd_en &&
                            bus_wdata >= 32 && bus_wdata < 2152) begin
                            task_prefetch_pending_r <= 1'b1;
                        end
                    end
                    REG_TASK_DATA: begin
                        if (!stream_wr_en && !stream_rd_en &&
                            task_addr_r < 32) coefficient_words[task_addr_r[4:0]] <= bus_wdata;
                    end
                    REG_IDENTIFIER: identifier_words[0] <= bus_wdata;
                    REG_IDENTIFIER + 4: identifier_words[1] <= bus_wdata;
                    REG_IDENTIFIER + 8: identifier_words[2] <= bus_wdata;
                    REG_IDENTIFIER + 12: identifier_words[3] <= bus_wdata;

                    default: begin
                        if (bus_addr[9:0] >= REG_INPUT_BASE &&
                            bus_addr[9:0] < REG_INPUT_BASE + 128) begin
                            input_words[(bus_addr[9:0] - REG_INPUT_BASE) >> 2] <= bus_wdata;
                        end
                    end
                endcase
            end

            /* R6 Stage 1 result-window state is driven by the dedicated result
             * state machine below (single owner, not this register-write block). */

            if (mqc_cmd_w && state_r == STATE_MQC_COEF) begin
                case (mqc_word_idx_r)
                    9'd0: case (w_coef_bits)
                        4'd1: coefficient_words[0][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[0][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[0][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[0][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd1: case (w_coef_bits)
                        4'd1: coefficient_words[1][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[1][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[1][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[1][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd2: case (w_coef_bits)
                        4'd1: coefficient_words[2][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[2][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[2][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[2][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd3: case (w_coef_bits)
                        4'd1: coefficient_words[3][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[3][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[3][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[3][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd4: case (w_coef_bits)
                        4'd1: coefficient_words[4][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[4][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[4][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[4][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd5: case (w_coef_bits)
                        4'd1: coefficient_words[5][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[5][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[5][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[5][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd6: case (w_coef_bits)
                        4'd1: coefficient_words[6][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[6][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[6][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[6][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd7: case (w_coef_bits)
                        4'd1: coefficient_words[7][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[7][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[7][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[7][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    9'd8: case (w_coef_bits)
                        4'd1: coefficient_words[8][mqc_shift_r] <= mqc_digit_w[0];
                        4'd2: coefficient_words[8][mqc_shift_r +: 2] <= mqc_digit_w[1:0];
                        4'd4: coefficient_words[8][mqc_shift_r +: 4] <= mqc_digit_w[3:0];
                        default: coefficient_words[8][mqc_shift_r +: 8] <= mqc_digit_w;
                    endcase
                    default: ;
                endcase
            end

            if ((!wrapper_busy_w && bus_valid && bus_write &&
                bus_addr[9:0] == REG_CONTROL) || ksd_sign_dispatch_w) begin
                if (bus_wdata == CTRL_CLEAR && !ksd_sign_dispatch_w) begin
                    done_r <= 1'b0;
                    error_status_r <= 1'b0;
                    error_r <= 32'b0;
                    cycle_count_r <= 32'b0;
                    busy_error_pending_r <= 1'b0;
                end else if ((bus_wdata & CTRL_START) || ksd_sign_dispatch_w) begin
                    done_r <= 1'b0;
                    error_r <= 32'b0;
                    if (!ksd_sign_dispatch_w && !cmd_check_valid_w) begin

                        error_status_r <= 1'b1;
                        error_r <= cmd_check_error_w;
                    end else if ((!ksd_sign_dispatch_w && !mask_ready_w) ||
                                 (ksd_sign_dispatch_w && MASKED && mask_drbg_fail_w)) begin
                        /* SIGN consumed and latched its R at the request beat.
                         * The delayed dispatch uses that immutable R; requiring
                         * the next pool block here would falsely reject it. */
                        error_status_r <= 1'b1;
                        error_r <= ERR_MASK_NOT_READY;
                    end else if (!INSECURE_TEST_MODE && command_r == CMD_LMOTS_SIGN && !ksd_sign_dispatch_w) begin
                        /* Request only: the controller dispatch starts work. */
                    end else begin
                        case (cmd_check_action_w)
                        ACT_START: begin
                            if (dintr_cmd_w) begin

                                cycle_count_r <= 32'd1;
                                        wait_core_to_r <= 18'd0;
                                dintr_layer_r <= 5'd0;
                                dintr_load_word_r <= 4'd0;
                                dintr_node_r <= arg_leaf_node_r;
                                state_r <= STATE_DINTR_PREFETCH;
                            end else if (batch_cmd_w) begin

                                batch_i_r <= 9'd0;
                                wait_core_to_r <= 18'd0;
                                pblc_final_block_r <= 7'd0;
                                pblc_final_word_r <= 6'd0;
                                pblc_final_window_r <= 1120'b0;
                                keygen_dleaf_r <= 1'b0;
                                cycle_count_r <= 32'd1;
                                chain_value0_r <= 256'b0;
                                chain_value1_r <= 256'b0;
                                chain_value0_b_r <= 256'b0;
                                chain_value1_b_r <= 256'b0;
                                chain_j0_r <= 8'b0;
                                chain_j1_r <= 8'b0;
                                chain_steps_left0_r <= 8'b0;
                                chain_steps_left1_r <= 8'b0;
                                core0_done_latched_r <= 1'b0;
                                core1_done_latched_r <= 1'b0;
                                dual_write_sel_r <= 1'b0;
                                verify_dual_load_r <= 1'b0;

                                core0_kick_r <= 1'b0;
                                core1_kick_r <= 1'b0;
                                core0_kick_q <= 1'b0;
                                core1_kick_q <= 1'b0;
                                if (verify_cmd_w) begin
                                    batch_phase_r <= BATCH_CHAIN;
                                    task_write_word_r <= 3'd0;
                                    state_r <= STATE_TASK_PREFETCH;
                                end else begin
                                    batch_phase_r <= BATCH_DERIVE;

                                    if (fold_first_w) begin
                                        batch_block_r  <= batch_rate_block_w;
                                        batch_block1_r <= core1_block_w;
                                        batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                        core0_init_r  <= batch_rate_init_w;
                                        core1_init_r  <= batch_rate_init_w;
                                        core0_kick_r <= 1'b1;
                                        fold_settle_r <= 1'b1;
                                        core0_done_latched_r <= 1'b0;
                                        dual_core1_active_r <= (9'd1 < w_p) && !SINGLE_CORE;
                                        if ((9'd1 < w_p) && !SINGLE_CORE) begin
                                            core1_kick_r <= 1'b1;
                                            fold_settle_r <= 1'b1;
                                            core1_done_latched_r <= 1'b0;
                                        end else begin
                                            core1_kick_r <= 1'b0;
                                            core1_done_latched_r <= 1'b1;
                                        end
                                        state_r <= STATE_WAIT_CORE;
                                    end else begin
                                        state_r <= STATE_START_CORE;
                                    end
                                end
                            end else if (hash_ram_path_w) begin

                                hash_ram_block_r <= 4'd0;
                                hash_ram_word_r <= 6'd0;
                                hash_ram_kicked_r <= 1'b0;
                                hash_ram_full_r <= input_length_r[11:0] / 12'd136;
                                hash_ram_rem_r  <= input_length_r[11:0] % 12'd136;
                                pblc_final_window_r <= 1120'b0;
                                mqc_q_be_r <= 256'b0;
                                mqc_cs_be_r <= 16'b0;
                                mqc_checksum_r <= 16'd0;
                                mqc_idx_r <= 9'd0;
                                mqc_shift_r <= 5'd0;
                                mqc_word_idx_r <= 9'd0;
                                cycle_count_r <= 32'd1;
                                state_r <= STATE_TASK_PREFETCH;
                            end else begin

                                if (rnd_apply_w) begin

                                    rnd_delay_r <= {1'b1, rnd_lfsr_r[8:0]};
                                    state_r <= STATE_RND_DELAY;
                                end else begin
                                    engine_start_r <= 1'b1;
                                end
                            end
                        end
                        ACT_DONE_SEED: begin

                            cycle_count_r <= 32'd1;
                            done_r <= 1'b1;

                        end
                        ACT_DONE_CHAIN0: begin
                            output_words[0] <= input_words[0];
                            output_words[1] <= input_words[1];
                            output_words[2] <= input_words[2];
                            output_words[3] <= input_words[3];
                            output_words[4] <= input_words[4];
                            output_words[5] <= input_words[5];
                            output_words[6] <= input_words[6];
                            output_words[7] <= input_words[7];
                            done_r <= 1'b1;
                        end
                        ACT_DONE_KWRAP: begin

                            cycle_count_r <= 32'd1;
                            done_r <= 1'b1;
                        end
                        ACT_DONE_KSTATE: begin

                            cycle_count_r <= 32'd1;
                            done_r <= 1'b1;
                        end
                        ACT_DONE_MC: begin

                            cycle_count_r <= 32'd1;
                            if (command_r == CMD_MC_STEP) begin
                                output_words[0] <= sec_mc_next_value_w;
                            end else begin
                                output_words[0] <= arg_q_r;
                            end
                            done_r <= 1'b1;
                        end
                        ACT_START_HMAC: begin

                        end
                        ACT_START_WRAP: begin

                        end
                        default: error_r <= ERR_UNSUPPORTED_COMMAND;
                    endcase
                end
            end
            end

            if (ksd_sign_rejected_w) begin
                done_r <= 1'b0;
                error_status_r <= 1'b1;
                error_r <= 32'd18;
            end

            if (batch_cmd_w || dintr_cmd_w || hash_ram_cmd_w || mqc_cmd_w) begin
                case (state_r)
                    STATE_MQC_COEF: begin

                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (mqc_idx_r < mqc_u_w) begin
                            mqc_checksum_r <= mqc_checksum_r + (w_max_step - mqc_digit_w);
                            if (mqc_idx_r == mqc_u_w - 9'd1) begin

                                mqc_cs_be_r <= {mqc_cs_final_w[15:8], mqc_cs_final_w[7:0]};
                            end
                        end

                        if ({1'b0, mqc_shift_r} == 6'd32 - {1'b0, w_coef_bits}) begin
                            mqc_shift_r <= 5'd0;
                            mqc_word_idx_r <= mqc_word_idx_r + 9'd1;
                        end else begin
                            mqc_shift_r <= mqc_shift_r + {1'b0, w_coef_bits};
                        end
                        if (mqc_idx_r == w_p - 9'd1) begin
                            state_r <= STATE_IDLE;
                            done_r <= 1'b1;
                        end else begin
                            mqc_idx_r <= mqc_idx_r + 9'd1;
                        end
                    end
                    STATE_START_CORE: begin

                        cycle_count_r <= cycle_count_r + 32'd1;
                        batch_block_r  <= batch_rate_block_w;
                        batch_block1_r <= core1_block_w;
                        batch_block_b1_r <= core1_block_b_w;
                        batch_block_b_r <= batch_rate_block_b_w;
                        if (keygen_dleaf_r) begin
                            core0_kick_r  <= 1'b1;
                            core1_kick_r  <= 1'b0;
                            core0_init_r  <= 1'b1;
                            core1_init_r  <= 1'b0;
                            dual_core1_active_r <= 1'b0;
                        end else begin

                            core0_init_r  <= batch_rate_init_w;
                            core1_init_r  <= batch_rate_init_w;

                            dual_core1_active_r <= (batch_i1_w < w_p) && !SINGLE_CORE;
                            if (batch_phase_r == BATCH_DERIVE || chain_steps_left0_r != 8'd0) begin
                                core0_kick_r <= 1'b1;
                                fold_settle_r <= 1'b1;
                                core0_done_latched_r <= 1'b0;
                            end else begin

                                core0_kick_r <= 1'b0;
                                core0_done_latched_r <= 1'b1;
                            end
                            if (core1_should_run) begin
                                core1_kick_r <= 1'b1;
                                fold_settle_r <= 1'b1;
                                core1_done_latched_r <= 1'b0;
                            end else begin
                                core1_kick_r <= 1'b0;
                                if (batch_i1_w < w_p && batch_phase_r != BATCH_DERIVE &&
                                    chain_steps_left1_r == 8'd0) begin
                                    core1_done_latched_r <= 1'b1;
                                end
                            end
                        end
                        state_r <= STATE_WAIT_CORE;
                    end
                    STATE_WAIT_CORE: begin
                        cycle_count_r <= cycle_count_r + 32'd1;

                        core0_kick_r <= 1'b0;
                        core1_kick_r <= 1'b0;
                        if (fold_settle_r) begin

                            fold_settle_r <= 1'b0;
                        end else if (keygen_dleaf_r) begin

                            if (kec_ext_done_w) begin
                                keygen_dleaf_r <= 1'b0;
                                for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                    output_words[out_oi[2:0]] <= {
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                        kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                end
                                state_r <= STATE_IDLE;
                                done_r <= 1'b1;
                            end
                        end else if (batch_phase_r == BATCH_PBLC) begin

                            if (kec_ext_done_w) begin
                                if (pblc_final_block_r == w_pblc_last_block) begin

                                    if (command_r == CMD_LMOTS_KEYGEN_LEAF ||
                                        command_r == CMD_LMOTS_VERIFY_LEAF) begin
                                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                            output_words[out_oi[2:0]] <= {
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                                kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                        end
                                        keygen_dleaf_r <= 1'b1;
                                        block_count_r <= 2'd1;
                                        block_index_r <= 2'd0;

                                        batch_block_r  <= batch_rate_block_w;
                                        batch_block1_r <= core1_block_w;
                                        batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                        core0_init_r  <= batch_rate_init_w;
                                        core1_init_r  <= 1'b0;
                                        core0_kick_r <= 1'b1;
                                        fold_settle_r <= 1'b1;
                                        core1_kick_r <= 1'b0;
                                        core0_done_latched_r <= 1'b0;
                                        core1_done_latched_r <= 1'b0;
                                        dual_core1_active_r <= 1'b0;
                                        fold_settle_r <= 1'b1;
                                        state_r <= STATE_WAIT_CORE;
                                    end else begin
                                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                            output_words[out_oi[2:0]] <= {
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                                kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                        end
                                        state_r <= STATE_IDLE;
                                        done_r <= 1'b1;
                                    end
                                end else begin

                                    pblc_final_block_r <= pblc_final_block_r + 1'b1;
                                    state_r <= STATE_TASK_PREFETCH;
                                end
                            end
                        end else begin

                            if (kec_ext_done_w) begin
                                core0_done_latched_r <= 1'b1;
                            end
                            if (dual_core1_active_r) begin
                                if (core1_done_eff_w) begin
                                    core1_done_latched_r <= 1'b1;
                                end
                            end
                            if ((core0_done_latched_r || kec_ext_done_w) && !kec_ext_busy_w) begin
                                if (!dual_core1_active_r ||
                                    ((core1_done_latched_r || core1_done_eff_w) && !kec_ext1_busy_w)) begin
                                    if (!sign_next_pair_stall_w) begin
                                    core0_done_latched_r <= 1'b0;
                                    core1_done_latched_r <= 1'b0;
                                    end
                                    if (command_r == CMD_LMOTS_SIGN) begin

                                        if (batch_phase_r == BATCH_DERIVE) begin
                                            chain_value0_r <= core0_next_value_w;
                                            chain_value0_b_r <= core0_next_value_b_w;
                                            chain_value1_r <= core1_next_value_w;
                                            chain_value1_b_r <= core1_next_value_b_w;
                                            chain_j0_r <= 8'd0;
                                            chain_j1_r <= 8'd0;
                                            chain_steps_left0_r <= batch_coefficient_w;
                                            chain_steps_left1_r <= batch_coefficient1_w;
                                            chain0_zero_r <= (batch_coefficient_w == 0);
                                            chain1_zero_r <= (batch_coefficient1_w == 0);
                                            batch_phase_r <= BATCH_CHAIN;

                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            if (batch_coefficient_w != 0) begin
                                                core0_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core0_done_latched_r <= 1'b0;
                                            end else begin
                                                core0_kick_r <= 1'b0;
                                                core0_done_latched_r <= 1'b1;
                                            end
                                            if (batch_i1_w < w_p && batch_coefficient1_w != 0 && !SINGLE_CORE) begin
                                                core1_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                if (batch_i1_w < w_p && !SINGLE_CORE) begin
                                                    core1_done_latched_r <= 1'b1;
                                                end
                                            end
                                            fold_settle_r <= 1'b1;
                                            state_r <= STATE_WAIT_CORE;
                                        end else if (chain_steps_left0_r > 8'd1 ||
                                                     chain_steps_left1_r > 8'd1) begin
                                            if (chain_steps_left0_r > 8'd0) begin
                                                chain_value0_r <= core0_next_value_w;
                                            chain_value0_b_r <= core0_next_value_b_w;
                                                chain_j0_r <= chain_j0_r + 1'b1;
                                                chain_steps_left0_r <= chain_steps_left0_r - 1'b1;
                                            end
                                            if (chain_steps_left1_r > 8'd0) begin
                                                chain_value1_r <= core1_next_value_w;
                                            chain_value1_b_r <= core1_next_value_b_w;
                                                chain_j1_r <= chain_j1_r + 1'b1;
                                                chain_steps_left1_r <= chain_steps_left1_r - 1'b1;
                                            end

                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            if (chain_steps_left0_r > 8'd1) begin
                                                core0_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core0_done_latched_r <= 1'b0;
                                            end else begin
                                                core0_kick_r <= 1'b0;
                                                core0_done_latched_r <= 1'b1;
                                            end
                                            if (batch_i1_w < w_p && chain_steps_left1_r > 8'd1 && !SINGLE_CORE) begin
                                                core1_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                if (batch_i1_w < w_p && chain_steps_left1_r <= 8'd1) begin

                                                    core1_done_latched_r <= 1'b1;
                                                end
                                            end
                                            fold_settle_r <= 1'b1;
                                            state_r <= STATE_WAIT_CORE;
                                        end else begin
                                            if (!sign_next_pair_stall_w) begin

                                            if (batch_i1_w >= w_p) begin
                                                state_r <= STATE_IDLE;
                                                done_r <= 1'b1;
                                            end else begin

                                                batch_i_r <= fold_next_i_w;
                                                batch_phase_r <= BATCH_DERIVE;
                                                batch_block_r  <= batch_rate_block_w;
                                                batch_block1_r <= core1_block_w;
                                                batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                                core0_init_r  <= batch_rate_init_w;
                                                core1_init_r  <= batch_rate_init_w;
                                                core0_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core0_done_latched_r <= 1'b0;
                                                dual_core1_active_r <= ((fold_next_i_w + 9'd1) < w_p) && !SINGLE_CORE;
                                                if ((fold_next_i_w + 9'd1) < w_p && !SINGLE_CORE) begin
                                                    core1_kick_r <= 1'b1;
                                                    fold_settle_r <= 1'b1;
                                                    core1_done_latched_r <= 1'b0;
                                                end else begin
                                                    core1_kick_r <= 1'b0;
                                                    core1_done_latched_r <= 1'b1;
                                                end
                                                fold_settle_r <= 1'b1;
                                                state_r <= STATE_WAIT_CORE;
                                            end
                                            end
                                        end
                                    end else begin

                                        if (batch_phase_r == BATCH_DERIVE) begin

                                            dual_core1_active_r <=
                                                (batch_i1_w < w_p) && !SINGLE_CORE;
                                            chain_value0_r <= core0_next_value_w;
                                            chain_value0_b_r <= core0_next_value_b_w;
                                            chain_value1_r <= core1_next_value_w;
                                            chain_value1_b_r <= core1_next_value_b_w;
                                            chain_j0_r <= 8'd0;
                                            chain_j1_r <= 8'd0;
                                            chain_steps_left0_r <= w_max_step;
                                            chain_steps_left1_r <= w_max_step;
                                            chain0_zero_r <= 1'b0;
                                            chain1_zero_r <= 1'b0;
                                            batch_phase_r <= BATCH_CHAIN;

                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            core0_kick_r <= 1'b1;
                                            fold_settle_r <= 1'b1;
                                            core0_done_latched_r <= 1'b0;
                                            if (batch_i1_w < w_p && !SINGLE_CORE) begin
                                                core1_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                core1_done_latched_r <= 1'b1;
                                            end
                                            fold_settle_r <= 1'b1;
                                            state_r <= STATE_WAIT_CORE;
                                        end else if (batch_phase_r == BATCH_CHAIN &&
                                                     (chain_steps_left0_r > 8'd1 ||
                                                      (chain_steps_left1_r > 8'd1 && !SINGLE_CORE))) begin
                                            if (chain_steps_left0_r > 8'd0) begin
                                                chain_value0_r <= core0_next_value_w;
                                            chain_value0_b_r <= core0_next_value_b_w;
                                                chain_j0_r <= chain_j0_r + 1'b1;
                                                chain_steps_left0_r <= chain_steps_left0_r - 1'b1;
                                            end
                                            if (chain_steps_left1_r > 8'd0) begin
                                                chain_value1_r <= core1_next_value_w;
                                            chain_value1_b_r <= core1_next_value_b_w;
                                                chain_j1_r <= chain_j1_r + 1'b1;
                                                chain_steps_left1_r <= chain_steps_left1_r - 1'b1;
                                            end

                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            if (chain_steps_left0_r > 8'd1) begin
                                                core0_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core0_done_latched_r <= 1'b0;
                                            end else begin
                                                core0_kick_r <= 1'b0;
                                                core0_done_latched_r <= 1'b1;
                                            end
                                            if (batch_i1_w < w_p && chain_steps_left1_r > 8'd1 && !SINGLE_CORE) begin
                                                core1_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                if (batch_i1_w < w_p && chain_steps_left1_r <= 8'd1) begin

                                                    core1_done_latched_r <= 1'b1;
                                                end
                                            end
                                            fold_settle_r <= 1'b1;
                                            state_r <= STATE_WAIT_CORE;
                                        end else if (batch_phase_r == BATCH_CHAIN) begin

                                            task_digest0_r <= chain0_zero_r ? chain_value0_r : kec_digest_be_w;
                                            task_digest1_r <= chain1_zero_r ? chain_value1_r : chain_digest_be_w;
                                            task_write_word0_r <= 3'd0;
                                            task_write_word1_r <= 3'd0;
                                            dual_write_sel_r <= 1'b0;
                                            state_r <= STATE_TASK_WRITE;
                                        end
                                    end
                                end
                            end
                        end

                        if (kec_ext_done_w || kec_ext1_done_w) begin
                            wait_core_to_r <= 18'd0;
                        end else if (wait_core_to_r >= 18'd1024) begin
                            wait_core_to_r <= 18'd0;
                            timeout_snap_r <= {
                                chain0_zero_r, chain1_zero_r, dual_core1_active_r,
                                fold_settle_r, core0_done_latched_r, core1_done_latched_r,
                                keygen_dleaf_r, state_r, batch_phase_r, batch_i_r,
                                batch_i1_w, chain_j0_r, chain_j1_r,
                                chain_steps_left0_r, chain_steps_left1_r
                            };
                            error_r <= ERR_CORE_TIMEOUT;
                            error_status_r <= 1'b1;
                            done_r <= 1'b1;
                            state_r <= STATE_IDLE;
                        end else begin
                            wait_core_to_r <= wait_core_to_r + 18'd1;
                        end
                    end
                    STATE_TASK_WRITE: begin
                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (!dual_write_sel_r) begin

                            if (task_write_word0_r == 3'd7) begin
                                if (dual_core1_active_r) begin
                                    dual_write_sel_r <= 1'b1;
                                    state_r <= STATE_TASK_WRITE;
                                end else if (batch_i_r == (w_p - 9'd1)) begin

                                    if (command_r == CMD_LMOTS_SIGN) begin
                                        state_r <= STATE_IDLE;
                                        done_r <= 1'b1;
                                    end else begin

                                        batch_phase_r <= BATCH_PBLC;
                                        pblc_final_block_r <= 7'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end
                                end else begin
                                    batch_i_r <= SINGLE_CORE ? (batch_i_r + 9'd1) : (batch_i_r + 9'd2);
                                    if (verify_cmd_w) begin
                                        batch_phase_r <= BATCH_CHAIN;
                                        task_write_word_r <= 3'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end else begin
                                        batch_phase_r <= BATCH_DERIVE;

                                        if (fold_derive_w) begin
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            core0_kick_r <= 1'b1;
                                            fold_settle_r <= 1'b1;
                                            core0_done_latched_r <= 1'b0;
                                            dual_core1_active_r <= ((fold_next_i_w + 9'd1) < w_p) && !SINGLE_CORE;
                                            if ((fold_next_i_w + 9'd1) < w_p && !SINGLE_CORE) begin
                                                core1_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                core1_done_latched_r <= 1'b1;
                                            end
                                            state_r <= STATE_WAIT_CORE;
                                        end else begin
                                            state_r <= STATE_START_CORE;
                                        end
                                    end
                                end
                            end else begin
                                task_write_word0_r <= task_write_word0_r + 1'b1;
                            end
                        end else begin

                            if (task_write_word1_r == 3'd7) begin
                                dual_write_sel_r <= 1'b0;
                                if (batch_i1_w == (w_p - 9'd1)) begin

                                    if (command_r == CMD_LMOTS_SIGN) begin
                                        state_r <= STATE_IDLE;
                                        done_r <= 1'b1;
                                    end else begin
                                        batch_phase_r <= BATCH_PBLC;
                                        pblc_final_block_r <= 7'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end
                                end else if (batch_i_r >= (w_p - 9'd3)) begin
                                    batch_i_r <= (w_p - 9'd1);
                                    if (verify_cmd_w) begin
                                        batch_phase_r <= BATCH_CHAIN;
                                        task_write_word_r <= 3'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end else begin
                                        batch_phase_r <= BATCH_DERIVE;

                                        if (fold_derive_w) begin
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            core0_kick_r <= 1'b1;
                                            fold_settle_r <= 1'b1;
                                            core0_done_latched_r <= 1'b0;
                                            dual_core1_active_r <= ((fold_next_i_w + 9'd1) < w_p) && !SINGLE_CORE;
                                            if ((fold_next_i_w + 9'd1) < w_p && !SINGLE_CORE) begin
                                                core1_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                core1_done_latched_r <= 1'b1;
                                            end
                                            state_r <= STATE_WAIT_CORE;
                                        end else begin
                                            state_r <= STATE_START_CORE;
                                        end
                                    end
                                end else begin
                                    batch_i_r <= SINGLE_CORE ? (batch_i_r + 9'd1) : (batch_i_r + 9'd2);
                                    if (verify_cmd_w) begin
                                        batch_phase_r <= BATCH_CHAIN;
                                        task_write_word_r <= 3'd0;
                                        state_r <= STATE_TASK_PREFETCH;
                                    end else begin
                                        batch_phase_r <= BATCH_DERIVE;

                                        if (fold_derive_w) begin
                                            batch_block_r  <= batch_rate_block_w;
                                            batch_block1_r <= core1_block_w;
                                            batch_block_b1_r <= core1_block_b_w;
                                        batch_block_b_r <= batch_rate_block_b_w;
                                            core0_init_r  <= batch_rate_init_w;
                                            core1_init_r  <= batch_rate_init_w;
                                            core0_kick_r <= 1'b1;
                                            fold_settle_r <= 1'b1;
                                            core0_done_latched_r <= 1'b0;
                                            dual_core1_active_r <= ((fold_next_i_w + 9'd1) < w_p) && !SINGLE_CORE;
                                            if ((fold_next_i_w + 9'd1) < w_p && !SINGLE_CORE) begin
                                                core1_kick_r <= 1'b1;
                                                fold_settle_r <= 1'b1;
                                                core1_done_latched_r <= 1'b0;
                                            end else begin
                                                core1_kick_r <= 1'b0;
                                                core1_done_latched_r <= 1'b1;
                                            end
                                            state_r <= STATE_WAIT_CORE;
                                        end else begin
                                            state_r <= STATE_START_CORE;
                                        end
                                    end
                                end
                            end else begin
                                task_write_word1_r <= task_write_word1_r + 1'b1;
                            end
                        end
                    end
                    STATE_TASK_PREFETCH: begin
                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (hash_ram_path_w) begin

                            state_r <= STATE_HASH_RAM_LOAD;
                        end else if (keygen_dleaf_r) begin

                            state_r <= STATE_START_CORE;
                        end else if (batch_phase_r == BATCH_PBLC) begin

                            pblc_final_word_r <= 6'd0;
                            state_r <= STATE_PBLC_FINAL;
                        end else begin

                            state_r <= STATE_TASK_LOAD;
                        end
                    end
                    STATE_TASK_LOAD: begin
                        cycle_count_r <= cycle_count_r + 32'd1;

                        if (!verify_dual_load_r) begin
                            chain_value0_r[255 - task_write_word_r * 32 -: 32] <= {
                                task_ram_read_r[7:0], task_ram_read_r[15:8],
                                task_ram_read_r[23:16], task_ram_read_r[31:24]};
                        end else begin
                            chain_value1_r[255 - task_write_word_r * 32 -: 32] <= {
                                task_ram_read_r[7:0], task_ram_read_r[15:8],
                                task_ram_read_r[23:16], task_ram_read_r[31:24]};
                        end
                        if (task_write_word_r == 3'd7) begin
                            if (!verify_dual_load_r) begin

                                verify_dual_load_r <= 1'b1;
                                task_write_word_r <= 3'd0;
                                state_r <= STATE_TASK_PREFETCH;
                            end else begin

                                verify_dual_load_r <= 1'b0;
                                chain_j0_r <= batch_coefficient_w;
                                chain_j1_r <= batch_coefficient1_w;
                                chain_steps_left0_r <= w_max_step - batch_coefficient_w;
                                chain_steps_left1_r <= w_max_step - batch_coefficient1_w;
                                chain0_zero_r <= (batch_coefficient_w == w_max_step);
                                chain1_zero_r <= (batch_coefficient1_w == w_max_step);
                                chain_value0_b_r <= 256'b0;
                                chain_value1_b_r <= 256'b0;
                                batch_phase_r <= BATCH_CHAIN;
                                batch_block_r  <= batch_rate_block_w;
                                batch_block1_r <= core1_block_w;
                                batch_block_b1_r <= core1_block_b_w;
                                batch_block_b_r <= batch_rate_block_b_w;
                                core0_init_r  <= batch_rate_init_w;
                                core1_init_r  <= batch_rate_init_w;
                                dual_core1_active_r <= (batch_i1_w < w_p) && !SINGLE_CORE;
                                if (batch_coefficient_w != w_max_step) begin
                                    core0_kick_r <= 1'b1;
                                    fold_settle_r <= 1'b1;
                                    core0_done_latched_r <= 1'b0;
                                end else begin
                                    core0_kick_r <= 1'b0;
                                    core0_done_latched_r <= 1'b1;
                                end
                                if (batch_i1_w < w_p && batch_coefficient1_w != w_max_step && !SINGLE_CORE) begin
                                    core1_kick_r <= 1'b1;
                                    fold_settle_r <= 1'b1;
                                    core1_done_latched_r <= 1'b0;
                                end else begin
                                    core1_kick_r <= 1'b0;
                                    if (batch_i1_w < w_p && !SINGLE_CORE) begin
                                        core1_done_latched_r <= 1'b1;
                                    end
                                end
                                state_r <= STATE_WAIT_CORE;
                            end
                        end else begin
                            task_write_word_r <= task_write_word_r + 1'b1;
                        end
                    end
                    STATE_PBLC_FINAL: begin

                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (pblc_final_word_r == pblc_final_rd_words) begin
                            core0_kick_r  <= 1'b1;
                            core1_kick_r  <= 1'b0;
                            core0_init_r  <= (pblc_final_block_r == 7'd0);
                            core1_init_r  <= 1'b0;
                            dual_core1_active_r <= 1'b0;
                            if (pblc_final_block_r == 7'd0) begin

                                batch_block_r <= {pblc_final_window_r[911:0], pblc_head_w};
                                batch_block_b_r <= 1088'b0;
                            end else if (pblc_final_block_r == w_pblc_last_block) begin

                                batch_block_r <= pblc_last_block_w;
                                batch_block_b_r <= 1088'b0;
                            end else begin

                                batch_block_r <= pblc_final_window_r[1103:16];
                                batch_block_b_r <= 1088'b0;
                            end
                            state_r <= STATE_WAIT_CORE;
                        end else begin
                            pblc_final_window_r[pblc_final_word_r * 32 +: 32] <= task_ram_read_r;
                            pblc_final_word_r <= pblc_final_word_r + 6'd1;
                        end
                    end
                    STATE_DINTR_PREFETCH: begin

                        cycle_count_r <= cycle_count_r + 32'd1;
                        state_r <= STATE_DINTR_LOAD_START;
                    end
                    STATE_DINTR_LOAD_START: begin

                        cycle_count_r <= cycle_count_r + 32'd1;
                        dintr_left_r[255 - dintr_load_word_r * 8'd32 -: 32] <= {
                            task_ram_read_r[7:0], task_ram_read_r[15:8],
                            task_ram_read_r[23:16], task_ram_read_r[31:24]};
                        if (dintr_load_word_r == 4'd7) begin
                            dintr_load_word_r <= 4'd0;
                            state_r <= STATE_DINTR_LOAD_SIB;
                        end else begin
                            dintr_load_word_r <= dintr_load_word_r + 1'b1;
                        end
                    end
                    STATE_DINTR_LOAD_SIB: begin

                        cycle_count_r <= cycle_count_r + 32'd1;
                        dintr_right_r[255 - dintr_load_word_r * 8'd32 -: 32] <= {
                            task_ram_read_r[7:0], task_ram_read_r[15:8],
                            task_ram_read_r[23:16], task_ram_read_r[31:24]};
                        if (dintr_load_word_r == 4'd7) begin
                            dintr_load_word_r <= 4'd0;
                            batch_block_r <= batch_rate_block_w;

                            batch_block_b_r <= batch_rate_block_b_w;
                            core0_kick_r <= 1'b1;
                            fold_settle_r <= 1'b1;
                            core1_kick_r <= 1'b0;
                            core0_init_r <= 1'b1;
                            core1_init_r <= 1'b0;
                            dual_core1_active_r <= 1'b0;
                            state_r <= STATE_DINTR_CORE;
                        end else begin
                            dintr_load_word_r <= dintr_load_word_r + 1'b1;
                        end
                    end
                    STATE_DINTR_CORE: begin

                        cycle_count_r <= cycle_count_r + 32'd1;
                        core0_kick_r <= 1'b0;
                        core1_kick_r <= 1'b0;
                        if (kec_ext_done_w) begin
                            if (dintr_layer_r + 1'b1 < {1'b0, arg_steps_r[4:0]}) begin

                                dintr_left_r <= kec_digest_be_w;
                                dintr_node_r <= dintr_node_r >> 1;
                                dintr_layer_r <= dintr_layer_r + 1'b1;
                                state_r <= STATE_DINTR_LOAD_SIB;
                            end else begin

                                for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                    output_words[out_oi[2:0]] <= {
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                        kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                        kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                end
                                state_r <= STATE_IDLE;
                                done_r <= 1'b1;
                            end
                        end
                    end
                    STATE_HASH_RAM_LOAD: begin

                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (hash_ram_word_r == hash_ram_rd_words_w) begin
                            state_r <= STATE_HASH_RAM_KICK;
                        end else begin
                            pblc_final_window_r[hash_ram_word_r * 32 +: 32] <= task_ram_read_r;
                            hash_ram_word_r <= hash_ram_word_r + 1'b1;
                        end
                    end
                    STATE_HASH_RAM_KICK: begin

                        cycle_count_r <= cycle_count_r + 32'd1;
                        if (!hash_ram_kicked_r) begin
                            batch_block_r <= hash_ram_block_w;
                            batch_block_b_r <= 1088'b0;
                            core0_kick_r <= 1'b1;
                            fold_settle_r <= 1'b1;
                            core1_kick_r <= 1'b0;
                            core0_init_r <= (hash_ram_block_r == 4'd0);
                            core1_init_r <= 1'b0;
                            dual_core1_active_r <= 1'b0;
                            hash_ram_kicked_r <= 1'b1;
                        end else begin
                            core0_kick_r <= 1'b0;
                            if (kec_ext_done_w) begin
                                hash_ram_kicked_r <= 1'b0;
                                if (hash_ram_block_r == hash_ram_full_r) begin
                                    if (mqc_multi_w) begin

                                        mqc_q_be_r <= kec_digest_be_w;
                                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                            output_words[out_oi[2:0]] <= {
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                                kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                        end
                                        state_r <= STATE_MQC_COEF;
                                    end else begin

                                        for (out_oi = 0; out_oi < 8; out_oi = out_oi + 1) begin
                                            output_words[out_oi[2:0]] <= {
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd24) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd16) -: 8],
                                                kec_digest_be_w[255 - (out_oi[2:0] * 8'd32 + 8'd8) -: 8],
                                                kec_digest_be_w[255 - out_oi[2:0] * 8'd32 -: 8]};
                                        end
                                        state_r <= STATE_IDLE;
                                        done_r <= 1'b1;
                                    end
                                end else begin
                                    hash_ram_block_r <= hash_ram_block_r + 1'b1;
                                    hash_ram_word_r <= 6'd0;
                                    state_r <= STATE_TASK_PREFETCH;
                                end
                            end
                        end
                    end
                    default: ;
                endcase
            end
        end
    end

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
            bus_addr[9:0] == REG_TASK_DATA && task_addr_r >= 32) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            task_ram_addr_w = task_addr_r;
            task_ram_wdata_w = bus_wdata;
        end else if (bg_drain_active_r) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = (bg_q_wrap[0] && bg_drain_idx_r[3]) ?
                              (12'd32 + {9'b0, bg_drain_idx_r[2:0]}) :
                              (bg_q_addr[0] + {8'b0, bg_drain_idx_r});

            task_ram_write_w = !(result_active_r &&
                                 (task_ram_addr_w < (12'd32 + {result_count_r, 3'b0})));
            if (bg_drain_idx_r[3]) begin
                task_ram_wdata_w = {
                    bg_q_d1[0][255 - (bg_drain_idx_r[2:0] * 32 + 24) -: 8],
                    bg_q_d1[0][255 - (bg_drain_idx_r[2:0] * 32 + 16) -: 8],
                    bg_q_d1[0][255 - (bg_drain_idx_r[2:0] * 32 + 8) -: 8],
                    bg_q_d1[0][255 - bg_drain_idx_r[2:0] * 32 -: 8]};
            end else begin
                task_ram_wdata_w = {
                    bg_q_d0[0][255 - (bg_drain_idx_r[2:0] * 32 + 24) -: 8],
                    bg_q_d0[0][255 - (bg_drain_idx_r[2:0] * 32 + 16) -: 8],
                    bg_q_d0[0][255 - (bg_drain_idx_r[2:0] * 32 + 8) -: 8],
                    bg_q_d0[0][255 - bg_drain_idx_r[2:0] * 32 -: 8]};
            end
        end else if (task_prefetch_pending_r) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = task_addr_r;
        end else if (state_r == STATE_TASK_WRITE) begin
            task_ram_enable_w = 1'b1;
            task_ram_write_w = 1'b1;
            if (dual_write_sel_r) begin

                task_ram_addr_w = 12'd32 + {der_perm_bi1_w, 3'b0} + {9'b0, task_write_word1_r};
                task_ram_wdata_w = {
                    task_digest1_r[255 - (task_write_word1_r * 32 + 24) -: 8],
                    task_digest1_r[255 - (task_write_word1_r * 32 + 16) -: 8],
                    task_digest1_r[255 - (task_write_word1_r * 32 + 8) -: 8],
                    task_digest1_r[255 - task_write_word1_r * 32 -: 8]};
            end else begin

                task_ram_addr_w = 12'd32 + {der_perm_bi_w, 3'b0} + {9'b0, task_write_word0_r};
                task_ram_wdata_w = {
                    task_digest0_r[255 - (task_write_word0_r * 32 + 24) -: 8],
                    task_digest0_r[255 - (task_write_word0_r * 32 + 16) -: 8],
                    task_digest0_r[255 - (task_write_word0_r * 32 + 8) -: 8],
                    task_digest0_r[255 - task_write_word0_r * 32 -: 8]};
            end
        end else if (state_r == STATE_TASK_LOAD) begin
            task_ram_enable_w = 1'b1;
            if (verify_dual_load_r) begin
                task_ram_addr_w = 12'd32 + {batch_i1_w, 3'b0} +
                    (task_write_word_r == 3'd7 ? 12'd7 : {9'b0, task_write_word_r} + 12'd1);
            end else begin
                task_ram_addr_w = 12'd32 + {batch_i_r, 3'b0} +
                    (task_write_word_r == 3'd7 ? 12'd7 : {9'b0, task_write_word_r} + 12'd1);
            end
        end else if (state_r == STATE_TASK_PREFETCH && !keygen_dleaf_r) begin
            task_ram_enable_w = 1'b1;
            if (hash_ram_path_w)
                task_ram_addr_w = hash_ram_base_w;
            else if (batch_phase_r == BATCH_PBLC)
                task_ram_addr_w = pblc_final_base_w;
            else
                task_ram_addr_w = 12'd32 +
                    (verify_dual_load_r ? {batch_i1_w, 3'b0} : {batch_i_r, 3'b0});
        end else if (state_r == STATE_PBLC_FINAL) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = pblc_final_base_w +
                (pblc_final_word_r >= pblc_final_rd_words - 6'd1 ?
                    (pblc_final_rd_words - 6'd1) : pblc_final_word_r + 6'd1);
        end else if (state_r == STATE_HASH_RAM_LOAD && hash_ram_rd_words_w != 6'd0) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = hash_ram_base_w +
                (hash_ram_word_r >= hash_ram_rd_words_w - 6'd1 ?
                    (hash_ram_rd_words_w - 6'd1) : hash_ram_word_r + 6'd1);
        end else if (state_r == STATE_DINTR_PREFETCH) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd32;
        end else if (state_r == STATE_DINTR_LOAD_START) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = (dintr_load_word_r == 4'd7) ? 12'd40 :
                               (12'd33 + dintr_load_word_r);
        end else if (state_r == STATE_DINTR_LOAD_SIB) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd40 + {dintr_layer_r, 3'b0} +
                (dintr_load_word_r == 4'd7 ? 4'd7 : dintr_load_word_r + 1'b1);
        end else if (state_r == STATE_DINTR_CORE) begin

            task_ram_enable_w = 1'b1;
            task_ram_addr_w = 12'd40 + {dintr_layer_r + 1'b1, 3'b0};
        end else if (!wrapper_busy_w && done_r && bus_valid && !bus_write &&
                     bus_addr[9:0] == REG_TASK_DATA && task_addr_r >= 32 && !stream_read_r &&
                     !bg_busy_w) begin
            task_ram_enable_w = 1'b1;
            task_ram_addr_w = task_addr_r;
        end
    end

    always @(posedge clk) begin
        if (rst) begin
            bg_drain_active_r <= 1'b0;
            bg_drain_idx_r    <= 4'd0;
            bg_q_valid[0]     <= 1'b0;
            bg_q_valid[1]     <= 1'b0;
            bg_q_addr[0]      <= 12'd0;
            bg_q_addr[1]      <= 12'd0;
            bg_q_words[0]     <= 5'd0;
            bg_q_words[1]     <= 5'd0;
            bg_q_wrap[0]      <= 1'b0;
            bg_q_wrap[1]      <= 1'b0;
        end else begin
            if (bg_drain_active_r) begin
                if ({1'b0, bg_drain_idx_r} + 5'd1 >= bg_q_words[0]) begin

                    bg_drain_active_r <= 1'b0;
                    bg_drain_idx_r    <= 4'd0;
                    if (bg_push_w) begin
                        bg_q_d0[0]    <= bg_digest0_sel_w;
                        bg_q_d1[0]    <= bg_digest1_sel_w;
                        bg_q_addr[0]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[0] <= (SINGLE_CORE || (batch_i_r >= (w_p - 9'd1))) ? 5'd8 : 5'd16;
                        bg_q_valid[0] <= 1'b1;
                        bg_q_wrap[0]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end else begin
                        bg_q_valid[0] <= bg_q_valid[1];
                        bg_q_d0[0]    <= bg_q_d0[1];
                        bg_q_d1[0]    <= bg_q_d1[1];
                        bg_q_addr[0]  <= bg_q_addr[1];
                        bg_q_words[0] <= bg_q_words[1];
                        bg_q_wrap[0]  <= bg_q_wrap[1];
                        bg_q_valid[1] <= 1'b0;
                    end
                end else begin
                    bg_drain_idx_r <= bg_drain_idx_r + 4'd1;

                    if (bg_push_w) begin
                        bg_q_d0[1]    <= bg_digest0_sel_w;
                        bg_q_d1[1]    <= bg_digest1_sel_w;
                        bg_q_addr[1]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[1] <= (SINGLE_CORE || (batch_i_r >= (w_p - 9'd1))) ? 5'd8 : 5'd16;
                        bg_q_valid[1] <= 1'b1;
                        bg_q_wrap[1]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end
                end
            end else begin
                if (bg_push_w) begin
                    if (!bg_q_valid[0]) begin
                        bg_q_d0[0]    <= bg_digest0_sel_w;
                        bg_q_d1[0]    <= bg_digest1_sel_w;
                        bg_q_addr[0]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[0] <= (SINGLE_CORE || (batch_i_r >= (w_p - 9'd1))) ? 5'd8 : 5'd16;
                        bg_q_valid[0] <= 1'b1;
                        bg_q_wrap[0]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end else if (!bg_q_valid[1]) begin
                        bg_q_d0[1]    <= bg_digest0_sel_w;
                        bg_q_d1[1]    <= bg_digest1_sel_w;
                        bg_q_addr[1]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[1] <= (SINGLE_CORE || (batch_i_r >= (w_p - 9'd1))) ? 5'd8 : 5'd16;
                        bg_q_valid[1] <= 1'b1;
                        bg_q_wrap[1]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end else begin

                        bg_q_d0[1]    <= bg_digest0_sel_w;
                        bg_q_d1[1]    <= bg_digest1_sel_w;
                        bg_q_addr[1]  <= 12'd32 + {der_perm_bi_w, 3'b0};
                        bg_q_words[1] <= (SINGLE_CORE || (batch_i_r >= (w_p - 9'd1))) ? 5'd8 : 5'd16;
                        bg_q_valid[1] <= 1'b1;
                        bg_q_wrap[1]  <= (der_perm_bi_w == (w_p - 9'd1));
                    end
                end
                if (bg_q_valid[0]) begin
                    bg_drain_active_r <= 1'b1;
                    bg_drain_idx_r    <= 4'd0;
                end
            end
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
        if (rst) begin
            task_ram_read_r <= 32'b0;
        end
    end

    /* R6 Stage 1: independent read-only task-RAM port B. Port A above is kept
     * byte-for-byte semantically unchanged. Port B only exposes the completed
     * y region and never accepts a write. A same-cycle port-A write to the
     * addressed word makes the B read not-valid instead of returning a
     * read-during-write value. */
    always @(posedge clk) begin
        if (rst) begin
            result_read_r <= 32'b0;
            result_read_valid_r <= 1'b0;
        end else begin
            result_read_valid_r <= result_addr_valid_w &&
                !(task_ram_write_w && task_ram_addr_w == result_abs_addr_w);
            if (result_addr_valid_w &&
                !(task_ram_write_w && task_ram_addr_w == result_abs_addr_w)) begin
                result_read_r <= task_words[result_abs_addr_w];
            end else if (!result_addr_valid_w) begin
                result_read_r <= 32'b0;
            end
        end
    end

    always @(posedge clk) begin
        if (rst) begin
            task_addr_r <= 12'b0;
            stream_read_r <= 1'b0;
            stream_rd_pending_r <= 1'b0;
        end else begin

            if (stream_rd_en && !wrapper_busy_w) begin
                stream_rd_pending_r <= 1'b1;
            end else begin
                stream_rd_pending_r <= 1'b0;
            end

            if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w && bus_valid && bus_write &&
                bus_addr[9:0] == REG_TASK_ADDR && bus_wdata < 2152) begin
                task_addr_r <= bus_wdata[11:0];
            end else if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w && bus_valid && bus_write &&
                bus_addr[9:0] == REG_TASK_DATA && task_addr_r >= 32) begin

                task_addr_r <= task_addr_r + 12'd1;
            end else if (!stream_wr_en && !stream_rd_en && !wrapper_busy_w && done_r && bus_valid && !bus_write &&
                bus_addr[9:0] == REG_TASK_DATA && task_addr_r >= 32 && !stream_read_r && !bg_busy_w) begin
                task_addr_r <= task_addr_r + 12'd1;
                stream_read_r <= 1'b1;
            end else if (!bus_valid) begin
                stream_read_r <= 1'b0;
            end
        end
    end

    assign stream_busy      = busy_report_w || bg_busy_w;
    assign stream_rd_valid  = stream_rd_pending_r && !ksd_output_hidden_w;
    assign stream_rd_data   = stream_rd_pending_r && !ksd_output_hidden_w ? task_ram_read_r : 32'b0;

    always @(posedge clk) begin
        if (rst) dbg_rd_sel_r <= 16'b0;
        else if (bus_valid && bus_write && bus_addr[9:0] == REG_DBG_ADDR)
            dbg_rd_sel_r <= bus_wdata[15:0];
    end

    reg          cap_en_r;
    reg  [6:0]   cap_i_r;
    reg  [6:0]   cap_rd_r;
    reg  [7:0]   cap_j0_r, cap_j1_r;
    reg  [255:0] cap_val0_r, cap_val1_r;
    reg  [1087:0] cap_blk0_r, cap_blk1_r;
    reg          cap_seen0_r, cap_seen1_r;

    always @(posedge clk) begin
        if (rst) begin
            cap_en_r    <= 1'b0;
            cap_i_r     <= 7'd0;
            cap_rd_r    <= 7'd0;
            cap_j0_r    <= 8'd0;
            cap_j1_r    <= 8'd0;
            cap_val0_r  <= 256'b0;
            cap_val1_r  <= 256'b0;
            cap_blk0_r  <= 1088'b0;
            cap_blk1_r  <= 1088'b0;
            cap_seen0_r <= 1'b0;
            cap_seen1_r <= 1'b0;
        end else begin
            if (bus_valid && bus_write && bus_addr[9:0] == REG_CAP_CTL) begin
                cap_en_r <= bus_wdata[7];
                cap_i_r  <= bus_wdata[6:0];
            end
            if (bus_valid && bus_write && bus_addr[9:0] == REG_CAP_IDX)
                cap_rd_r <= bus_wdata[6:0];

            if (batch_start_w) begin
                cap_seen0_r <= 1'b0;
                cap_seen1_r <= 1'b0;
            end
            if (kec_start_w && cap_en_r && (batch_i_r[6:0] == cap_i_r)) begin

                if ((batch_phase_r == BATCH_DERIVE) && !cap_seen0_r) begin
                    cap_blk1_r  <= batch_block_r;
                    cap_val1_r  <= chain_value0_r;
                    cap_j1_r    <= 8'hfe;
                    cap_seen0_r <= 1'b1;
                end else if ((batch_phase_r == BATCH_CHAIN) && cap_seen0_r && !cap_seen1_r) begin
                    cap_blk0_r  <= batch_block_r;
                    cap_val0_r  <= chain_value0_r;
                    cap_j0_r    <= chain_j0_r;
                    cap_seen1_r <= 1'b1;
                end
            end
            if (kec1_start_w && cap_en_r && (batch_i1_w[6:0] == cap_i_r)) begin
                cap_blk1_r  <= batch_block1_r;
                cap_val1_r  <= chain_value1_r;
                cap_j1_r    <= chain_j1_r;
                cap_seen1_r <= 1'b1;
            end
        end
    end

    reg [31:0] dbg_start0_cnt;
    reg [31:0] dbg_start1_cnt;
    reg [31:0] dbg_kick0_cnt;
    reg [31:0] dbg_kick1_cnt;
    reg        kick0_prev_r;
    reg        kick1_prev_r;
    always @(posedge clk) begin
        if (rst || batch_start_w) begin
            dbg_start0_cnt <= 32'd0;
            dbg_start1_cnt <= 32'd0;
            dbg_kick0_cnt  <= 32'd0;
            dbg_kick1_cnt  <= 32'd0;
            kick0_prev_r   <= 1'b0;
            kick1_prev_r   <= 1'b0;
        end else begin
            if (kec_start_w)  dbg_start0_cnt <= dbg_start0_cnt + 32'd1;
            if (kec1_start_w) dbg_start1_cnt <= dbg_start1_cnt + 32'd1;
            if (core0_kick_r && !kick0_prev_r) dbg_kick0_cnt <= dbg_kick0_cnt + 32'd1;
            if (core1_kick_r && !kick1_prev_r) dbg_kick1_cnt <= dbg_kick1_cnt + 32'd1;
            kick0_prev_r <= core0_kick_r;
            kick1_prev_r <= core1_kick_r;
        end
    end

    reg [31:0] cap_rdata_w;
    wire [10:0] cap_base_w = {4'b0, cap_rd_r} << 5;
    always @* begin
        cap_rdata_w = 32'b0;
        if (cap_rd_r < 7'd34)
            cap_rdata_w = cap_blk0_r[cap_base_w +: 32];
        else if (cap_rd_r < 7'd68)
            cap_rdata_w = cap_blk1_r[(cap_base_w - 11'd1088) +: 32];
        else if (cap_rd_r < 7'd76)
            cap_rdata_w = cap_val0_r[(cap_base_w - 11'd2176) +: 32];
        else if (cap_rd_r < 7'd84)
            cap_rdata_w = cap_val1_r[(cap_base_w - 11'd2432) +: 32];
        else if (cap_rd_r == 7'd84)
            cap_rdata_w = {16'b0, cap_j1_r, cap_j0_r, 5'b0, cap_seen1_r, cap_seen0_r};
        else if (cap_rd_r == 7'd85)
            cap_rdata_w = {24'b0, cap_en_r, cap_i_r};
        else if (cap_rd_r == 7'd86)
            cap_rdata_w = dbg_start0_cnt;
        else if (cap_rd_r == 7'd87)
            cap_rdata_w = dbg_kick0_cnt;
        else if (cap_rd_r == 7'd88)
            cap_rdata_w = dbg_start1_cnt;
        else if (cap_rd_r == 7'd89)
            cap_rdata_w = dbg_kick1_cnt;
    end

    wire [31:0] dbg_cap_rdata_w;
    always @* begin
        bus_rdata = 32'b0;
        case (bus_addr[9:0])
            REG_VERSION: bus_rdata = VERSION;
            REG_CAPABILITY: bus_rdata = CAPABILITY;
            REG_STATUS: bus_rdata = (busy_report_w || bg_busy_w) ? STATUS_BUSY :
                                     (done_r ? STATUS_DONE : 32'b0) |
                                     (error_status_r ? STATUS_ERROR : 32'b0);
            REG_ERROR: bus_rdata = error_r;
            REG_OUTPUT_LENGTH: bus_rdata = output_length_r;
            REG_CYCLE_COUNT: bus_rdata = (batch_cmd_w || dintr_cmd_w || hash_ram_cmd_w ||
                                          sec_cmd_pending_w) ? cycle_count_r : engine_cycle_w;
            REG_SIM_MC: bus_rdata = sec_bus_rdata_w;
            REG_ARG_LEAF_NODE: bus_rdata = arg_leaf_node_r;
            REG_ARG_W: bus_rdata = {28'b0, arg_w_r};
            REG_TASK_ADDR: bus_rdata = {20'b0, task_addr_r};
            REG_TASK_DATA: begin
                if (task_addr_r < 32) begin
                    bus_rdata = coefficient_words[task_addr_r[4:0]];
                end else begin
                    bus_rdata = task_ram_read_r;
                end
            end
            REG_RESULT_EPOCH:  bus_rdata = result_epoch_r;
            REG_RESULT_COUNT:  bus_rdata = {23'b0, result_count_r};
            REG_RESULT_STATUS: bus_rdata = {29'b0, (result_error_r || error_status_r),
                                            result_done_r, result_active_r};
            REG_RESULT_LENGTH: bus_rdata = {20'b0, result_length_r};
            REG_RESULT_ADDR:   bus_rdata = {20'b0, result_addr_r};
            REG_RESULT_DATA:   bus_rdata = (result_addr_valid_w && result_read_valid_r)
                                          ? result_read_r : 32'b0;
            REG_RESULT_ERROR:  bus_rdata = result_error_r ? ERR_RESULT_NOT_READY : error_r;
            REG_DBG_ADDR: bus_rdata = {16'b0, dbg_rd_sel_r};
            /* Only index 1 exists here: public RNG health/readiness status.
             * Firmware needs it to wait for R; all payload indices read zero. */
            REG_DBG_DATA: bus_rdata = dbg_cap_rdata_w;
            REG_TIMEOUT0: bus_rdata = timeout_snap_r[31:0];
            REG_TIMEOUT1: bus_rdata = timeout_snap_r[63:32];
            REG_CAP_CTL:  bus_rdata = {24'b0, cap_en_r, cap_i_r};
            REG_CAP_IDX:  bus_rdata = {25'b0, cap_rd_r};
            REG_CAP_DATA: bus_rdata = INSECURE_TEST_MODE ? cap_rdata_w : 32'b0;
            default: begin
                if (INSECURE_TEST_MODE && bus_addr[9:0] >= 10'h1c0 && bus_addr[9:0] < 10'h1e0) begin

                    case (bus_addr[4:2])
                        3'd0: bus_rdata = seed_xor_w[255:224];
                        3'd1: bus_rdata = seed_xor_w[223:192];
                        3'd2: bus_rdata = seed_xor_w[191:160];
                        3'd3: bus_rdata = seed_xor_w[159:128];
                        3'd4: bus_rdata = seed_xor_w[127:96];
                        3'd5: bus_rdata = seed_xor_w[95:64];
                        3'd6: bus_rdata = seed_xor_w[63:32];
                        3'd7: bus_rdata = seed_xor_w[31:0];
                        default: bus_rdata = 32'b0;
                    endcase
                end else if (bus_addr[9:0] >= REG_IDENTIFIER &&
                    bus_addr[9:0] < REG_IDENTIFIER + 16) begin
                    bus_rdata = identifier_words[(bus_addr[9:0] - REG_IDENTIFIER) >> 2];
                end else if (bus_addr[9:0] >= REG_SEED_BASE &&
                             bus_addr[9:0] < REG_SEED_BASE + 32) begin
                    bus_rdata = sec_bus_rdata_w;
                end else if (bus_addr[9:0] >= REG_WRAPPED_BASE &&
                             bus_addr[9:0] < REG_WRAPPED_BASE + 48) begin
                    bus_rdata = sec_bus_rdata_w;
                end else if (bus_addr[9:0] >= REG_KWRAP_BASE &&
                             bus_addr[9:0] < REG_KWRAP_BASE + 32) begin
                    bus_rdata = sec_bus_rdata_w;
                end else if (bus_addr[9:0] >= REG_INPUT_BASE &&
                             bus_addr[9:0] < REG_INPUT_BASE + 128) begin
                    bus_rdata = input_words[(bus_addr[9:0] - REG_INPUT_BASE) >> 2];
                end else if (bus_addr[9:0] >= REG_OUTPUT_BASE &&
                             bus_addr[9:0] < REG_OUTPUT_BASE + 32) begin
                    bus_rdata = output_words[(bus_addr[9:0] - REG_OUTPUT_BASE) >> 2];
                end
            end
        endcase
        if (ksd_mmio_hit_w) bus_rdata = ksd_mmio_rdata_w;
        if (ksd_output_hidden_w) begin
            if ((bus_addr[9:0] == REG_TASK_DATA && task_addr_r >= 32) ||
                (bus_addr[9:0] >= REG_OUTPUT_BASE && bus_addr[9:0] < REG_OUTPUT_BASE + 32 &&
                 !public_output_visible_w) ||
                bus_addr[9:0] == REG_RESULT_DATA || bus_addr[9:0] == REG_RESULT_COUNT ||
                bus_addr[9:0] == REG_RESULT_LENGTH) bus_rdata = 32'b0;
            if (bus_addr[9:0] == REG_RESULT_STATUS) bus_rdata = 32'd4;
            if (command_r == CMD_LMOTS_SIGN && !physical_busy_w) begin
                if (bus_addr[9:0] == REG_STATUS) bus_rdata = STATUS_ERROR;
                if (bus_addr[9:0] == REG_ERROR) bus_rdata = 32'd18;
            end
        end
    end

    wire [31:0] eng_dbg;

    assign dbg_bus = {
        chain_steps_left1_r,        /* [31:24] */
        chain_j1_r[3:0],            /* [23:20] */
        batch_i_r[7:0],             /* [19:12] */
        chain1_zero_r,              /* [11] */
        core1_done_seen_r,          /* [10] */
        chain_more_w,               /* [9] */
        batch_start_w,              /* [8] */
        batch_cmd_w,                /* [7] */
        core1_should_run,           /* [6] */
        sec_core_mode_w,            /* [5] */
        kec_ext_mode_w,             /* [4] */
        verify_dual_load_r,         /* [3] */
        task_write_word_r[0],       /* [2] */
        2'b00                       /* [1:0] */
    };

    wire [8:0] steps0_delta_w = {1'b0, chain_steps_left0_r} - {1'b0, steps0_prev_r};
    wire       steps0_legal_w =
        (steps0_delta_w == 9'd0) ||
        (steps0_delta_w == 9'd511) ||
        (chain_steps_left0_r == w_max_step) ||   /* reload(DERIVE→CHAIN)*/
        (chain_steps_left0_r == 8'd0);
    wire       kick_busy_w = (core0_kick_r && kec_ext_busy_w) ||
                             (core1_kick_r && kec_ext1_busy_w);
    wire       mon_any_w = mon_kick_busy_r | mon_wait_long_r | mon_steps_jump_r;

    reg [31:0] hang_snap_r;

    wire [31:0] dbg_live_w = {
        state_r[4:0],
        fold_settle_r,             /* [26] */
        dual_core1_active_r,       /* [25] */
        core0_done_latched_r,      /* [24] */
        core1_done_latched_r,      /* [23] */
        core0_kick_r,              /* [22] */
        core0_kick_q,              /* [21] */
        kec_start_w,               /* [20] */
        kec_ext_busy_w,            /* [19] */
        kec_ext_done_w,            /* [18] */
        core1_kick_r,              /* [17] */
        core1_kick_q,              /* [16] */
        kec1_start_w,              /* [15] */
        kec_ext1_busy_w,           /* [14] */
        core1_done_eff_w,          /* [13] */
        chain0_zero_r,             /* [12] */
        chain_steps_left0_r,       /* [11:4] */
        chain_j0_r[3:0]            /* [3:0] */
    };

    always @(posedge clk) begin
        if (rst) begin
            mon_kick_busy_r   <= 1'b0;
            mon_steps_jump_r  <= 1'b0;
            mon_wait_long_r   <= 1'b0;
            mon_first_cycle_r <= 8'd0;
            steps0_prev_r     <= 8'd0;
            fw_stage_r        <= 8'd0;
            hang_snap_r       <= 32'd0;
        end else begin
            steps0_prev_r <= chain_steps_left0_r;

            if (bus_valid && bus_write && (bus_addr[9:6] == 4'b0110)) begin
                fw_stage_r <= {2'b00, bus_addr[5:2]};
            end
            if (batch_start_w) begin

                mon_kick_busy_r   <= 1'b0;
                mon_steps_jump_r  <= 1'b0;
                mon_wait_long_r   <= 1'b0;
                mon_first_cycle_r <= 8'd0;
                hang_snap_r       <= 32'd0;
            end else begin
                if (!mon_any_w && kick_busy_w) begin
                    mon_kick_busy_r   <= 1'b1;
                    mon_first_cycle_r <= cycle_count_r[7:0];
                end else if (!mon_any_w && (state_r == STATE_WAIT_CORE) && batch_cmd_w &&
                             !steps0_legal_w) begin
                    mon_steps_jump_r  <= 1'b1;
                    mon_first_cycle_r <= cycle_count_r[7:0];
                end

                if (!mon_wait_long_r && (state_r == STATE_WAIT_CORE) &&
                    (wait_core_to_r >= 18'd1024)) begin
                    mon_wait_long_r   <= 1'b1;
                    mon_first_cycle_r <= cycle_count_r[7:0];
                    hang_snap_r       <= dbg_live_w;
                end
            end
        end
    end

    assign dbg_state = mon_wait_long_r ? hang_snap_r : dbg_live_w;

wire [31:0] mask_status_w = {MASKED, 14'b0, mask_reseed_count_w[11:0],
                             mask_seed_share_valid_w,
                             rnd_block_valid_w, mask_drbg_valid_w,
                             rnd_block_missing_r, mask_drbg_fail_w};

assign dbg_cap_rdata_w = (dbg_rd_sel_r == 16'h0001) ? mask_status_w : 32'b0;

endmodule

`default_nettype wire
