`default_nettype none

/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off UNUSEDSIGNAL */

//

//

//

//   - busy:state != IDLE

module lms_hash_engine #(
    parameter HASH_TYPE = 1,
    parameter INSECURE_TEST_MODE = 0,
    parameter RANDOM_DELAY = 0
    ,parameter MASKED = 0
    ,parameter DBG_CORE1_SKEW = 0
    ,parameter DBG_DROP_CORE1_DONE = 0
    ,parameter SINGLE_CORE = 0        /* SHAKE256: omit inactive core1; dual-core default unchanged */
) (
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [31:0] command,        /* HASH_ONCE/CHAIN/DERIVE_CHAIN/DERIVE_RANDOMIZER */
    input  wire [7:0]  input_length,
    input  wire [31:0] arg_q,
    input  wire [15:0] arg_i,
    input  wire [7:0]  arg_start,
    input  wire [31:0] arg_steps,
    input  wire [127:0] identifier_flat,
    input  wire [255:0] chain_value_in,
    input  wire [255:0] seed_flat,
    input  wire [255:0] seed_b,
    input  wire [1023:0] input_words_flat,
    input  wire [63:0]  rnd_share,
    input  wire [1087:0] rnd_block = 1088'b0,
    input  wire        sha_ext_mode,
    input  wire        sha_ext_start,
    input  wire        sha_ext_init,
    input  wire        sha_ext_state_load,
    input  wire [255:0] sha_ext_state_in,
    input  wire [511:0] sha_ext_block,
    output wire        sha_ext_busy,
    output wire        sha_ext_done,
    output wire [255:0] sha_ext_digest,
    input  wire        sha_ext1_start,
    input  wire        sha_ext1_init,
    input  wire        sha_ext1_state_load,
    input  wire [255:0] sha_ext1_state_in,
    input  wire [511:0] sha_ext1_block,
    output wire        sha_ext1_busy,
    output wire        sha_ext1_done,
    output wire [255:0] sha_ext1_digest,

    input  wire        kec_ext_mode,
    input  wire        kec_ext_start,
    input  wire        kec_ext_init,
    input  wire [1087:0] kec_ext_block,
    input  wire [1087:0] kec_ext_block_b,
    input  wire        kec_ext_digest_public,
    output wire        kec_ext_busy,
    output wire        kec_ext_done,
    output wire [255:0] kec_ext_digest,
    output wire [255:0] kec_ext_digest_a,
    output wire [255:0] kec_ext_digest_b,
    input  wire        kec_ext1_start,
    input  wire        kec_ext1_init,
    input  wire [1087:0] kec_ext1_block,
    input  wire [1087:0] kec_ext1_block_b,
    input  wire        kec_ext1_digest_public,
    output wire        kec_ext1_busy,
    output wire        kec_ext1_done,
    output wire [255:0] kec_ext1_digest,
    output wire [255:0] kec_ext1_digest_a,
    output wire [255:0] kec_ext1_digest_b,
    output wire [31:0]  dbg_eng,
    output wire        busy,
    output wire        done,
    output wire [255:0] digest_out,
    output reg  [31:0] cycle_count
);
    localparam [31:0] CMD_HASH_ONCE         = 32'h00000001;
    localparam [31:0] CMD_CHAIN             = 32'h00000002;
    localparam [31:0] CMD_DERIVE_CHAIN      = 32'h00000004;
    localparam [31:0] CMD_DERIVE_RANDOMIZER = 32'h00000005;

    generate
        if (HASH_TYPE == 1) begin : g_shake256
            localparam [1:0] TASK_HASH_ONCE  = 2'd0;
            localparam [1:0] TASK_CHAIN      = 2'd1;
            localparam [1:0] TASK_DERIVE     = 2'd2;
            localparam [1:0] TASK_RANDOMIZER = 2'd3;

            localparam [3:0] ST_IDLE      = 4'd0;
            localparam [3:0] ST_ABSORB    = 4'd1;
            localparam [3:0] ST_WAIT_CORE = 4'd2;
            localparam [3:0] ST_DONE      = 4'd3;

            reg [3:0]  state_r;
            reg [1:0]  task_r;
            reg [255:0] chain_value_r;
            reg [255:0] chain_value_b_r;
            reg [7:0]  chain_j_r;
            reg [31:0] chain_steps_left_r;
            reg        derive_phase_r;
            reg        core_start_r;

            reg [9:0]  rnd_delay_r;
            reg        rnd_pending_r;
            reg [15:0] rnd_lfsr_r;

            reg [1087:0] core_block_r;
            reg [1087:0] core_block_b_r;
            reg          core_init_r;
            reg [1087:0] rate_block_w;
            reg [1087:0] rate_block_b_w;
            reg        rate_init_w;

            wire rnd_apply_w = RANDOM_DELAY &&
                               (command == CMD_DERIVE_RANDOMIZER ||
                                (command == CMD_DERIVE_CHAIN && arg_steps == 32'd0));

            wire        core_busy_w;
            wire        core_done_w;
            wire [255:0] core_digest_w;
            wire [255:0] core_digest_a_w;
            wire [255:0] core_digest_b_w;
            wire [255:0] core_digest_c_w;
            wire        kec_core1_busy_w;
            wire        kec_core1_done_w;
            wire [255:0] kec_core1_digest_w;
            wire [255:0] kec_core1_digest_a_w;
            wire [255:0] kec_core1_digest_b_w;
            wire [255:0] kec_core1_digest_c_w;
            wire [255:0] digest_be_w;
            wire [255:0] digest_be_a_w;
            wire [255:0] digest_be_b_w;
            wire single_digest_public_w =
                (task_r == TASK_HASH_ONCE) || (task_r == TASK_RANDOMIZER) ||
                ((task_r == TASK_CHAIN) && (chain_steps_left_r == 32'd1)) ||
                ((task_r == TASK_DERIVE) &&
                 (derive_phase_r ? (chain_steps_left_r == 32'd0) :
                                   (chain_steps_left_r == 32'd1)));
            wire core_digest_public_w = kec_ext_mode ? kec_ext_digest_public :
                                                       single_digest_public_w;
            wire [255:0] digest_next_a_w = single_digest_public_w ? digest_be_w : digest_be_a_w;
            wire [255:0] digest_next_b_w = single_digest_public_w ? 256'b0 : digest_be_b_w;

            if (MASKED) begin : g_masked_core

                lms_keccak_core_masked keccak (
                    .clk(clk),
                    .rst(rst),
                    .start(kec_ext_mode ? kec_ext_start : core_start_r),
                    .init(kec_ext_mode ? kec_ext_init : core_init_r),
                    .block_a(kec_ext_mode ? kec_ext_block : core_block_r),
                    .block_b(kec_ext_mode ? kec_ext_block_b : core_block_b_r),
                    .digest_public(core_digest_public_w),
                    .busy(core_busy_w),
                    .done(core_done_w),
                    .digest(core_digest_w),
                    .digest_a(core_digest_a_w),
                    .digest_b(core_digest_b_w),
                    .digest_c(core_digest_c_w)
                );
            end else begin : g_plain_core
                lms_keccak_core keccak (
                    .clk(clk),
                    .rst(rst),
                    .start(kec_ext_mode ? kec_ext_start : core_start_r),
                    .init(kec_ext_mode ? kec_ext_init : core_init_r),
                    .block(kec_ext_mode ? kec_ext_block : core_block_r),
                    .busy(core_busy_w),
                    .done(core_done_w),
                    .digest(core_digest_w)
                );
                assign core_digest_a_w = core_digest_w;
                assign core_digest_b_w = 256'b0;
                assign core_digest_c_w = 256'b0;
            end

            if (SINGLE_CORE) begin : g_no_core1
                assign kec_core1_busy_w = 1'b0;
                assign kec_core1_done_w = 1'b0;
                assign kec_core1_digest_w = 256'b0;
                assign kec_core1_digest_a_w = 256'b0;
                assign kec_core1_digest_b_w = 256'b0;
                assign kec_core1_digest_c_w = 256'b0;
            end else if (MASKED) begin : g_masked_core1
                lms_keccak_core_masked keccak_core1 (
                    .clk(clk),
                    .rst(rst),
                    .start(kec_ext1_start),
                    .init(kec_ext1_init),
                    .block_a(kec_ext1_block),
                    .block_b(kec_ext1_block_b),
                    .digest_public(kec_ext1_digest_public),
                    .busy(kec_core1_busy_w),
                    .done(kec_core1_done_w),
                    .digest(kec_core1_digest_w),
                    .digest_a(kec_core1_digest_a_w),
                    .digest_b(kec_core1_digest_b_w),
                    .digest_c(kec_core1_digest_c_w)
                );
            end else begin : g_plain_core1
                lms_keccak_core keccak_core1 (
                    .clk(clk),
                    .rst(rst),
                    .start(kec_ext1_start),
                    .init(kec_ext1_init),
                    .block(kec_ext1_block),
                    .busy(kec_core1_busy_w),
                    .done(kec_core1_done_w),
                    .digest(kec_core1_digest_w)
                );
                assign kec_core1_digest_a_w = kec_core1_digest_w;
                assign kec_core1_digest_b_w = 256'b0;
                assign kec_core1_digest_c_w = 256'b0;
            end

            lms_shake256_blockgen u_blockgen (
                .task_type({1'b0, task_r}),
                .input_words_flat(input_words_flat),
                .identifier_flat(identifier_flat),
                .arg_q(arg_q),
                .arg_i(arg_i),
                .chain_j(chain_j_r),
                .chain_value(chain_value_r),
                .chain_value_b(chain_value_b_r),
                .derive_phase(derive_phase_r),
                .input_length(input_length),
                .seed_a(seed_flat),
                .seed_b(seed_b),
                .rnd_block(rnd_block),
                .rate_block(rate_block_w),
                .rate_block_b(rate_block_b_w),
                .rate_init(rate_init_w),
                .core_digest(core_digest_w),
                .core_digest_a(core_digest_a_w),
                .core_digest_b(core_digest_b_w),
                .core_digest_c(core_digest_c_w),
                .digest_bigendian(digest_be_w),
                .digest_bigendian_a(digest_be_a_w),
                .digest_bigendian_b(digest_be_b_w)
            );

            assign busy = (state_r != ST_IDLE);
            assign done = (state_r == ST_DONE);
            assign digest_out = chain_value_r;
            assign sha_ext_busy = 1'b0;
            assign sha_ext_done = 1'b0;
            assign sha_ext_digest = 256'b0;
            assign sha_ext1_busy = 1'b0;
            assign sha_ext1_done = 1'b0;
            assign sha_ext1_digest = 256'b0;
            assign kec_ext_busy = core_busy_w;
            assign kec_ext_done = core_done_w;
            assign kec_ext_digest = core_digest_w;
            assign kec_ext_digest_a = digest_be_a_w;
            assign kec_ext_digest_b = digest_be_b_w;
            assign kec_ext1_busy = kec_core1_busy_w;
            assign kec_ext1_digest_a = kec_core1_digest_a_w;
            assign kec_ext1_digest_b = kec_core1_digest_b_w ^ kec_core1_digest_c_w;

            reg [7:0] dbg_skew_sr;
            always @(posedge clk) begin
                if (rst) dbg_skew_sr <= 8'h00;
                else     dbg_skew_sr <= {dbg_skew_sr[6:0], kec_core1_done_w};
            end

            reg [15:0] dbg_done_cnt_r;
            reg        dbg_drop_r;
            always @(posedge clk) begin
                if (rst) begin
                    dbg_done_cnt_r <= 16'd0;
                    dbg_drop_r     <= 1'b0;
                end else begin
                    dbg_drop_r <= 1'b0;
                    if (kec_core1_done_w) begin
                        dbg_done_cnt_r <= dbg_done_cnt_r + 16'd1;
                        if ((DBG_DROP_CORE1_DONE != 0) &&
                            (dbg_done_cnt_r == (DBG_DROP_CORE1_DONE - 1))) begin
                            dbg_drop_r <= 1'b1;
                        end
                    end
                end
            end

            wire dbg_drop_now_w = (DBG_DROP_CORE1_DONE != 0) &&
                                  (dbg_done_cnt_r == (DBG_DROP_CORE1_DONE - 1));

            localparam integer DBG_SKEW_IDX = (DBG_CORE1_SKEW < 1) ? 1 :
                                              ((DBG_CORE1_SKEW > 8) ? 8 : DBG_CORE1_SKEW);
            wire dbg_skewed_w = (DBG_CORE1_SKEW == 0) ? kec_core1_done_w
                                                      : dbg_skew_sr[DBG_SKEW_IDX-1];
            assign kec_ext1_done = dbg_skewed_w & ~(dbg_drop_r | (dbg_drop_now_w & kec_core1_done_w));

            assign dbg_eng = {
                state_r,                 /* [31:28] */
                task_r,                  /* [27:26] */
                kec_ext1_start,          /* [25] */
                kec_ext1_init,           /* [24] */
                kec_core1_busy_w,        /* [23] */
                kec_core1_done_w,
                kec_ext_start,           /* [21] */
                kec_ext_init,            /* [20] */
                core_busy_w,             /* [19] */
                core_done_w,             /* [18] */
                2'b00,
                cycle_count[7:0],        /* [15:8] */
                8'h00                    /* [7:0] */
            };
            assign kec_ext1_digest = kec_core1_digest_w;

            always @(posedge clk) begin
                if (rst) begin
                    state_r <= ST_IDLE;
                    task_r <= TASK_HASH_ONCE;
                    chain_value_r <= 256'b0;
                    chain_value_b_r <= 256'b0;
                    chain_j_r <= 8'b0;
                    chain_steps_left_r <= 32'b0;
                    derive_phase_r <= 1'b0;
                    core_start_r <= 1'b0;
                    rnd_delay_r <= 10'd0;
                    rnd_pending_r <= 1'b0;
                    rnd_lfsr_r <= 16'hACE1;
                    core_block_r <= 1088'b0;
                    core_block_b_r <= 1088'b0;
                    core_init_r <= 1'b0;
                    cycle_count <= 32'b0;
                end else begin
                    core_start_r <= 1'b0;

                    rnd_lfsr_r <= {rnd_lfsr_r[14:0],
                                   rnd_lfsr_r[15] ^ rnd_lfsr_r[13] ^
                                   rnd_lfsr_r[12] ^ rnd_lfsr_r[10]};
                    if (start && state_r == ST_IDLE) begin

                        case (command)
                            CMD_CHAIN:             task_r <= TASK_CHAIN;
                            CMD_DERIVE_CHAIN:      task_r <= TASK_DERIVE;
                            CMD_DERIVE_RANDOMIZER: task_r <= TASK_RANDOMIZER;
                            default:               task_r <= TASK_HASH_ONCE;
                        endcase
                        chain_j_r <= arg_start;
                        chain_steps_left_r <= arg_steps;
                        derive_phase_r <= (command == CMD_DERIVE_CHAIN);
                        chain_value_r <= chain_value_in;
                        chain_value_b_r <= 256'b0;
                        cycle_count <= 32'b0;
                        state_r <= ST_ABSORB;
                    end
                    case (state_r)
                        ST_ABSORB: begin

                            core_block_r <= rate_block_w;
                            core_block_b_r <= rate_block_b_w;
                            core_init_r  <= rate_init_w;
                            if (rnd_apply_w && !rnd_pending_r) begin

                                rnd_delay_r <= {1'b1, rnd_lfsr_r[8:0]};
                                rnd_pending_r <= 1'b1;
                            end else if (rnd_apply_w && rnd_pending_r) begin
                                if (rnd_delay_r == 10'd0) begin
                                    rnd_pending_r <= 1'b0;
                                    core_start_r <= 1'b1;
                                    state_r <= ST_WAIT_CORE;
                                end else begin
                                    rnd_delay_r <= rnd_delay_r - 10'd1;
                                end
                            end else begin
                                core_start_r <= 1'b1;
                                state_r <= ST_WAIT_CORE;
                            end
                        end
                        ST_WAIT_CORE: begin
                            if (core_done_w) begin
                                cycle_count <= cycle_count + 32'd12;
                                case (task_r)
                                    TASK_CHAIN: begin
                                        chain_value_r <= digest_next_a_w;
                                        chain_value_b_r <= digest_next_b_w;
                                        if (chain_steps_left_r == 1) begin
                                            state_r <= ST_DONE;
                                        end else begin
                                            chain_j_r <= chain_j_r + 1;
                                            chain_steps_left_r <= chain_steps_left_r - 1;
                                            state_r <= ST_ABSORB;
                                        end
                                    end
                                    TASK_DERIVE: begin
                                        if (derive_phase_r) begin
                                            chain_value_r <= digest_next_a_w;
                                            chain_value_b_r <= digest_next_b_w;
                                            derive_phase_r <= 1'b0;
                                            chain_j_r <= 8'd0;
                                            if (chain_steps_left_r == 0) begin
                                                state_r <= ST_DONE;
                                            end else begin
                                                state_r <= ST_ABSORB;
                                            end
                                        end else begin
                                            chain_value_r <= digest_next_a_w;
                                            chain_value_b_r <= digest_next_b_w;
                                            if (chain_steps_left_r == 1) begin
                                                state_r <= ST_DONE;
                                            end else begin
                                                chain_j_r <= chain_j_r + 1;
                                                chain_steps_left_r <= chain_steps_left_r - 1;
                                                state_r <= ST_ABSORB;
                                            end
                                        end
                                    end
                                    TASK_RANDOMIZER: begin
                                        chain_value_r <= digest_next_a_w;
                                        chain_value_b_r <= digest_next_b_w;
                                        state_r <= ST_DONE;
                                    end
                                    default: begin
                                        chain_value_r <= digest_next_a_w;
                                        chain_value_b_r <= digest_next_b_w;
                                        state_r <= ST_DONE;
                                    end
                                endcase
                            end
                        end
                        ST_DONE: begin
                            state_r <= ST_IDLE;
                        end
                        default: ;
                    endcase
                end
            end
        end else begin : g_sha256
            localparam [1:0] TASK_HASH_ONCE  = 2'd0;
            localparam [1:0] TASK_CHAIN      = 2'd1;
            localparam [1:0] TASK_DERIVE     = 2'd2;
            localparam [1:0] TASK_RANDOMIZER = 2'd3;

            localparam [2:0] ST_IDLE       = 3'd0;
            localparam [2:0] ST_START_CORE = 3'd1;
            localparam [2:0] ST_WAIT_CORE  = 3'd2;
            localparam [2:0] ST_DONE       = 3'd3;

            reg [2:0] state_r;
            reg [1:0] task_r;
            reg [255:0] chain_value_r;
            reg [7:0] chain_j_r;
            reg [31:0] chain_steps_left_r;
            reg derive_phase_r;
            reg [1:0] block_index_r;
            reg [1:0] block_count_r;
            reg core_start_r;
            wire core_busy_w;
            wire core_done_w;
            wire [255:0] core_digest_w;
            wire core1_busy_w;
            wire core1_done_w;
            wire [255:0] core1_digest_w;
            wire [255:0] digest_be_w;
            wire [511:0] block_w;
            wire core_init_w;

            lms_sha256_core sha256 (
                .clk(clk),
                .rst(rst),
                .start(sha_ext_mode ? sha_ext_start : core_start_r),
                .init(sha_ext_mode ? sha_ext_init : core_init_w),
                .state_load(sha_ext_mode ? sha_ext_state_load : 1'b0),
                .state_in(sha_ext_mode ? sha_ext_state_in : 256'b0),
                .block(sha_ext_mode ? sha_ext_block : block_w),
                .busy(core_busy_w),
                .done(core_done_w),
                .digest(core_digest_w)
            );

            lms_sha256_core sha256_core1 (
                .clk(clk),
                .rst(rst),
                .start(sha_ext1_start),
                .init(sha_ext1_init),
                .state_load(sha_ext1_state_load),
                .state_in(sha_ext1_state_in),
                .block(sha_ext1_block),
                .busy(core1_busy_w),
                .done(core1_done_w),
                .digest(core1_digest_w)
            );

            lms_sha256_blockgen u_blockgen (
                .task_type(task_r),
                .input_words_flat(input_words_flat),
                .identifier_flat(identifier_flat),
                .arg_q(arg_q),
                .arg_i(arg_i),
                .chain_j(chain_j_r),
                .chain_value(chain_value_r),
                .derive_phase(derive_phase_r),
                .input_length(input_length),
                .block_index(block_index_r),
                .seed_flat(seed_flat),
                .block(block_w),
                .core_init(core_init_w),
                .core_digest(core_digest_w),
                .digest_bigendian(digest_be_w)
            );

            assign busy = (state_r != ST_IDLE);
            assign done = (state_r == ST_DONE);
            assign digest_out = chain_value_r;
            assign sha_ext_busy = core_busy_w;
            assign sha_ext_done = core_done_w;
            assign sha_ext_digest = core_digest_w;
            assign sha_ext1_busy = core1_busy_w;
            assign sha_ext1_done = core1_done_w;
            assign sha_ext1_digest = core1_digest_w;
            assign kec_ext_busy = 1'b0;
            assign kec_ext_done = 1'b0;
            assign kec_ext_digest = 256'b0;
            assign kec_ext1_busy = 1'b0;
            assign kec_ext1_done = 1'b0;
            assign dbg_eng = 32'b0;
            assign kec_ext1_digest = 256'b0;

            always @(posedge clk) begin
                if (rst) begin
                    state_r <= ST_IDLE;
                    task_r <= TASK_HASH_ONCE;
                    chain_value_r <= 256'b0;
                    chain_j_r <= 8'b0;
                    chain_steps_left_r <= 32'b0;
                    derive_phase_r <= 1'b0;
                    block_index_r <= 2'b0;
                    block_count_r <= 2'b0;
                    core_start_r <= 1'b0;
                    cycle_count <= 32'b0;
                end else begin
                    core_start_r <= 1'b0;
                    if (start && state_r == ST_IDLE) begin
                        case (command)
                            CMD_CHAIN:             task_r <= TASK_CHAIN;
                            CMD_DERIVE_CHAIN:      task_r <= TASK_DERIVE;
                            CMD_DERIVE_RANDOMIZER: task_r <= TASK_RANDOMIZER;
                            default:               task_r <= TASK_HASH_ONCE;
                        endcase
                        chain_value_r <= chain_value_in;
                        chain_j_r <= arg_start;
                        chain_steps_left_r <= arg_steps;
                        derive_phase_r <= (command == CMD_DERIVE_CHAIN);
                        block_index_r <= 2'b0;
                        if (command != CMD_HASH_ONCE || input_length <= 55) begin
                            block_count_r <= 2'd1;
                        end else if (input_length <= 119) begin
                            block_count_r <= 2'd2;
                        end else begin
                            block_count_r <= 2'd3;
                        end
                        cycle_count <= 32'd1;
                        state_r <= ST_START_CORE;
                    end
                    case (state_r)
                        ST_START_CORE: begin
                            cycle_count <= cycle_count + 1'b1;
                            if (!core_busy_w) begin
                                core_start_r <= 1'b1;
                                state_r <= ST_WAIT_CORE;
                            end
                        end
                        ST_WAIT_CORE: begin
                            cycle_count <= cycle_count + 1'b1;
                            if (core_done_w) begin
                                case (task_r)
                                    TASK_CHAIN: begin
                                        chain_value_r <= digest_be_w;
                                        if (chain_steps_left_r == 1) begin
                                            state_r <= ST_DONE;
                                        end else begin
                                            chain_j_r <= chain_j_r + 1'b1;
                                            chain_steps_left_r <= chain_steps_left_r - 1'b1;
                                            state_r <= ST_START_CORE;
                                        end
                                    end
                                    TASK_DERIVE: begin
                                        chain_value_r <= digest_be_w;
                                        if (derive_phase_r) begin
                                            derive_phase_r <= 1'b0;
                                            chain_j_r <= arg_start;
                                            if (chain_steps_left_r == 0) begin
                                                state_r <= ST_DONE;
                                            end else begin
                                                state_r <= ST_START_CORE;
                                            end
                                        end else if (chain_steps_left_r == 1) begin
                                            state_r <= ST_DONE;
                                        end else begin
                                            chain_j_r <= chain_j_r + 1'b1;
                                            chain_steps_left_r <= chain_steps_left_r - 1'b1;
                                            state_r <= ST_START_CORE;
                                        end
                                    end
                                    TASK_RANDOMIZER: begin
                                        chain_value_r <= digest_be_w;
                                        state_r <= ST_DONE;
                                    end
                                    default: begin
                                        if (block_index_r + 1'b1 < block_count_r) begin
                                            block_index_r <= block_index_r + 1'b1;
                                            state_r <= ST_START_CORE;
                                        end else begin
                                            chain_value_r <= digest_be_w;
                                            state_r <= ST_DONE;
                                        end
                                    end
                                endcase
                            end
                        end
                        ST_DONE: state_r <= ST_IDLE;
                        default: ;
                    endcase
                end
            end
        end
    endgenerate

endmodule

`default_nettype wire
