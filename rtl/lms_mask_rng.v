`default_nettype none

// Ring-oscillator entropy seeds the DRBG. Its output supplies the seed
// shares and a 1088-bit mask for each rate block.

module lms_mask_rng #(
    parameter TRNG_SIM_MODE  = 0,
    parameter RESEED_TAKES   = 64
) (
    input  wire          clk,
    input  wire          rst,

    output wire [255:0]  seed_share,
    output wire          seed_share_valid,

    output wire [63:0]   mask_word,
    output wire          mask_valid,

    output reg  [1087:0] rnd_block,
    output reg           rnd_block_valid,
    input  wire          rnd_block_ack,

    output reg           rnd_fail,
    output wire          health_fail,
    output reg  [15:0]   reseed_count
);

    wire [31:0] ent_word_w;
    wire        ent_valid_w;
    wire        ent_health_w;

    lms_trng #(
        .SIM_MODE(TRNG_SIM_MODE)
    ) u_trng (
        .clk(clk),
        .rst(rst),
        .enable(1'b1),
        .rct_cutoff(8'd64),
        .apt_cutoff(11'd650),
        .clear_fail(1'b0),
        .rnd_word(ent_word_w),
        .word_valid(ent_valid_w),
        .health_fail(ent_health_w),
        .rct_count(),
        .apt_count(),
        .apt_win_pos()
    );

    assign health_fail = (TRNG_SIM_MODE != 0) ? 1'b0 : ent_health_w;
    wire drbg_fail_w;

    wire [63:0] drbg_word_w;
    wire        drbg_valid_w;
    wire        drbg_seed_ready_w;
    wire        reseed_busy_w;

    reg  [255:0] seed_win_r;
    reg  [255:0] seed_win_next_r;
    reg  [2:0]   seed_fill_cnt_r;
    reg          seed_fill_r;
    reg          seed_win_valid_r;
    wire         seed_take_w = seed_fill_r && drbg_valid_w;

    assign seed_share       = seed_win_r;
    assign seed_share_valid = seed_win_valid_r;
    assign mask_word        = drbg_word_w;
    assign mask_valid       = drbg_valid_w;

    reg  [255:0] seed_r;
    reg  [2:0]   seed_cnt_r;
    reg          seed_valid_r;
    reg  [15:0]  take_cnt_r;
    reg          collect_r;

    reg  [1087:0] r_acc_r;
    reg  [4:0]    r_cnt_r;
    reg           filling_r;
    wire          pool_take_w = (filling_r || seed_fill_r) && drbg_valid_w;

    always @(posedge clk) begin
        if (rst) begin
            seed_r       <= 256'b0;
            seed_cnt_r   <= 3'd0;
            seed_valid_r <= 1'b0;
            take_cnt_r   <= 16'd0;
            collect_r    <= 1'b1;
            rnd_fail     <= 1'b0;
            reseed_count <= 16'd0;
            r_acc_r      <= 1088'b0;
            r_cnt_r      <= 5'd0;
            filling_r    <= 1'b1;
            rnd_block    <= 1088'b0;
            rnd_block_valid <= 1'b0;
            seed_win_r       <= 256'b0;
            seed_win_next_r  <= 256'b0;
            seed_fill_cnt_r  <= 3'd0;
            seed_fill_r      <= 1'b0;
            seed_win_valid_r <= 1'b0;
        end else begin

            if (seed_valid_r && drbg_seed_ready_w) begin
                seed_valid_r <= 1'b0;
            end

            if (((TRNG_SIM_MODE == 0) && ent_health_w) || drbg_fail_w) begin
                rnd_fail <= 1'b1;
            end

            if (collect_r && ent_valid_w) begin
                seed_r     <= {seed_r[223:0], ent_word_w};
                seed_cnt_r <= seed_cnt_r + 3'd1;
                if (seed_cnt_r == 3'd7) begin
                    seed_valid_r <= 1'b1;
                    seed_cnt_r   <= 3'd0;
                    collect_r    <= 1'b0;
                    reseed_count <= reseed_count + 16'd1;
                end
            end
            if (rnd_block_ack && (take_cnt_r >= (RESEED_TAKES - 1))) begin
                take_cnt_r <= 16'd0;
                collect_r  <= 1'b1;
            end else if (rnd_block_ack) begin
                take_cnt_r <= take_cnt_r + 16'd1;
            end

            if (rnd_block_ack) begin
                rnd_block_valid <= 1'b0;
                filling_r       <= 1'b1;
                r_cnt_r         <= 5'd0;
                seed_fill_r      <= 1'b0;
                seed_fill_cnt_r  <= 3'd0;
            end else if (rnd_block_valid) begin
                filling_r <= 1'b0;
            end

            if (filling_r && drbg_valid_w) begin
                r_acc_r <= {r_acc_r[1023:0], drbg_word_w};
                r_cnt_r <= r_cnt_r + 5'd1;
                if (r_cnt_r == 5'd16) begin
                    rnd_block       <= {r_acc_r[1023:0], drbg_word_w};
                    rnd_block_valid <= 1'b1;
                    filling_r       <= 1'b0;
                    r_cnt_r         <= 5'd0;
                    seed_fill_r     <= 1'b1;
                    seed_fill_cnt_r <= 3'd0;
                end
            end

            if (seed_take_w) begin
                if (seed_fill_cnt_r == 3'd3) begin
                    seed_win_r       <= {seed_win_next_r[191:0], drbg_word_w};
                    seed_win_valid_r <= 1'b1;
                    seed_fill_r      <= 1'b0;
                end else begin
                    seed_win_next_r <= {seed_win_next_r[191:0], drbg_word_w};
                end
                seed_fill_cnt_r <= seed_fill_cnt_r + 3'd1;
            end
        end
    end

    /* ---------------- DRBG ---------------- */
    lms_hmac_drbg u_drbg (
        .clk(clk),
        .rst(rst),
        .seed_valid(seed_valid_r),
        .seed_data(seed_r),
        .seed_ready(drbg_seed_ready_w),
        .take(pool_take_w),
        .mask_word(drbg_word_w),
        .mask_valid(drbg_valid_w),
        .reseed_busy(reseed_busy_w),
        .rnd_fail(drbg_fail_w),
        .reseed_count()
    );

endmodule

`default_nettype wire
