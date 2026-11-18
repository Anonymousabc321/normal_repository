`default_nettype none

// HMAC-SHA-256 DRBG with a 256-bit seed input and a pool of 64-bit mask words.

module lms_hmac_drbg #(
    parameter POOL_WORDS = 16
) (
    input  wire         clk,
    input  wire         rst,
    input  wire         seed_valid,
    output wire         seed_ready,
    input  wire [255:0] seed_data,
    input  wire         take,
    output wire [63:0]  mask_word,
    output wire         mask_valid,
    output wire         reseed_busy,
    output reg          rnd_fail,
    output reg  [15:0]  reseed_count
);

    localparam [255:0] V_INIT = {8{32'h01010101}};

    /* ---------------- SHA-256 core ---------------- */
    wire [511:0] blk_d;
    reg          start_d, init_d, sload_d;
    reg  [255:0] digest_r;
    wire [255:0] digest_w;
    wire         busy_w, done_w;

    lms_sha256_core u_sha (
        .clk(clk), .rst(rst),
        .start(start_d), .init(init_d), .state_load(sload_d),
        .state_in(digest_r), .block(blk_d),
        .busy(busy_w), .done(done_w), .digest(digest_w)
    );

    reg [63:0] pool [0:POOL_WORDS-1];
    reg [3:0]  wr_p, rd_p;
    reg [4:0]  cnt;
    assign mask_valid = (cnt != 5'd0);
    assign mask_word  = pool[rd_p];

    reg [255:0] k_r, v_r, data_r, inner_r, key_r;

    reg [2:0] sel;

    wire [15:0] inner_len_w = (mode_upd && ((hm == 2'd0) || (hm == 2'd2))) ? 16'h0408 : 16'h0300;
    wire [15:0] outer_len_w = 16'h0300;

    function [7:0] kf(input integer i); begin kf = key_r[255 - i*8 -: 8]; end endfunction
    function [7:0] vf(input integer i); begin vf = v_r  [255 - i*8 -: 8]; end endfunction
    function [7:0] df(input integer i); begin df = data_r[255 - i*8 -: 8]; end endfunction
    function [7:0] if_(input integer i); begin if_ = inner_r[255 - i*8 -: 8]; end endfunction

    function [7:0] byte_for(input [2:0] s, input integer i);
        begin
            case (s)
            3'd0: byte_for = (i < 32) ? (kf(i) ^ 8'h36) : 8'h36;
            3'd1: byte_for = (i < 32) ? (kf(i) ^ 8'h5c) : 8'h5c;
            3'd2: byte_for = (i < 32) ? vf(i) : ((i == 32) ? 8'h00 : df(i - 33));
            3'd3: byte_for = (i == 0) ? df(31) : (i == 1) ? 8'h80 :
                              (i == 62) ? inner_len_w[15:8] : (i == 63) ? inner_len_w[7:0] : 8'h00;
            3'd4: byte_for = (i < 32) ? vf(i) : (i == 32) ? 8'h80 :
                              (i == 62) ? outer_len_w[15:8] : (i == 63) ? outer_len_w[7:0] : 8'h00;
            3'd5: byte_for = (i < 32) ? if_(i) : (i == 32) ? 8'h80 :
                              (i == 62) ? outer_len_w[15:8] : (i == 63) ? outer_len_w[7:0] : 8'h00;
            3'd6: byte_for = (i < 32) ? vf(i) : ((i == 32) ? 8'h01 : df(i - 33));
            3'd7: byte_for = (i == 0) ? df(31) : (i == 1) ? 8'h80 :
                              (i == 62) ? inner_len_w[15:8] : (i == 63) ? inner_len_w[7:0] : 8'h00;
            default: byte_for = 8'h00;
            endcase
        end
    endfunction

    genvar gi;
    generate
        for (gi = 0; gi < 64; gi = gi + 1) begin : g_blk

            assign blk_d[(63 - gi)*8 +: 8] = byte_for(sel, gi);
        end
    endgenerate

    /* ---------------- FSM ---------------- */
    localparam [2:0] S_IDLE = 3'd0, S_START = 3'd1, S_WAIT = 3'd2;

    reg [2:0] st;
    reg       seeded_r;
    reg       mode_upd;     /* 1=Update(seed) 0=Generate */
    reg [1:0] hm;
    reg       outer_r;
    reg [1:0] bi;

    wire [1:0] n_inner_w = !mode_upd ? 2'd2 :
                          ((hm[0] == 1'b0) ? 2'd3 : 2'd2);

    always @(posedge clk) begin
        if (rst) begin
            st <= S_IDLE; mode_upd <= 1'b0; hm <= 2'd0; outer_r <= 1'b0; bi <= 2'd0;
            k_r <= 256'b0; v_r <= V_INIT; data_r <= 256'b0; inner_r <= 256'b0; key_r <= 256'b0;
            digest_r <= 256'b0; wr_p <= 4'd0; rd_p <= 4'd0; cnt <= 5'd0;
            rnd_fail <= 1'b0; reseed_count <= 16'd0; seeded_r <= 1'b0;
            start_d <= 1'b0; init_d <= 1'b0; sload_d <= 1'b0; sel <= 3'd0;
        end else begin
            start_d <= 1'b0;

            if (take && (cnt != 5'd0)) begin
                rd_p <= rd_p + 4'd1;
                cnt  <= cnt - 5'd1;
            end

            case (st)
            S_IDLE: begin
                if (seed_valid) begin
                    data_r <= seed_data; k_r <= 256'b0; v_r <= V_INIT;
                    key_r <= 256'b0; mode_upd <= 1'b1; hm <= 2'd0;
                    outer_r <= 1'b0; bi <= 2'd0;
                    reseed_count <= reseed_count + 16'd1;
                    st <= S_START;
                end else if (seeded_r && (cnt <= 5'd12)) begin
                    key_r <= k_r; mode_upd <= 1'b0; hm <= 2'd0;
                    outer_r <= 1'b0; bi <= 2'd0;
                    st <= S_START;
                end
            end

            S_START: begin
                start_d <= 1'b1;
                init_d  <= (bi == 2'd0);
                sload_d <= (bi != 2'd0);
                if (!outer_r) begin
                    if (bi == 2'd0)          sel <= 3'd0;                   /* ipad */
                    else if (!mode_upd)      sel <= 3'd4;
                    else if (hm[0] == 1'b1)  sel <= 3'd4;                   /* V = HMAC(K,V) */
                    else if (bi == 2'd1)     sel <= (hm == 2'd0) ? 3'd2 : 3'd6;
                    else                     sel <= (hm == 2'd0) ? 3'd3 : 3'd7;
                end else begin
                    sel <= (bi == 2'd0) ? 3'd1 : 3'd5;
                end

                st <= S_WAIT;
            end

            S_WAIT: begin
                start_d <= 1'b0;
                if (done_w) begin
                    start_d  <= 1'b0;
                    digest_r <= digest_w;
                    if (!outer_r) begin
                        if (bi + 2'd1 < n_inner_w) begin
                            bi <= bi + 2'd1;
                        end else begin
                            inner_r <= digest_w;
                            outer_r <= 1'b1;
                            bi <= 2'd0;
                        end
                        st <= S_START;
                    end else begin
                        if (bi == 2'd0) begin
                            bi <= 2'd1;
                            st <= S_START;
                        end else if (!mode_upd) begin

                            v_r <= digest_w;

                            pool[wr_p]                 <= digest_w[255:192];
                            pool[(wr_p + 4'd1) & 4'hf] <= digest_w[191:128];
                            pool[(wr_p + 4'd2) & 4'hf] <= digest_w[127:64];
                            pool[(wr_p + 4'd3) & 4'hf] <= digest_w[63:0];
                            wr_p <= wr_p + 4'd4;
                            cnt  <= (cnt > 5'd12) ? 5'd16 :
                                    (cnt + 5'd4 - ((take && (cnt != 5'd0)) ? 5'd1 : 5'd0));
                            st <= S_IDLE;
                        end else begin

                            case (hm)
                            2'd0: begin k_r <= digest_w; key_r <= digest_w;
                                         v_r <= v_r; hm <= 2'd1; end
                            2'd1: begin v_r <= digest_w; key_r <= k_r; hm <= 2'd2; end
                            2'd2: begin k_r <= digest_w; key_r <= digest_w; hm <= 2'd3; end
                            default: begin v_r <= digest_w; mode_upd <= 1'b0; hm <= 2'd0;
                                             seeded_r <= 1'b1; end
                            endcase
                            outer_r <= 1'b0;
                            bi <= 2'd0;
                            st <= S_START;
                        end
                    end
                end
            end
            default: st <= S_IDLE;
            endcase
        end
    end

    assign reseed_busy = (st != S_IDLE) || mode_upd;

    assign seed_ready  = (st == S_IDLE) && !rst;

endmodule
`default_nettype wire
