`default_nettype none

// ============================================================================
// lms_keccak_core_masked.v - TI 3-share masked Keccak-p[1600] core
// (SHAKE256, rate=1088-bit, unroll-2). Interface-identical to lms_keccak_core.
//

// Each enabled lane instantiates a masked core. The caller latches
// block_a and block_b in the same cycle.
//
// Masking scheme: Threshold Implementation with 3 Boolean shares (a,b,c),
// a ^ b ^ c = state. Linear layers (theta/rho/pi) are applied per share
// (linear, share structure preserved). Chi is computed with pairwise threshold
// logic (kecti3_tchi) so no share is combined with more than one other at a
// time. Iota XORs the round constant into share a only.
// Round logic: rtl/kecti3_round.v (SLotH, BSD 3-Clause, verbatim copy).
//
// Interface semantics:
//   - start+init=1 : first block absorb (state cleared then XOR this rate block)
//   - start+init=0 : continue absorb (state XOR this rate block)
//   Each block absorb then permutes 12 cycles and asserts done.
//   digest_a/b/c expose the shares. `digest` is a PUBLIC-only recombination:
//   the XOR tree inputs are AND-gated with (digest_public && !busy), so while a
//   secret operation runs the tree is held at constant 0 and does not toggle
//   (no per-cycle plaintext recombination). It is valid only for consumers
//   whose command/phase is declared public by the wrapper.
//
// Input sharing is supplied by the caller: a = block ^ r, b = r, c = 0;
// capacity shares start at zero. Correctness is exact for any r.
// ============================================================================

module lms_keccak_core_masked (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire         init,
    input  wire [1087:0] block_a,
    input  wire [1087:0] block_b,
    input  wire          digest_public = 1'b0,
    output reg          busy,
    output reg          done,
    output wire [255:0] digest,
    output wire [255:0] digest_a,
    output wire [255:0] digest_b,
    output wire [255:0] digest_c
);
    localparam [1:0] PH_IDLE    = 2'd0;
    localparam [1:0] PH_PERMUTE = 2'd1;

    reg [1599:0] a_r;
    reg [1599:0] b_r;
    reg [1599:0] c_r;
    reg [3:0]    round_r;
    reg [1:0]    phase_r;

    wire digest_rcomb_en_w = digest_public && !busy;
    wire [255:0] digest_gate_a_w;
    wire [255:0] digest_gate_b_w;
    wire [255:0] digest_gate_c_w;
    (* dont_touch = "true" *) lms_share_gate u_digest_gate_a (
        .d(a_r[255:0]), .en(digest_rcomb_en_w), .q(digest_gate_a_w));
    (* dont_touch = "true" *) lms_share_gate u_digest_gate_b (
        .d(b_r[255:0]), .en(digest_rcomb_en_w), .q(digest_gate_b_w));
    (* dont_touch = "true" *) lms_share_gate u_digest_gate_c (
        .d(c_r[255:0]), .en(digest_rcomb_en_w), .q(digest_gate_c_w));
    assign digest = digest_gate_a_w ^ digest_gate_b_w ^ digest_gate_c_w;
    assign digest_a = a_r[255:0];
    assign digest_b = b_r[255:0];
    assign digest_c = c_r[255:0];

    function automatic [7:0] rc_step;
        input [7:0] r_i;
        begin
            rc_step = ({8{r_i[0]}} & 8'h1A) ^ ({8{r_i[1]}} & 8'h34) ^
                      ({8{r_i[2]}} & 8'h68) ^ ({8{r_i[3]}} & 8'hD0) ^
                      ({8{r_i[4]}} & 8'hBA) ^ ({8{r_i[5]}} & 8'h6E) ^
                      ({8{r_i[6]}} & 8'hC6) ^ ({8{r_i[7]}} & 8'h8D);
        end
    endfunction

    wire [7:0] rc_r1_w;
    wire [7:0] rc_r2_w;
    reg  [7:0] rc_count_r;

    wire [1599:0] a1_w, b1_w, c1_w;
    wire [1599:0] a2_w, b2_w, c2_w;

    kecti3_round round_u1 (
        .a_o(a1_w), .b_o(b1_w), .c_o(c1_w),
        .a_i(a_r),  .b_i(b_r),  .c_i(c_r),
        .r_i(rc_count_r)
    );
    kecti3_round round_u2 (
        .a_o(a2_w), .b_o(b2_w), .c_o(c2_w),
        .a_i(a1_w), .b_i(b1_w), .c_i(c1_w),
        .r_i(rc_step(rc_count_r))
    );

    always @(posedge clk) begin

        done <= 1'b0;

        if (start && !busy) begin
            if (init) begin
                a_r <= {512'b0, block_a};
                b_r <= {512'b0, block_b};
                c_r <= 1600'b0;
            end else begin

                a_r <= (a_r ^ {512'b0, block_a});
                b_r <= (b_r ^ {512'b0, block_b});
            end
            rc_count_r <= 8'h01;
            round_r <= 4'd0;
            phase_r <= PH_PERMUTE;
            busy <= 1'b1;
        end else if (phase_r == PH_PERMUTE) begin
            a_r <= a2_w;
            b_r <= b2_w;
            c_r <= c2_w;
            rc_count_r <= rc_step(rc_step(rc_count_r));
            if (round_r == 4'd11) begin
                phase_r <= PH_IDLE;
                busy <= 1'b0;
                done <= 1'b1;
            end else begin
                round_r <= round_r + 4'd1;
            end
        end

        if (rst) begin
            a_r <= 1600'b0;
            b_r <= 1600'b0;
            c_r <= 1600'b0;
            round_r <= 4'd0;
            phase_r <= PH_IDLE;
            busy <= 1'b0;
            done <= 1'b0;
            rc_count_r <= 8'h01;
        end
    end

endmodule

(* dont_touch = "true" *) module lms_share_gate #(
    parameter W = 256
) (
    input  wire [W-1:0] d,
    input  wire         en,
    output wire [W-1:0] q
);
    assign q = d & {W{en}};
endmodule

`default_nettype wire
