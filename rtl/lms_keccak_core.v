`default_nettype none

//

//

//

//

module lms_keccak_core (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire         init,
    input  wire [1087:0] block,
    output reg          busy,
    output reg          done,
    output wire [255:0] digest
);
    localparam [1:0] PH_IDLE    = 2'd0;
    localparam [1:0] PH_PERMUTE = 2'd1;

    reg [1599:0] state_r;
    reg [3:0]    round_r;
    reg [1:0]    phase_r;

    assign digest = state_r[255:0];

    wire [1599:0] step1_w;
    wire [1599:0] step2_w;

    lms_keccak_round round_u1 (
        .state_i(state_r),
        .rnd({round_r, 1'b0}),
        .state_o(step1_w)
    );
    lms_keccak_round round_u2 (
        .state_i(step1_w),
        .rnd({round_r, 1'b0} + 5'd1),
        .state_o(step2_w)
    );

    always @(posedge clk) begin
        done <= 1'b0;

        if (start && !busy) begin
            if (init) begin
                state_r <= {512'b0, block};
            end else begin
                state_r <= state_r ^ {512'b0, block};
            end
            round_r <= 4'd0;
            phase_r <= PH_PERMUTE;
            busy    <= 1'b1;
        end else if (phase_r == PH_PERMUTE) begin
            state_r <= step2_w;
            if (round_r == 4'd11) begin
                phase_r <= PH_IDLE;
                busy <= 1'b0;
                done <= 1'b1;
            end else begin
                round_r <= round_r + 4'd1;
            end
        end

        if (rst) begin
            state_r <= 1600'b0;
            round_r <= 4'd0;
            phase_r <= PH_IDLE;
            busy <= 1'b0;
            done <= 1'b0;
        end
    end

endmodule

`default_nettype wire
