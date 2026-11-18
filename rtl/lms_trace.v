//

//

//    lms_trace #(.DEPTH_LOG2(12)) u_trace (
//      .clk(clk50), .rst(rst), .probe(probe), .trig(trig), .arm(arm_pulse_sync),
//      .decim(4'd0), .cap_busy(cap_busy), .cap_done(cap_done), .cap_trig_seen(cap_trig_seen),
//      .rclk(usb_clk), .raddr(index), .rdata(sample));
//

`default_nettype none

module lms_trace #(
    parameter DEPTH_LOG2 = 12
) (

    input  wire                     clk,
    input  wire                     rst,
    input  wire [63:0]              probe,
    input  wire                     trig,
    input  wire                     arm,
    input  wire [3:0]               decim,
    output reg                      cap_busy,
    output reg                      cap_done,
    output reg                      cap_trig_seen,

    input  wire                     rclk,
    input  wire [DEPTH_LOG2-1:0]    raddr,
    output reg  [63:0]              rdata
);

    localparam DEPTH = (1 << DEPTH_LOG2);

    reg [63:0] mem [0:DEPTH-1];

    reg [DEPTH_LOG2-1:0] wptr;
    reg [3:0]            div_cnt;

    always @(posedge clk) begin
        if (rst) begin
            wptr         <= {DEPTH_LOG2{1'b0}};
            div_cnt      <= 4'd0;
            cap_busy     <= 1'b0;
            cap_done     <= 1'b0;
            cap_trig_seen <= 1'b0;
        end else begin
            if (arm) begin
                wptr          <= {DEPTH_LOG2{1'b0}};
                div_cnt       <= 4'd0;
                cap_busy      <= 1'b1;
                cap_done      <= 1'b0;
                cap_trig_seen <= 1'b0;
            end else if (cap_busy) begin
                if (cap_trig_seen || trig) begin
                    if (trig) begin
                        cap_trig_seen <= 1'b1;
                    end
                    if (div_cnt != 4'd0) begin
                        div_cnt <= div_cnt - 4'd1;
                    end else begin
                        div_cnt <= decim;
                        mem[wptr] <= probe;
                        wptr <= wptr + 1'b1;
                        if (wptr == (DEPTH - 1)) begin
                            cap_busy <= 1'b0;
                            cap_done <= 1'b1;
                        end
                    end
                end
            end
        end
    end

    always @(posedge rclk) begin
        rdata <= mem[raddr];
    end

endmodule

`default_nettype wire
