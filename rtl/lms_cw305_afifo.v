`default_nettype none
`timescale 1 ns / 1 ps

module lms_cw305_afifo #(
    parameter DEPTH = 256,
    parameter ADDRW = 8,            /* log2(DEPTH) */
    parameter DW    = 8
) (
    input  wire             rst,

    input  wire             wclk,
    input  wire             wren,
    input  wire [DW-1:0]    wdata,
    output wire             full,

    input  wire             rclk,
    input  wire             rden,
    output wire [DW-1:0]    rdata,
    output wire             empty,

    output wire [ADDRW:0]   count_rd,
    output wire [ADDRW:0]   count_wr
);
    localparam PTRW = ADDRW + 1;

    reg [DW-1:0] mem [0:DEPTH-1];

    reg [PTRW-1:0] wr_ptr_g, rd_ptr_g;

    reg [PTRW-1:0] wr_ptr_b, rd_ptr_b;
    wire [PTRW-1:0] wr_ptr_b_next = wr_ptr_b + 1'b1;
    wire [PTRW-1:0] rd_ptr_b_next = rd_ptr_b + 1'b1;

    (* ASYNC_REG = "TRUE" *) reg [PTRW-1:0] wr_g_sync1, wr_g_sync2;
    (* ASYNC_REG = "TRUE" *) reg [PTRW-1:0] rd_g_sync1, rd_g_sync2;

    function [PTRW-1:0] gray2bin;
        input [PTRW-1:0] g;
        integer i;
        begin

            gray2bin = g;
            for (i = 0; i < PTRW-1; i = i + 1)
                gray2bin = gray2bin ^ (g >> (i + 1));
        end
    endfunction

    always @(posedge wclk) begin
        if (rst) begin
            wr_ptr_b <= 0;
            wr_ptr_g <= 0;
        end else begin
            if (wren && !full) begin
                mem[wr_ptr_b[ADDRW-1:0]] <= wdata;
                wr_ptr_b <= wr_ptr_b_next;
                wr_ptr_g <= wr_ptr_b_next ^ (wr_ptr_b_next >> 1);
            end
        end
    end

    always @(posedge wclk) begin
        if (rst) begin
            rd_g_sync1 <= 0;
            rd_g_sync2 <= 0;
        end else begin
            rd_g_sync1 <= rd_ptr_g;
            rd_g_sync2 <= rd_g_sync1;
        end
    end

    always @(posedge rclk) begin
        if (rst) begin
            rd_ptr_b <= 0;
            rd_ptr_g <= 0;
        end else begin
            if (rden && !empty) begin
                rd_ptr_b <= rd_ptr_b_next;
                rd_ptr_g <= rd_ptr_b_next ^ (rd_ptr_b_next >> 1);
            end
        end
    end

    always @(posedge rclk) begin
        if (rst) begin
            wr_g_sync1 <= 0;
            wr_g_sync2 <= 0;
        end else begin
            wr_g_sync1 <= wr_ptr_g;
            wr_g_sync2 <= wr_g_sync1;
        end
    end

    assign full  = (wr_ptr_g == {~rd_g_sync2[PTRW-1:PTRW-2], rd_g_sync2[PTRW-3:0]});
    assign empty = (rd_ptr_g == wr_g_sync2);

    assign rdata = mem[rd_ptr_b[ADDRW-1:0]];

    wire [PTRW-1:0] wr_b_in_rd = gray2bin(wr_g_sync2);
    wire [PTRW-1:0] rd_b_in_wr = gray2bin(rd_g_sync2);
    assign count_rd = wr_b_in_rd - rd_ptr_b;
    assign count_wr = wr_ptr_b - rd_b_in_wr;

endmodule

`default_nettype wire
