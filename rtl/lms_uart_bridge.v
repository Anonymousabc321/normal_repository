`default_nettype none

//

//

/* verilator lint_off UNUSEDSIGNAL */

(* keep_hierarchy = "yes" *)
module lms_uart_bridge #(
    parameter [31:0] BRIDGE_BASE = 32'h1800_0000
) (
    input  wire        clk,
    input  wire        rst,

    input  wire        mem_valid,
    input  wire        mem_write,
    input  wire [31:0] mem_addr,
    input  wire [31:0] mem_wdata,
    input  wire [3:0]  mem_wstrb,
    output wire        mem_hit,
    output reg  [31:0] mem_rdata,

    input  wire [7:0]  rx_data,
    input  wire        rx_rdy,
    output wire        rx_ack,

    output reg  [7:0]  tx_data,
    output wire        tx_send,
    input  wire        tx_ready,

    output reg         stream_wr_en,
    output reg  [11:0] stream_wr_addr,
    output reg  [31:0] stream_wr_data,
    output reg         stream_rd_en,
    output reg  [11:0] stream_rd_addr,
    input  wire        stream_rd_valid,
    input  wire [31:0] stream_rd_data,
    input  wire        stream_busy,
    output wire        busy
);
    localparam [9:0] REG_CTRL  = 10'h000;
    localparam [9:0] REG_ADDR  = 10'h004;
    localparam [9:0] REG_LEN   = 10'h008;
    localparam [9:0] REG_DEBUG = 10'h00c;

    localparam [2:0] S_IDLE    = 3'd0;
    localparam [2:0] S_RX_BYTE = 3'd1;
    localparam [2:0] S_RX_WR   = 3'd2;
    localparam [2:0] S_TX_RD   = 3'd3;
    localparam [2:0] S_TX_LOAD = 3'd4;
    localparam [2:0] S_TX_PUT  = 3'd5;
    localparam [2:0] S_DONE    = 3'd6;

    /* verilator lint_off UNUSEDSIGNAL */
    (* fsm_encoding = "none" *) (* keep = "true" *) reg [2:0] state_r;
    reg [11:0] word_addr_r;
    reg [15:0] byte_left_r;
    reg [11:0] word_left_r;
    (* keep = "true" *) reg [31:0] wdata_buf_r;
    reg [1:0]  wbyte_idx_r;
    reg [1:0]  rbyte_idx_r;
    reg [31:0] rdata_buf_r;
    reg        byte_sent_r;
    reg        tx_hold_r;
    reg        busy_r;
    reg        done_r;
    reg        error_r;
    reg        tx_send_r;
    reg [11:0] dbg_wl_start;

    wire address_hit = mem_valid && mem_addr[31:10] == BRIDGE_BASE[31:10];
    assign mem_hit = address_hit;

    assign rx_ack = state_r == S_RX_BYTE && rx_rdy;
    assign tx_send = tx_send_r;
    assign busy = busy_r;

    wire start_req = mem_valid && mem_write && address_hit &&
                     mem_addr[9:0] == REG_CTRL && (mem_wdata[0] & mem_wstrb[0]);

    always @(posedge clk) begin
        if (rst) begin
            state_r        <= S_IDLE;
            word_addr_r    <= 12'b0;
            byte_left_r    <= 16'b0;
            word_left_r    <= 12'b0;
            wdata_buf_r    <= 32'b0;
            wbyte_idx_r    <= 2'b0;
            rbyte_idx_r    <= 2'b0;
            rdata_buf_r    <= 32'b0;
            byte_sent_r    <= 1'b0;
            tx_hold_r      <= 1'b0;
            busy_r         <= 1'b0;
            done_r         <= 1'b0;
            error_r        <= 1'b0;
            tx_send_r      <= 1'b0;
            tx_data        <= 8'b0;
            stream_wr_en   <= 1'b0;
            stream_wr_addr <= 12'b0;
            stream_wr_data <= 32'b0;
            stream_rd_en   <= 1'b0;
            stream_rd_addr <= 12'b0;
        end else begin
            tx_send_r      <= 1'b0;
            stream_wr_en   <= 1'b0;
            stream_rd_en   <= 1'b0;

            if (mem_valid && mem_write && address_hit && !busy_r) begin
                if (mem_addr[9:0] == REG_ADDR && mem_wstrb[0]) begin
                    word_addr_r <= mem_wdata[11:0];
                end else if (mem_addr[9:0] == REG_LEN && mem_wstrb[0]) begin
                    byte_left_r <= mem_wdata[15:0];
                end
            end

            case (state_r)
                S_IDLE: begin
                    if (start_req) begin
                        if (stream_busy || byte_left_r == 16'b0 ||
                            (byte_left_r & 16'h3) != 16'b0 ||
                            byte_left_r > 16'd8608) begin
                            error_r <= 1'b1;
                            done_r  <= 1'b0;
                            state_r <= S_DONE;
                        end else begin
                            busy_r      <= 1'b1;
                            done_r      <= 1'b0;
                            error_r     <= 1'b0;
                            wbyte_idx_r <= 2'b0;
                            rbyte_idx_r <= 2'b0;
                            byte_sent_r <= 1'b0;
                            tx_hold_r   <= 1'b0;
                            if (mem_wdata[1]) begin
                                word_left_r  <= byte_left_r[13:2];
                                dbg_wl_start <= byte_left_r[13:2];
                                state_r      <= S_TX_RD;
                            end else begin
                                state_r      <= S_RX_BYTE;
                            end
                        end
                    end
                end

                S_RX_BYTE: begin
                    if (rx_rdy) begin

                        wdata_buf_r <= {rx_data, wdata_buf_r[31:8]};
                        byte_left_r <= byte_left_r - 16'd1;
                        if (wbyte_idx_r == 2'd3) begin
                            wbyte_idx_r <= 2'b0;
                            state_r     <= S_RX_WR;
                        end else begin
                            wbyte_idx_r <= wbyte_idx_r + 2'd1;
                        end
                    end
                end
                S_RX_WR: begin
                    stream_wr_en   <= 1'b1;
                    stream_wr_addr <= word_addr_r;
                    stream_wr_data <= wdata_buf_r;
                    if (byte_left_r == 16'b0) begin
                        busy_r <= 1'b0;
                        done_r <= 1'b1;
                        state_r <= S_DONE;
                    end else begin
                        word_addr_r <= word_addr_r + 12'd1;
                        state_r     <= S_RX_BYTE;
                    end
                end

                S_TX_RD: begin
                    stream_rd_en   <= 1'b1;
                    stream_rd_addr <= word_addr_r;
                    state_r        <= S_TX_LOAD;
                end
                S_TX_LOAD: begin
                    if (stream_rd_valid) begin
                        rdata_buf_r <= stream_rd_data;
                        rbyte_idx_r <= 2'b0;
                        byte_sent_r <= 1'b0;
                        tx_hold_r   <= 1'b0;
                        state_r     <= S_TX_PUT;
                    end
                end
                S_TX_PUT: begin
                    if (!byte_sent_r && tx_ready) begin

                        byte_sent_r <= 1'b1;
                        tx_hold_r   <= 1'b1;
                        tx_send_r   <= 1'b1;
                        tx_data     <= rdata_buf_r[7:0];
                    end else if (!tx_hold_r && tx_ready) begin

                        rbyte_idx_r <= rbyte_idx_r + 2'd1;
                        if (rbyte_idx_r == 2'd3) begin

                            word_left_r <= word_left_r - 12'd1;
                            if (word_left_r == 12'd1) begin
                                busy_r <= 1'b0;
                                done_r <= 1'b1;
                                state_r <= S_DONE;
                            end else begin
                                word_addr_r <= word_addr_r + 12'd1;
                                state_r     <= S_TX_RD;
                            end
                        end else begin
                            case (rbyte_idx_r)
                                2'd0: begin
                                    tx_data <= rdata_buf_r[15:8];
                                end
                                2'd1: begin
                                    tx_data <= rdata_buf_r[23:16];
                                end
                                default: begin
                                    tx_data <= rdata_buf_r[31:24];
                                end
                            endcase
                            tx_hold_r <= 1'b1;
                            tx_send_r <= 1'b1;
                        end
                    end else begin
                        tx_hold_r <= 1'b0;
                    end
                end
                S_DONE: begin
                    dbg_wl_start <= word_left_r;
                    if (mem_valid && mem_write && address_hit &&
                        mem_addr[9:0] == REG_CTRL && (mem_wdata[1] & mem_wstrb[0])) begin

                        done_r  <= 1'b0;
                        error_r <= 1'b0;
                        busy_r  <= 1'b0;
                        state_r <= S_IDLE;
                    end
                end
                default: state_r <= S_IDLE;
            endcase
        end
    end

    always @* begin
        mem_rdata = 32'b0;
        case (mem_addr[9:0])
            REG_CTRL: mem_rdata = {29'b0, error_r, done_r, busy_r};
            REG_ADDR: mem_rdata = {20'b0, word_addr_r};
            REG_LEN:  mem_rdata = {16'b0, byte_left_r};
            REG_DEBUG: mem_rdata = {20'b0, dbg_wl_start};
            default: ;
        endcase
    end

endmodule

`default_nettype wire
