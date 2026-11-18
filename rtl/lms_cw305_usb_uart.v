`default_nettype none
`include "lms_soc_config.vh"
`include "lms_cw305_regs.vh"

/* verilator lint_off DECLFILENAME */
/*
ChipWhisperer Artix Target - Example frontend to USB interface.
Copyright (c) 2020, NewAE Technology Inc.
Redistribution and use in source and binary forms, with or without
modification, are permitted without restriction. Note that modules within
the project may have additional restrictions, please carefully inspect
additional licenses.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
module cw305_usb_reg_fe #(
    parameter pADDR_WIDTH = 21,
    parameter pBYTECNT_SIZE = 7,
    parameter pREG_RDDLY_LEN = 3
)(
    input  wire                         usb_clk,
    input  wire                         rst,

    // Interface to host
    input  wire [7:0]                   usb_din,
    output wire [7:0]                   usb_dout,
    output wire                         usb_isout,
    input  wire [pADDR_WIDTH-1:0]       usb_addr,
    input  wire                         usb_rdn,
    input  wire                         usb_wrn,
    input  wire                         usb_alen,        // unused here
    input  wire                         usb_cen,

    // Interface to registers
    output wire [pADDR_WIDTH-1:pBYTECNT_SIZE] reg_address,  // Address of register
    output wire [pBYTECNT_SIZE-1:0]     reg_bytecnt,  // Current byte count
    output reg  [7:0]                   reg_datao,    // Data to write
    input  wire [7:0]                   reg_datai,    // Data to read
    output reg                          reg_read,     // Read flag. One clock cycle AFTER this flag is high
                                                      // valid data must be present on the reg_datai bus
    output wire                         reg_write,    // Write flag. When high on rising edge valid data is
                                                      // present on reg_datao
    output wire                         reg_addrvalid // Address valid flag
);

    reg [pADDR_WIDTH-1:0] usb_addr_r;
    reg usb_rdn_r;
    reg usb_wrn_r;
    reg usb_cen_r;
    reg [pREG_RDDLY_LEN-1:0] isoutreg;

    // register USB interface inputs:
    always @(posedge usb_clk) begin
        usb_addr_r <= usb_addr;
        usb_rdn_r <= usb_rdn;
        usb_wrn_r <= usb_wrn;
        usb_cen_r <= usb_cen;
    end

    assign reg_addrvalid = 1'b1;

    // reg_address selects the register:
    assign reg_address = usb_addr_r[pADDR_WIDTH-1:pBYTECNT_SIZE];

    // reg_bytecnt selects the byte within the register:
    assign reg_bytecnt = usb_addr_r[pBYTECNT_SIZE-1:0];

    assign reg_write = ~usb_cen_r & ~usb_wrn_r;

    always @(posedge usb_clk) begin
        if (~usb_cen & ~usb_rdn)
            reg_read <= 1'b1;
        else if (usb_rdn)
            reg_read <= 1'b0;
    end

    // drive output data bus:
    always @(posedge usb_clk) begin
        if (rst) begin
            isoutreg <= 0;
        end else begin
           isoutreg[0] <= ~usb_rdn_r;
           isoutreg[pREG_RDDLY_LEN-1:1] <= isoutreg[pREG_RDDLY_LEN-2:0];
        end
    end
    assign usb_isout = (|isoutreg) | (~usb_rdn_r);

    assign usb_dout = reg_datai;

    always @(posedge usb_clk)
        reg_datao <= usb_din;

endmodule
/* verilator lint_on DECLFILENAME */

module lms_cw305_usb_uart #(
    parameter pCRYPT_TYPE  = 8'h4D,
    parameter pCRYPT_REV   = 8'h01,
    parameter pIDENTIFY    = 8'h4C,       /* 'L' */
    parameter UART_BITCLKS = `LMS_SOC_CLK / 115200
) (

    input  wire         usb_clk,
    input  wire         rst,
    input  wire [7:0]   usb_din,
    output wire [7:0]   usb_dout,
    output wire         usb_isout,
    input  wire [20:0]  usb_addr,
    input  wire         usb_rdn,
    input  wire         usb_wrn,
    input  wire         usb_alen,
    input  wire         usb_cen,

    input  wire         iut_clk,
    /* Trusted management mailbox: direct wires to KSD, never CPU MMIO. */
    output wire         ksd_recover_valid,
    output wire [895:0]  ksd_recover_record,
    input  wire         ksd_recover_accept,
    output wire         ksd_ack_valid,
    output wire [895:0]  ksd_ack_record,
    input  wire         ksd_ack_accept,
    input  wire         ksd_persist_valid,
    input  wire [895:0]  ksd_persist_record,
    output wire         ksd_trusted_fault,
    input  wire         soc_uart_txd,
    output wire         soc_uart_rxd,
    output wire         soc_uart_cts,

    input  wire         trap_in,         /* SoC trap → REG_STATUS[0] */
    output reg          o_user_led
);

    assign soc_uart_cts = !txf_full;
    localparam UART_BITCLKS_USE = UART_BITCLKS > 0 ? UART_BITCLKS : (`LMS_SOC_CLK / 115200);

    wire [13:0] reg_address;
    wire [6:0]  reg_bytecnt;
    wire [7:0]  write_data;
    reg  [7:0]  read_data;
    wire        reg_read;
    wire        reg_write;
    wire        reg_addrvalid;
    wire        ksd_usb_selected;
    wire [7:0]  ksd_usb_read_data;
    lms_ksd_usb_mailbox u_ksd_mailbox (
        .usb_clk(usb_clk), .iut_clk(iut_clk), .rst(rst),
        .usb_reg_address(reg_address), .usb_reg_bytecnt(reg_bytecnt),
        .usb_write_data(write_data),
        .usb_reg_write(reg_addrvalid && reg_write && !reg_write_d),
        .usb_reg_read(reg_addrvalid && reg_read),
        .usb_selected(ksd_usb_selected), .usb_read_data(ksd_usb_read_data),
        .ksd_recover_valid(ksd_recover_valid), .ksd_recover_record(ksd_recover_record),
        .ksd_recover_accept(ksd_recover_accept),
        .ksd_ack_valid(ksd_ack_valid), .ksd_ack_record(ksd_ack_record),
        .ksd_ack_accept(ksd_ack_accept),
        .ksd_persist_valid(ksd_persist_valid), .ksd_persist_record(ksd_persist_record),
        .ksd_trusted_fault(ksd_trusted_fault)
    );

    cw305_usb_reg_fe #(
        .pADDR_WIDTH(21),
        .pBYTECNT_SIZE(7)
    ) reg_fe (
        .rst(rst),
        .usb_clk(usb_clk),
        .usb_din(usb_din),
        .usb_dout(usb_dout),
        .usb_rdn(usb_rdn),
        .usb_wrn(usb_wrn),
        .usb_cen(usb_cen),
        .usb_alen(usb_alen),
        .usb_addr(usb_addr),
        .usb_isout(usb_isout),
        .reg_address(reg_address),
        .reg_bytecnt(reg_bytecnt),
        .reg_datao(write_data),
        .reg_datai(read_data),
        .reg_read(reg_read),
        .reg_write(reg_write),
        .reg_addrvalid(reg_addrvalid)
    );

    wire [7:0]  txf_wdata;
    wire        txf_wren;
    wire        txf_full;
    reg         txf_rden;
    wire [7:0]  txf_rdata;
    wire        txf_empty;
    wire [8:0]  txf_count_rd;

    wire [7:0]  rxf_wdata;
    reg         rxf_wren;
    wire        rxf_full;
    reg         rxf_rden;
    wire [7:0]  rxf_rdata;
    wire        rxf_empty;
    wire [8:0]  rxf_count_wr;

    lms_cw305_afifo #(.DEPTH(256), .ADDRW(8), .DW(8)) txfifo (
        .rst(rst),
        .wclk(iut_clk), .wren(txf_wren), .wdata(txf_wdata), .full(txf_full),
        .rclk(usb_clk), .rden(txf_rden), .rdata(txf_rdata), .empty(txf_empty),
        .count_rd(txf_count_rd), .count_wr()
    );

    lms_cw305_afifo #(.DEPTH(256), .ADDRW(8), .DW(8)) rxfifo (
        .rst(rst),
        .wclk(usb_clk), .wren(rxf_wren), .wdata(rxf_wdata), .full(rxf_full),
        .rclk(iut_clk), .rden(rxf_rden), .rdata(rxf_rdata), .empty(rxf_empty),
        .count_rd(), .count_wr(rxf_count_wr)
    );

    wire [7:0] srx_byte;
    wire       srx_rdy;
    reg        ack_pulse;
    assign txf_wdata = srx_byte;
    assign txf_wren  = ack_pulse && srx_rdy;

    uart_rx #(
        .BITCLKS(UART_BITCLKS_USE)
    ) srx_unit (
        .clk(iut_clk),
        .rst(rst),
        .ack(ack_pulse),
        .data(srx_byte),
        .rdy(srx_rdy),
        .rts(),
        .rxd(soc_uart_txd)
    );

    always @(posedge iut_clk) begin
        if (rst) begin
            ack_pulse <= 1'b0;
        end else begin
            ack_pulse <= srx_rdy && !txf_full;
        end
    end

    wire       stx_txok;
    reg        stx_send;
    reg        stx_cond_d;
    reg [7:0]  stx_byte_r;
    wire       stx_cond = stx_txok && !rxf_empty;

    uart_tx #(
        .BITCLKS(UART_BITCLKS_USE)
    ) stx_unit (
        .clk(iut_clk),
        .rst(rst),
        .send(stx_send),
        .data(stx_byte_r),
        .rdy(stx_txok),
        .cts(1'b1),
        .txd(soc_uart_rxd)
    );

    always @(posedge iut_clk) begin
        if (rst) begin
            stx_cond_d <= 1'b0;
            stx_send   <= 1'b0;
            rxf_rden   <= 1'b0;
            stx_byte_r <= 8'h00;
        end else begin
            stx_cond_d <= stx_cond;
            rxf_rden   <= 1'b0;

            stx_send   <= stx_cond && !stx_cond_d;
            if (stx_cond && !stx_cond_d) begin
                stx_byte_r <= rxf_rdata;
                rxf_rden   <= 1'b1;
            end
        end
    end

    (* ASYNC_REG = "TRUE" *) reg trap_sync1, trap_sync2;
    always @(posedge usb_clk) begin
        if (rst) begin
            trap_sync1 <= 1'b0;
            trap_sync2 <= 1'b0;
        end else begin
            trap_sync1 <= trap_in;
            trap_sync2 <= trap_sync1;
        end
    end

    wire [31:0] buildtime;
`ifdef SYNTHESIS
    USR_ACCESSE2 buildtime_0 (
        .CFGCLK(),
        .DATA(buildtime),
        .DATAVALID()
    );
`else
    assign buildtime = 32'h0;
`endif

    reg [7:0] rdata_mux;
    always @(*) begin
        case (reg_address)
            `REG_CLKSETTINGS: rdata_mux = 8'h00;
            `REG_USER_LED:    rdata_mux = {7'b0, o_user_led};
            `REG_CRYPT_TYPE:  rdata_mux = pCRYPT_TYPE;
            `REG_CRYPT_REV:   rdata_mux = pCRYPT_REV;
            `REG_IDENTIFY:    rdata_mux = pIDENTIFY;
            `REG_TX_BYTE:     rdata_mux = txf_pop_byte;
            `REG_TX_IDX:      rdata_mux = txf_count_rd[8] ? 8'hFF : txf_count_rd[7:0];
            `REG_RX_BYTE:     rdata_mux = 8'h00;
            `REG_RX_IDX:      rdata_mux = rxf_count_wr[8] ? 8'hFF : rxf_count_wr[7:0];
            `REG_RX_POS:      rdata_mux = rxf_count_wr[8] ? 8'hFF : rxf_count_wr[7:0];
            `REG_STATUS:      rdata_mux = {7'h00, trap_sync2};
            `REG_BUILDTIME:   rdata_mux = buildtime[reg_bytecnt*8 +: 8];
            default:          rdata_mux = 8'h00;
        endcase
        if (ksd_usb_selected) rdata_mux = ksd_usb_read_data;
    end

    reg reg_read_d;
    reg [7:0] txf_pop_byte;
    always @(posedge usb_clk) begin
        if (rst) begin
            reg_read_d   <= 1'b0;
            txf_rden     <= 1'b0;
            txf_pop_byte <= 8'h00;
        end else begin
            reg_read_d <= reg_read;
            txf_rden   <= 1'b0;
            if (reg_addrvalid && reg_read && !reg_read_d &&
                reg_address == `REG_TX_BYTE && !txf_empty) begin
                txf_rden     <= 1'b1;
                txf_pop_byte <= txf_rdata;
            end
        end
    end

    reg reg_write_d;
    always @(posedge usb_clk) begin
        if (rst) begin
            reg_write_d <= 1'b0;
            rxf_wren    <= 1'b0;
            o_user_led  <= 1'b0;
        end else begin
            reg_write_d <= reg_write;
            rxf_wren    <= 1'b0;
            if (reg_addrvalid && reg_write && !reg_write_d) begin
                case (reg_address)
                    `REG_USER_LED: o_user_led <= write_data[0];
                    `REG_RX_BYTE:  if (!rxf_full) rxf_wren <= 1'b1;
                    default: ;
                endcase
            end
        end
    end
    assign rxf_wdata = write_data;

    always @(posedge usb_clk) begin
        if (rst) begin
            read_data <= 8'h00;
        end else if (reg_addrvalid && reg_read && !reg_read_d &&
                     reg_address == `REG_TX_BYTE && !txf_empty) begin
            read_data <= txf_rdata;
        end else begin
            read_data <= rdata_mux;
        end
    end

endmodule

`default_nettype wire
