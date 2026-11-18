`default_nettype none

module lms_cw310_top #(
    parameter FIRMWARE_HEX    = "",
    parameter INSECURE_TEST_MODE = 0,
    parameter TRNG_SIM_MODE   = 0,
    parameter SCA_TEST        = 0,
    parameter RANDOM_DELAY    = 0,
    parameter DERIVE_SHUFFLE  = 0,
    parameter ENABLE_SHA256   = 0,
    parameter ENABLE_SHAKE256 = 1,
    parameter HAS_SECURITY    = 1,
    parameter ALLOW_XQ_DERIVE = 0,
    parameter SINGLE_CORE     = 0,
    parameter MASKED          = 0
) (

    input  wire        SYSCLK_P,          /* AC9 */
    input  wire        SYSCLK_N,          /* AD9 */
    output wire        LVDS_XO_200M_ENA,

    input  wire        USB_CLK0,
    inout  wire [7:0]  USB_D,             /* U25/U26/AC21/V24/V26/W26/W25/Y26 */
    input  wire [19:0] USB_A,             /* AC26..W20 */
    input  wire        USB_nRD,           /* AC23 */
    input  wire        USB_nWR,           /* AA25 */
    input  wire        USB_nCE,           /* AA23 */
    input  wire        USB_nALE,

    input  wire        USRSW2,
    output wire [7:0]  USRLED,            /* M26/M25/M24/M19/L25/K26/L24/K25 */

    /* ---- ChipWhisperer 20-pin(SCA)---- */
    output wire        CWIO_HS1,
    output wire        CWIO_IO4,

    output wire        SAM_RXD0
);

    assign LVDS_XO_200M_ENA = 1'b1;

    wire clk200_ibuf, clk200;
    IBUFDS u_ibufds_200 (.I(SYSCLK_P), .IB(SYSCLK_N), .O(clk200_ibuf));
    BUFG   u_bufg_200   (.I(clk200_ibuf), .O(clk200));

    wire clk50_mmcm, clk50, clkfb_out, clkfb_in, clk50_locked;
    MMCME2_BASE #(
        .BANDWIDTH("OPTIMIZED"),
        .CLKFBOUT_MULT_F(5.000),
        .CLKIN1_PERIOD(5.000),
        .CLKOUT0_DIVIDE_F(40.000),
        .DIVCLK_DIVIDE(1),
        .STARTUP_WAIT("FALSE")
    ) u_mmcm (
        .CLKIN1(clk200),
        .CLKFBIN(clkfb_in),
        .CLKFBOUT(clkfb_out),
        .CLKFBOUTB(),
        .CLKOUT0(clk50_mmcm),
        .CLKOUT0B(),
        .CLKOUT1(), .CLKOUT1B(), .CLKOUT2(), .CLKOUT2B(),
        .CLKOUT3(), .CLKOUT3B(), .CLKOUT4(), .CLKOUT5(), .CLKOUT6(),
        .LOCKED(clk50_locked),
        .PWRDWN(1'b0),
        .RST(1'b0)
    );
    BUFG u_bufg_fb (.I(clkfb_out), .O(clkfb_in));
    BUFG u_bufg_50 (.I(clk50_mmcm), .O(clk50));

    wire usb_clk;
    BUFG u_bufg_usb (.I(USB_CLK0), .O(usb_clk));

reg [4:0] rst_low_cnt = 5'd0, rst_high_cnt = 5'd0;
reg       rst_filtered = 1'b1;
always @(posedge clk50) begin
    if (USRSW2 == 1'b0) begin
        rst_high_cnt <= 5'd0;
        if (rst_low_cnt != 5'd16) rst_low_cnt <= rst_low_cnt + 5'd1;
        else                      rst_filtered <= 1'b1;
    end else begin
        rst_low_cnt <= 5'd0;
        if (rst_high_cnt != 5'd16) rst_high_cnt <= rst_high_cnt + 5'd1;
        else                       rst_filtered <= 1'b0;
    end
end
wire rst = rst_filtered;

    wire [63:0] trace_probe;
    wire        trace_trig;

    wire        trace_sel = (USB_A[11:7] >= 5'h1A) && (USB_A[11:7] <= 5'h1E);
    wire        trace_rd  = trace_sel && !USB_nRD && !USB_nCE;
    wire        trace_wr  = trace_sel && !USB_nWR && !USB_nCE;
    wire [2:0]  tr_word   = USB_A[11:7] - 5'h1A;
    wire [1:0]  tr_lane   = USB_A[1:0];

    reg         tr_arm_tog;
    reg  [3:0]  tr_decim;
    reg  [7:0]  tr_idx_lo;
    reg  [3:0]  tr_idx_hi;
    wire [11:0] tr_index = {tr_idx_hi, tr_idx_lo};

    always @(posedge usb_clk) begin
        if (trace_wr && tr_word == 3'd0 && tr_lane == 2'd0 && USB_D[0]) begin
            tr_arm_tog <= ~tr_arm_tog;
        end
        if (trace_wr && tr_word == 3'd0 && tr_lane == 2'd2) begin
            tr_decim <= USB_D[3:0];
        end
        if (trace_wr && tr_word == 3'd1) begin
            if (tr_lane == 2'd0)      tr_idx_lo <= USB_D;
            else if (tr_lane == 2'd1) tr_idx_hi <= USB_D[3:0];
        end
    end

    reg [2:0] tr_arm_sync;
    always @(posedge clk50) begin
        tr_arm_sync <= {tr_arm_sync[1:0], tr_arm_tog};
    end
    wire tr_arm_pulse = tr_arm_sync[2] ^ tr_arm_sync[1];

    wire        tr_busy, tr_done, tr_trig_seen;
    wire [63:0] tr_sample;

    lms_trace #(.DEPTH_LOG2(12)) u_trace (
        .clk(clk50),
        .rst(rst),
        .probe(trace_probe),
        .trig(trace_trig),
        .arm(tr_arm_pulse),
        .decim(tr_decim),
        .cap_busy(tr_busy),
        .cap_done(tr_done),
        .cap_trig_seen(tr_trig_seen),
        .rclk(usb_clk),
        .raddr(tr_index),
        .rdata(tr_sample)
    );

    reg [2:0] tr_stat_s1, tr_stat_s2;
    always @(posedge usb_clk) begin
        tr_stat_s1 <= {tr_done, tr_busy, tr_trig_seen};
        tr_stat_s2 <= tr_stat_s1;
    end

    reg [31:0] tr_rdata_w;
    always @(*) begin
        case (tr_word)
            3'd0: tr_rdata_w = {29'b0, tr_stat_s2[2], tr_stat_s2[1], tr_stat_s2[0]};
            3'd1: tr_rdata_w = {20'b0, tr_index};
            3'd2: tr_rdata_w = tr_sample[31:0];
            3'd3: tr_rdata_w = tr_sample[63:32];
            3'd4: tr_rdata_w = 32'd4096;
            default: tr_rdata_w = 32'hdead_beef;
        endcase
    end

    wire [7:0] tr_rdata_byte = (tr_lane == 2'd0) ? tr_rdata_w[7:0] :
                               (tr_lane == 2'd1) ? tr_rdata_w[15:8] :
                               (tr_lane == 2'd2) ? tr_rdata_w[23:16] :
                                                   tr_rdata_w[31:24];

    assign USB_D = trace_rd ? tr_rdata_byte :
                   (usb_isout ? usb_dout : 8'hZZ);

    wire [7:0] gpio_out;
    wire       trap;
    wire       uart_txd_soc, uart_rxd_soc, uart_cts_soc;

    wire ksd_recover_valid, ksd_recover_accept, ksd_ack_valid, ksd_ack_accept;
    wire ksd_persist_valid, ksd_trusted_fault;
    wire [895:0] ksd_recover_record, ksd_ack_record, ksd_persist_record;

    lms_soc #(
        .FIRMWARE_HEX(FIRMWARE_HEX),
        .INSECURE_TEST_MODE(INSECURE_TEST_MODE),
        .TRNG_SIM_MODE(TRNG_SIM_MODE),
        .SCA_TEST(SCA_TEST),
        .RANDOM_DELAY(RANDOM_DELAY),
        .DERIVE_SHUFFLE(DERIVE_SHUFFLE),
        .ENABLE_SHA256(ENABLE_SHA256),
        .ENABLE_SHAKE256(ENABLE_SHAKE256),
        .HAS_SECURITY(HAS_SECURITY),
        .ALLOW_XQ_DERIVE(ALLOW_XQ_DERIVE),
        .SINGLE_CORE(SINGLE_CORE),
        .MASKED(MASKED)
    ) soc (
        /* Dedicated USB mailbox: CPU/UART commands cannot drive this boundary. */
        .ksd_recover_valid(ksd_recover_valid), .ksd_recover_record(ksd_recover_record),
        .ksd_recover_accept(ksd_recover_accept),
        .ksd_ack_valid(ksd_ack_valid), .ksd_ack_record(ksd_ack_record), .ksd_ack_accept(ksd_ack_accept),
        .ksd_persist_valid(ksd_persist_valid), .ksd_persist_record(ksd_persist_record),
        .ksd_trusted_fault(ksd_trusted_fault),
        .clk(clk50),
        .rst(rst),
        .uart_rxd(uart_rxd_soc),
        .uart_txd(uart_txd_soc),
        .uart_cts_i(uart_cts_soc),
        .gpio_in(8'b0),
        .gpio_out(gpio_out),
        .trap(trap),

    .sca_trigger(sca_trigger_soc),

        .dbg_ext_i({uart_cts_soc, uart_txd_soc, 6'b000000}),
        .trace_probe(trace_probe),
        .trace_trig(trace_trig),
        .spi_sck(),
        .spi_sck_en(),
        .spi_cs_n(),
        .spi_mosi(),
        .spi_miso(5'b0)
    );

    wire [7:0] usb_dout;
    wire       usb_isout;
    wire       user_led;

    lms_cw305_usb_uart bridge (
        .usb_clk(usb_clk),
        .rst(rst),
        .usb_din(USB_D),
        .usb_dout(usb_dout),
        .usb_isout(usb_isout),
        .usb_addr({1'b0, USB_A}),
        .usb_rdn(USB_nRD),
        .usb_wrn(USB_nWR),
        .usb_alen(USB_nALE),
        .usb_cen(USB_nCE),
        .iut_clk(clk50),
        .soc_uart_txd(uart_txd_soc),
        .soc_uart_rxd(uart_rxd_soc),
        .soc_uart_cts(uart_cts_soc),
        .trap_in(trap),
        .o_user_led(user_led),
        .ksd_recover_valid(ksd_recover_valid), .ksd_recover_record(ksd_recover_record),
        .ksd_recover_accept(ksd_recover_accept),
        .ksd_ack_valid(ksd_ack_valid), .ksd_ack_record(ksd_ack_record), .ksd_ack_accept(ksd_ack_accept),
        .ksd_persist_valid(ksd_persist_valid), .ksd_persist_record(ksd_persist_record),
        .ksd_trusted_fault(ksd_trusted_fault)
    );

    assign SAM_RXD0 = uart_txd_soc;

    reg [23:0] heartbeat = 24'd0;
    always @(posedge clk50)
        heartbeat <= heartbeat + 24'd1;

    assign USRLED[0] = gpio_out[0];
    assign USRLED[1] = trap;
    assign USRLED[2] = user_led;
    assign USRLED[3] = gpio_out[1];
    assign USRLED[4] = gpio_out[2];
    assign USRLED[5] = heartbeat[23];
    assign USRLED[6] = heartbeat[22];
    assign USRLED[7] = heartbeat[21];

    wire sca_trigger_soc;

    assign CWIO_IO4 = sca_trigger_soc;

    wire tio_clkout_en = (SCA_TEST == 1);
    ODDR #(
        .DDR_CLK_EDGE("SAME_EDGE"),
        .INIT(1'b0),
        .SRTYPE("SYNC")
    ) clkout_oddr (
        .Q(CWIO_HS1),
        .C(clk50),
        .CE(tio_clkout_en),
        .D1(1'b1),
        .D2(1'b0),
        .R(1'b0),
        .S(1'b0)
    );

endmodule

`default_nettype wire
