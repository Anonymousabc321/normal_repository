`default_nettype none
/* Trusted management USB transport, not a storage device or authentication root.
 * CPU has no connection to these registers. The trusted host must durably commit
 * the complete outgoing record BEFORE submitting its identical ACK. Byte order
 * is little endian within the existing 28-word KSD record.
 *
 * USB registers (7-bit byte offset):
 * 10: read 24 bytes starting at byte 0: magic KSD2, flags, outgoing generation,
 *     completion counter, last result, last command (all u32 little endian).
 * flags: out_valid, inbox_busy, all_bytes_written, completion_valid, accepted,
 *        recovered_since_reset, ignored_busy_write, transport_fault (bits 0..7).
 * result: 0 none, 1 accepted, 2 incomplete, 3 invalid command, 4 KSD rejected.
 * 11: immutable outgoing 112-byte snapshot. Read STATUS/record/STATUS and accept
 *     only matching generation with out_valid and no transport_fault both times.
 * 12: write-only incoming staging, all 112 bytes required for every submission.
 * 13: write byte 0: 1 RECOVER, 2 ACK. Busy writes cannot change pending data.
 * A common reset cancels transport state; host must perform fresh recovery,
 * serialized with reads/submissions, before handling a new outgoing request.
 *
 * CDC: toggle synchronizers plus held bundled data. Each record has an extra
 * destination settle cycle before capture. Sources remain stable until the
 * reverse acknowledgement has crossed back. ASYNC_REG is only for controls;
 * constrain held-data source->capture registers with max_delay -datapath_only
 * (at most one destination clock period), excluded from blanket false paths.
 */
module lms_ksd_usb_mailbox (
    input wire usb_clk, iut_clk, rst,
    input wire [13:0] usb_reg_address,
    input wire [6:0] usb_reg_bytecnt,
    input wire [7:0] usb_write_data,
    input wire usb_reg_write, usb_reg_read,
    output wire usb_selected,
    output reg [7:0] usb_read_data,
    output wire ksd_recover_valid,
    output wire [895:0] ksd_recover_record,
    input wire ksd_recover_accept,
    output wire ksd_ack_valid,
    output wire [895:0] ksd_ack_record,
    input wire ksd_ack_accept,
    input wire ksd_persist_valid,
    input wire [895:0] ksd_persist_record,
    output wire ksd_trusted_fault
);
    (* ASYNC_REG = "TRUE" *) reg [1:0] reset_usb_r, reset_iut_r;
    always @(posedge usb_clk or posedge rst)
        if(rst) reset_usb_r <= 2'b11; else reset_usb_r <= {reset_usb_r[0],1'b0};
    always @(posedge iut_clk or posedge rst)
        if(rst) reset_iut_r <= 2'b11; else reset_iut_r <= {reset_iut_r[0],1'b0};
    wire usb_reset = reset_usb_r[1];
    wire iut_reset = reset_iut_r[1];

    reg [895:0] in_record_usb_r;
    reg [7:0] in_cmd_usb_r;
    reg [111:0] written_usb_r;
    reg in_req_usb_r, in_busy_usb_r;
    reg busy_error_usb_r, fault_usb_r;
    reg [31:0] completion_count_usb_r, last_result_usb_r, last_cmd_usb_r;
    reg completion_valid_usb_r;
    reg [191:0] status_snapshot_usb_r;

    reg [895:0] in_record_iut_r;
    reg [7:0] in_cmd_iut_r;
    (* ASYNC_REG = "TRUE" *) reg [1:0] in_req_sync_iut_r;
    (* ASYNC_REG = "TRUE" *) reg [1:0] fault_sync_iut_r;
    reg in_seen_iut_r;
    reg [1:0] in_state_iut_r;
    localparam [1:0] IN_IDLE=0, IN_SETTLE=1, IN_ISSUE=2, IN_WAIT=3;
    reg completion_toggle_iut_r;
    reg [31:0] completion_result_iut_r;
    reg recovered_iut_r;
    (* ASYNC_REG = "TRUE" *) reg [1:0] completion_sync_usb_r;
    (* ASYNC_REG = "TRUE" *) reg [1:0] recovered_sync_usb_r;
    reg completion_seen_usb_r;

    reg [895:0] out_record_iut_r;
    reg out_valid_iut_r, out_req_iut_r;
    (* ASYNC_REG = "TRUE" *) reg [1:0] out_ack_sync_iut_r;
    reg [895:0] out_record_usb_r;
    reg out_valid_usb_r, out_ack_usb_r, out_settle_usb_r;
    reg [31:0] out_generation_usb_r;
    (* ASYNC_REG = "TRUE" *) reg [1:0] out_req_sync_usb_r;

    assign usb_selected = usb_reg_address >= 14'h10 && usb_reg_address <= 14'h13;
    assign ksd_recover_record = in_record_iut_r;
    assign ksd_ack_record = in_record_iut_r;
    assign ksd_recover_valid = !rst && !iut_reset && !fault_sync_iut_r[1] &&
        in_state_iut_r == IN_ISSUE && in_cmd_iut_r == 8'd1;
    assign ksd_ack_valid = !rst && !iut_reset && !fault_sync_iut_r[1] &&
        in_state_iut_r == IN_ISSUE && in_cmd_iut_r == 8'd2;
    assign ksd_trusted_fault = !rst && !iut_reset && fault_sync_iut_r[1];
    wire [31:0] flags_usb_w = {24'b0, fault_usb_r, busy_error_usb_r,
        recovered_sync_usb_r[1], last_result_usb_r == 1, completion_valid_usb_r,
        &written_usb_r, in_busy_usb_r, out_valid_usb_r};
    wire [191:0] status_usb_w = {last_cmd_usb_r, last_result_usb_r,
        completion_count_usb_r, out_generation_usb_r, flags_usb_w, 32'h4b534432};
    always @* begin
        usb_read_data = 8'b0;
        if(!rst && !usb_reset) begin
            if(usb_reg_address == 14'h10 && usb_reg_bytecnt < 24)
                usb_read_data = status_snapshot_usb_r[usb_reg_bytecnt*8 +: 8];
            else if(usb_reg_address == 14'h11 && usb_reg_bytecnt < 112)
                usb_read_data = out_record_usb_r[usb_reg_bytecnt*8 +: 8];
            /* Byte 0 triggers the snapshot. Return its invariant magic byte
             * immediately, preserving the frontend's original read latency. */
            if(usb_reg_address == 14'h10 && usb_reg_bytecnt == 0)
                usb_read_data = 8'h32;
        end
    end

    always @(posedge usb_clk or posedge usb_reset) begin
        if(usb_reset) begin
            in_record_usb_r <= 0; in_cmd_usb_r <= 0; written_usb_r <= 0;
            in_req_usb_r <= 0; in_busy_usb_r <= 0;
            busy_error_usb_r <= 0; fault_usb_r <= 0;
            completion_count_usb_r <= 0; last_result_usb_r <= 0; last_cmd_usb_r <= 0;
            completion_valid_usb_r <= 0; status_snapshot_usb_r <= 0;
            completion_sync_usb_r <= 0; recovered_sync_usb_r <= 0;
            completion_seen_usb_r <= 0;
            out_req_sync_usb_r <= 0; out_record_usb_r <= 0;
            out_valid_usb_r <= 0; out_ack_usb_r <= 0; out_settle_usb_r <= 0;
            out_generation_usb_r <= 0;
        end else begin
            completion_sync_usb_r <= {completion_sync_usb_r[0],completion_toggle_iut_r};
            recovered_sync_usb_r <= {recovered_sync_usb_r[0],recovered_iut_r};
            out_req_sync_usb_r <= {out_req_sync_usb_r[0],out_req_iut_r};
            if(usb_reg_read && usb_reg_address == 14'h10 && usb_reg_bytecnt == 0)
                status_snapshot_usb_r <= status_usb_w;
            if(completion_sync_usb_r[1] != completion_seen_usb_r) begin
                completion_seen_usb_r <= completion_sync_usb_r[1];
                in_busy_usb_r <= 0;
                last_result_usb_r <= completion_result_iut_r;
                completion_valid_usb_r <= 1;
                if(completion_count_usb_r == 32'hffffffff) fault_usb_r <= 1;
                else completion_count_usb_r <= completion_count_usb_r + 1'b1;
            end
            if(out_settle_usb_r) begin
                out_settle_usb_r <= 0;
                out_ack_usb_r <= out_req_sync_usb_r[1];
                if(out_generation_usb_r == 32'hffffffff) begin
                    fault_usb_r <= 1; out_valid_usb_r <= 0;
                end else begin
                    out_record_usb_r <= out_record_iut_r;
                    out_valid_usb_r <= out_valid_iut_r;
                    out_generation_usb_r <= out_generation_usb_r + 1'b1;
                end
            end else if(out_req_sync_usb_r[1] != out_ack_usb_r)
                out_settle_usb_r <= 1;

            if(usb_reg_write && (usb_reg_address == 14'h12 || usb_reg_address == 14'h13)) begin
                if(in_busy_usb_r) busy_error_usb_r <= 1;
                else if(!fault_usb_r) begin
                    if(usb_reg_address == 14'h12 && usb_reg_bytecnt < 112) begin
                        in_record_usb_r[usb_reg_bytecnt*8 +: 8] <= usb_write_data;
                        written_usb_r[usb_reg_bytecnt] <= 1;
                    end else if(usb_reg_address == 14'h13 && usb_reg_bytecnt == 0) begin
                        written_usb_r <= 0;
                        last_cmd_usb_r <= {24'b0,usb_write_data};
                        if((usb_write_data == 1 || usb_write_data == 2) && &written_usb_r) begin
                            in_cmd_usb_r <= usb_write_data;
                            in_req_usb_r <= !in_req_usb_r;
                            in_busy_usb_r <= 1;
                        end else begin
                            last_result_usb_r <= (usb_write_data == 1 || usb_write_data == 2) ? 2 : 3;
                            completion_valid_usb_r <= 1;
                            if(completion_count_usb_r == 32'hffffffff) fault_usb_r <= 1;
                            else completion_count_usb_r <= completion_count_usb_r + 1'b1;
                        end
                    end
                end
            end
        end
    end

    always @(posedge iut_clk or posedge iut_reset) begin
        if(iut_reset) begin
            in_req_sync_iut_r <= 0; fault_sync_iut_r <= 0; in_seen_iut_r <= 0;
            in_record_iut_r <= 0; in_cmd_iut_r <= 0; in_state_iut_r <= IN_IDLE;
            completion_toggle_iut_r <= 0; completion_result_iut_r <= 0; recovered_iut_r <= 0;
            out_record_iut_r <= 0; out_valid_iut_r <= 0; out_req_iut_r <= 0;
            out_ack_sync_iut_r <= 0;
        end else begin
            in_req_sync_iut_r <= {in_req_sync_iut_r[0],in_req_usb_r};
            fault_sync_iut_r <= {fault_sync_iut_r[0],fault_usb_r};
            out_ack_sync_iut_r <= {out_ack_sync_iut_r[0],out_ack_usb_r};
            case(in_state_iut_r)
                IN_IDLE: if(in_req_sync_iut_r[1] != in_seen_iut_r) begin
                    in_seen_iut_r <= in_req_sync_iut_r[1];
                    in_state_iut_r <= IN_SETTLE;
                end
                IN_SETTLE: begin
                    in_record_iut_r <= in_record_usb_r;
                    in_cmd_iut_r <= in_cmd_usb_r;
                    in_state_iut_r <= IN_ISSUE;
                end
                IN_ISSUE: in_state_iut_r <= IN_WAIT;
                IN_WAIT: begin
                    completion_result_iut_r <=
                        ((in_cmd_iut_r == 1 && ksd_recover_accept) ||
                         (in_cmd_iut_r == 2 && ksd_ack_accept)) ? 1 : 4;
                    if(in_cmd_iut_r == 1 && ksd_recover_accept) recovered_iut_r <= 1;
                    completion_toggle_iut_r <= !completion_toggle_iut_r;
                    in_state_iut_r <= IN_IDLE;
                end
                default: in_state_iut_r <= IN_IDLE;
            endcase
            if(out_req_iut_r == out_ack_sync_iut_r[1] &&
               (ksd_persist_valid != out_valid_iut_r ||
                (ksd_persist_valid && ksd_persist_record != out_record_iut_r))) begin
                out_record_iut_r <= ksd_persist_record;
                out_valid_iut_r <= ksd_persist_valid;
                out_req_iut_r <= !out_req_iut_r;
            end
        end
    end
endmodule
`default_nettype wire
