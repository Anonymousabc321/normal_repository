/* Trusted persistence boundary for the accelerator. Only the sideband can
 * recover/acknowledge durable records. MMIO can request BEGIN/ABORT and inspect
 * status, never fabricate a receipt. Provisioning must load the actual key
 * before trusted recovery associates it with key_id/I/profile. */
`default_nettype none
module lms_ksd_sign_adapter #(
    parameter [7:0] HASH_ID = 8'd1,
    parameter INSECURE_TEST_MODE = 0
) (
    input wire clk, rst,
    input wire ksd_recover_valid,
    input wire [895:0] ksd_recover_record,
    output wire ksd_recover_accept,
    input wire ksd_ack_valid,
    input wire [895:0] ksd_ack_record,
    output wire ksd_ack_accept,
    output wire ksd_persist_valid,
    output wire [895:0] ksd_persist_record,
    input wire ksd_trusted_fault,
    input wire bus_valid, bus_write,
    input wire [9:0] bus_addr,
    input wire [31:0] bus_wdata,
    output wire ksd_mmio_hit,
    output reg [31:0] ksd_mmio_rdata,
    input wire seed_valid, engine_quiescent,
    input wire [31:0] command, arg_q,
    input wire [3:0] arg_w,
    input wire [127:0] identifier,
    input wire [255:0] mqc_context,
    input wire sign_request, sign_complete,
    output wire command_allowed,
    output wire sign_wait, sign_dispatch,
    output reg sign_rejected,
    output reg sign_cancelled,
    output wire registered,
    output wire [3:0] txn_state
);
    localparam [31:0] CMD_SIGN=7, CMD_KEYGEN=6, CMD_KEYGEN_LEAF=14;
    wire [63:0] recovery_params = ksd_recover_record[703:640];
    // Recovery burns RESERVED without resuming its message. An IDLE record may
    // retain the last completed context; neither context can grant a SIGN.
    wire [255:0] unused_recovery_context = ksd_recover_record[639:384];
    wire [7:0] recovery_h = recovery_params[15:8];
    wire recovery_fields_valid =
        (ksd_recover_record[1:0] == 1 || ksd_recover_record[1:0] == 2) &&
        ksd_recover_record[31:2] == 0 && ksd_recover_record[895:864] == 0 &&
        recovery_params[63:24] == 0 && recovery_params[7:4] == 0 &&
        recovery_params[23:16] == HASH_ID && recovery_h <= 31 &&
        (recovery_params[3:0] == 1 || recovery_params[3:0] == 2 ||
         recovery_params[3:0] == 4 || recovery_params[3:0] == 8) &&
        ksd_recover_record[863:832] == (32'd1 << recovery_h) && seed_valid;
    reg registry_ready_r;
    reg [127:0] registered_identifier_r;
    reg [63:0] registered_params_r;
    reg [31:0] registered_limit_r;
    reg [223:0] recover_metadata_r;
    wire txn_recover_accept;
    wire recover_valid_w = !INSECURE_TEST_MODE && ksd_recover_valid && recovery_fields_valid;
    wire trusted_fault_w = !INSECURE_TEST_MODE &&
        (ksd_trusted_fault || (ksd_recover_valid && !recovery_fields_valid));
    wire ack_fields_valid = ksd_ack_record[31:2] == 0 &&
        ksd_ack_record[895:864] == 0 && registry_ready_r &&
        ksd_ack_record[831:704] == registered_identifier_r &&
        ksd_ack_record[863:832] == registered_limit_r;
    wire begin_doorbell = bus_valid && bus_write && bus_addr == 10'h240 && bus_wdata[31:2] == 0 && bus_wdata[0];
    wire abort_doorbell = bus_valid && bus_write && bus_addr == 10'h240 && bus_wdata[31:2] == 0 && bus_wdata[1];
    wire profile_matches = registered && identifier == registered_identifier_r &&
        arg_w == registered_params_r[3:0];
    wire secret_command = command == CMD_SIGN || command == CMD_KEYGEN || command == CMD_KEYGEN_LEAF;
    wire key_mutation = command == 3 || command == 28 || command == 18 || command == 19 ||
        command == 20 || command == 21 || command == 16 || command == 17;
    assign command_allowed = INSECURE_TEST_MODE ||
        ((!secret_command || (profile_matches && arg_q < registered_limit_r)) &&
         !((registry_ready_r || txn_state != 0) && key_mutation));
    assign registered = registry_ready_r && txn_state != 0 && txn_state != 8 && !trusted_fault_w;
    assign ksd_mmio_hit = bus_addr >= 10'h240 && bus_addr <= 10'h258;
    wire [31:0] txn_q, txn_next_q, txn_last_tx;
    always @* begin
        case(bus_addr)
            10'h244: ksd_mmio_rdata = {28'b0, txn_state};
            10'h248: ksd_mmio_rdata = txn_q;
            10'h24c: ksd_mmio_rdata = txn_next_q;
            10'h250: ksd_mmio_rdata = txn_last_tx;
            10'h254: ksd_mmio_rdata = registered_params_r[31:0];
            10'h258: ksd_mmio_rdata = INSECURE_TEST_MODE ? 32'b0 : 32'h4b534431;
            default: ksd_mmio_rdata = 32'b0;
        endcase
    end
    wire txn_start_accept, txn_rejected, txn_cancel;
    wire [3:0] unused_txn_error;
    wire unused_txn_begin_accept;
    reg start_pending_r;
    reg sign_inflight_r;
    reg completion_pending_r;
    wire valid_sign_request = sign_request && command == CMD_SIGN && command_allowed && registered;
    assign sign_wait = !INSECURE_TEST_MODE && start_pending_r;
    assign sign_dispatch = !INSECURE_TEST_MODE && txn_start_accept && start_pending_r &&
        !txn_cancel && !trusted_fault_w && !abort_doorbell && registered;
    always @(posedge clk) begin
        if(rst) begin
            registry_ready_r <= 1'b0;
            registered_identifier_r <= 0;
            registered_params_r <= 0;
            registered_limit_r <= 0;
            recover_metadata_r <= 0;
            start_pending_r <= 1'b0;
            sign_inflight_r <= 1'b0;
            completion_pending_r <= 1'b0;
            sign_rejected <= 1'b0;
            sign_cancelled <= 1'b0;
        end else begin
            sign_rejected <= 1'b0;
            if(recover_valid_w && txn_state == 0) recover_metadata_r <= ksd_recover_record[863:640];
            if(txn_recover_accept) begin
                registry_ready_r <= 1'b1;
                registered_identifier_r <= recover_metadata_r[191:64];
                registered_params_r <= recover_metadata_r[63:0];
                registered_limit_r <= recover_metadata_r[223:192];
            end
            if(sign_request && !INSECURE_TEST_MODE) begin
                if(valid_sign_request) start_pending_r <= 1'b1;
                else sign_rejected <= 1'b1;
            end
            if(sign_dispatch) begin
                start_pending_r <= 1'b0;
                sign_inflight_r <= 1'b1;
                sign_cancelled <= 1'b0;
            end
            if(start_pending_r && (txn_rejected || txn_cancel || abort_doorbell)) begin
                start_pending_r <= 1'b0;
                sign_rejected <= 1'b1;
            end
            if(sign_inflight_r && (txn_cancel || abort_doorbell || trusted_fault_w))
                sign_cancelled <= 1'b1;
            if(sign_complete && sign_inflight_r && engine_quiescent) begin
                sign_inflight_r <= 1'b0;
                completion_pending_r <= 1'b1;
            end
            if(txn_state != 4) completion_pending_r <= 1'b0;
        end
    end
    wire [1:0] persist_op;
    wire [31:0] persist_q, persist_tx, txn_epoch;
    wire [127:0] txn_key_id, txn_session;
    wire [255:0] txn_context;
    wire [63:0] txn_params;
    wire txn_persist_valid;
    assign ksd_persist_valid = txn_persist_valid && registry_ready_r && !INSECURE_TEST_MODE;
    assign ksd_persist_record = {32'b0, registered_limit_r, registered_identifier_r,
        txn_params, txn_context, persist_tx, persist_q, txn_session, txn_epoch, txn_key_id,
        30'b0, persist_op};
    assign ksd_recover_accept = txn_recover_accept;
    lms_ksd_txn #(.LATE_BIND_CONTEXT(1)) u_txn (
        .clk(clk), .rst(rst), .trusted_fault(trusted_fault_w),
        .trusted_recover_valid(recover_valid_w),
        .trusted_recover_reserved(ksd_recover_record[1:0] == 1),
        .trusted_recover_key_id(ksd_recover_record[159:32]),
        .trusted_recover_epoch(ksd_recover_record[191:160]),
        .trusted_recover_session(ksd_recover_record[319:192]),
        .trusted_recover_q(ksd_recover_record[351:320]),
        .trusted_recover_q_limit(ksd_recover_record[863:832]),
        .trusted_recover_tx(ksd_recover_record[383:352]),
        .trusted_recover_params(recovery_params),
        .trusted_ack_valid(!INSECURE_TEST_MODE && ksd_ack_valid),
        .trusted_ack_op(ack_fields_valid ? ksd_ack_record[1:0] : 2'b0),
        .trusted_ack_key_id(ksd_ack_record[159:32]),
        .trusted_ack_epoch(ksd_ack_record[191:160]),
        .trusted_ack_session(ksd_ack_record[319:192]),
        .trusted_ack_q(ksd_ack_record[351:320]),
        .trusted_ack_tx(ksd_ack_record[383:352]),
        .trusted_ack_context(ksd_ack_record[639:384]),
        .trusted_ack_params(ksd_ack_record[703:640]),
        .begin_valid(!INSECURE_TEST_MODE && begin_doorbell && registry_ready_r),
        .begin_context(256'b0), .begin_params(registered_params_r),
        .start_valid(!INSECURE_TEST_MODE && valid_sign_request), .start_q(arg_q),
        .start_context(mqc_context), .start_params(registered_params_r),
        .abort_valid(!INSECURE_TEST_MODE && abort_doorbell),
        .engine_done(completion_pending_r && txn_state == 4),
        .engine_quiescent(engine_quiescent),
        .begin_accept(unused_txn_begin_accept), .start_accept(txn_start_accept),
        .ack_accept(ksd_ack_accept), .recover_accept(txn_recover_accept),
        .rejected(txn_rejected), .error_code(unused_txn_error), .cancel(txn_cancel),
        .persist_valid(txn_persist_valid), .persist_op(persist_op), .persist_q(persist_q),
        .persist_tx(persist_tx), .key_id(txn_key_id), .epoch(txn_epoch),
        .session_id(txn_session), .signing_context(txn_context), .signing_params(txn_params),
        .signing_q(txn_q), .next_q(txn_next_q), .last_tx(txn_last_tx), .state(txn_state)
    );
endmodule
`default_nettype wire
