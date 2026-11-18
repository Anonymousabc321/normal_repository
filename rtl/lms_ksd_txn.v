/*
 * Reservation transaction core. lms_ksd_sign_adapter connects this controller
 * to both SoC hash wrappers and their one-shot SIGN dispatch.
 *
 * trusted_recover_* and trusted_ack_* are SECURITY BOUNDARY inputs. The external
 * persistence authority must authenticate these and establish freshness before
 * asserting valid. They MUST NOT be mapped to firmware-writable registers or
 * synthesized from STATE_COMMIT/HMAC completion. This module does not implement
 * endpoint authentication, durable storage, or a reset-persistent counter.
 *
 * context is an opaque claimed digest, not a message-binding proof produced by
 * this module. A trusted signing adapter must verify/enforce its relation to
 * the actual immutable message and parameters, then use the latched
 * outputs, enforce batch/chain progress, and report completion for ONE complete
 * signature. start_accept is a one-shot dispatch, not a reusable gate-open bit.
 * trusted_recover_params registers the key's fixed algorithm/w/h profile;
 * begin_params must match it exactly. The trusted key registry must establish
 * that profile and its q_limit relation. key_id must identify SEED + I + the
 * parameter-set generation. The SoC adapter also gates public KEYGEN on this
 * fixed registered profile; this transaction core alone cannot gate that path.
 * The adapter must quiesce on cancel, and on reset discard all in-flight work.
 *
 * Persistent record operation 1 = RESERVED(q), 2 = IDLE(next_q). The authenticated
 * receipt binds every request output, including namespace/session/context.
 * A trusted recovery of RESERVED always burns q; it never reissues a grant.
 * Conflicting event strobes are rejected without partial acceptance. The
 * persistence adapter must retry a receipt until ack_accept. The signing
 * adapter must hold/retry engine_done until state becomes FINALIZE_PENDING;
 * a one-cycle done pulse colliding with another event is not acknowledged.
 */
`default_nettype none
module lms_ksd_txn #(
    /* Late binding reserves q before message preparation. RESERVED receipts
     * carry context=0; the trusted signing adapter supplies the immutable MQC
     * digest on the sole accepted START. FINALIZE then binds that digest. */
    parameter LATE_BIND_CONTEXT = 0
) (
    input wire clk,
    input wire rst,
    input wire trusted_fault,

    input wire trusted_recover_valid,
    input wire trusted_recover_reserved,
    input wire [127:0] trusted_recover_key_id,
    input wire [31:0] trusted_recover_epoch,
    input wire [127:0] trusted_recover_session,
    input wire [31:0] trusted_recover_q,
    input wire [31:0] trusted_recover_q_limit,
    input wire [31:0] trusted_recover_tx,
    input wire [63:0] trusted_recover_params,

    input wire trusted_ack_valid,
    input wire [1:0] trusted_ack_op,
    input wire [127:0] trusted_ack_key_id,
    input wire [31:0] trusted_ack_epoch,
    input wire [127:0] trusted_ack_session,
    input wire [31:0] trusted_ack_q,
    input wire [31:0] trusted_ack_tx,
    input wire [255:0] trusted_ack_context,
    input wire [63:0] trusted_ack_params,

    input wire begin_valid,
    input wire [255:0] begin_context,
    input wire [63:0] begin_params,
    input wire start_valid,
    input wire [31:0] start_q,
    input wire [255:0] start_context,
    input wire [63:0] start_params,
    input wire abort_valid,
    input wire engine_done,
    input wire engine_quiescent,

    output reg begin_accept,
    output reg start_accept,
    output reg ack_accept,
    output reg recover_accept,
    output reg rejected,
    output reg [3:0] error_code,
    output wire cancel,
    output wire persist_valid,
    output wire [1:0] persist_op,
    output wire [31:0] persist_q,
    output wire [31:0] persist_tx,
    output wire [127:0] key_id,
    output wire [31:0] epoch,
    output wire [127:0] session_id,
    output wire [255:0] signing_context,
    output wire [63:0] signing_params,
    output wire [31:0] signing_q,
    output wire [31:0] next_q,
    output wire [31:0] last_tx,
    output wire [3:0] state
);
    localparam [3:0] RECOVERY_LOCKED = 4'd0, IDLE = 4'd1,
        RESERVE_PENDING = 4'd2, RESERVED_READY = 4'd3, SIGNING = 4'd4,
        DRAINING = 4'd5, FINALIZE_PENDING = 4'd6, EXHAUSTED = 4'd7,
        ERROR_LOCKED = 4'd8;
    localparam [3:0] ERR_NONE = 4'd0, ERR_PHASE = 4'd1,
        ERR_RECEIPT = 4'd2, ERR_CONTEXT = 4'd3, ERR_RANGE = 4'd4,
        ERR_OVERFLOW = 4'd5, ERR_CONFLICT = 4'd6, ERR_ENGINE = 4'd7,
        ERR_TRUSTED_FAULT = 4'd8;

    reg [3:0] state_r;
    reg [127:0] key_id_r, session_r;
    reg [31:0] epoch_r, next_q_r, q_limit_r, last_tx_r, pending_tx_r, q_r;
    reg [255:0] context_r;
    reg [63:0] params_r, registered_params_r;
    wire pending = state_r == RESERVE_PENDING || state_r == FINALIZE_PENDING;
    wire [2:0] action_count = {2'b0, trusted_recover_valid} +
        {2'b0, trusted_ack_valid} + {2'b0, begin_valid} +
        {2'b0, start_valid} + {2'b0, abort_valid} + {2'b0, engine_done};
    wire receipt_matches = trusted_ack_op == persist_op &&
        trusted_ack_key_id == key_id_r && trusted_ack_epoch == epoch_r &&
        trusted_ack_session == session_r && trusted_ack_q == persist_q &&
        trusted_ack_tx == pending_tx_r && trusted_ack_context == context_r &&
        trusted_ack_params == params_r;

    assign state = state_r;
    assign key_id = key_id_r;
    assign epoch = epoch_r;
    assign session_id = session_r;
    assign signing_context = context_r;
    assign signing_params = params_r;
    assign signing_q = q_r;
    assign next_q = next_q_r;
    assign last_tx = last_tx_r;
    assign persist_valid = pending && !rst && !trusted_fault;
    assign persist_op = state_r == RESERVE_PENDING ? 2'd1 : 2'd2;
    assign persist_q = state_r == RESERVE_PENDING ? q_r : next_q_r;
    assign persist_tx = pending_tx_r;
    assign cancel = rst || trusted_fault || state_r == DRAINING ||
        state_r == ERROR_LOCKED || state_r == RECOVERY_LOCKED;

    always @(posedge clk) begin
        begin_accept <= 1'b0;
        start_accept <= 1'b0;
        ack_accept <= 1'b0;
        recover_accept <= 1'b0;
        rejected <= 1'b0;
        error_code <= ERR_NONE;
        if (rst) begin
            state_r <= RECOVERY_LOCKED;
            key_id_r <= 128'b0;
            epoch_r <= 32'b0;
            session_r <= 128'b0;
            next_q_r <= 32'b0;
            q_limit_r <= 32'b0;
            last_tx_r <= 32'b0;
            pending_tx_r <= 32'b0;
            q_r <= 32'b0;
            context_r <= 256'b0;
            params_r <= 64'b0;
            registered_params_r <= 64'b0;
        end else if (trusted_fault) begin
            state_r <= ERROR_LOCKED;
            rejected <= 1'b1;
            error_code <= ERR_TRUSTED_FAULT;
        end else if (action_count > 3'd1) begin
            /* No partial acceptance when control events conflict. */
            rejected <= 1'b1;
            error_code <= ERR_CONFLICT;
        end else if (trusted_recover_valid) begin
            if (state_r != RECOVERY_LOCKED || !engine_quiescent) begin
                rejected <= 1'b1;
                error_code <= ERR_PHASE;
            end else if (trusted_recover_q_limit == 32'b0 ||
                         trusted_recover_q > trusted_recover_q_limit ||
                         (trusted_recover_reserved &&
                          trusted_recover_q == trusted_recover_q_limit)) begin
                state_r <= ERROR_LOCKED;
                rejected <= 1'b1;
                error_code <= ERR_RANGE;
            end else if (trusted_recover_reserved &&
                         trusted_recover_tx == 32'hffffffff) begin
                state_r <= ERROR_LOCKED;
                rejected <= 1'b1;
                error_code <= ERR_OVERFLOW;
            end else begin
                key_id_r <= trusted_recover_key_id;
                epoch_r <= trusted_recover_epoch;
                session_r <= trusted_recover_session;
                q_limit_r <= trusted_recover_q_limit;
                registered_params_r <= trusted_recover_params;
                params_r <= trusted_recover_params;
                last_tx_r <= trusted_recover_tx;
                q_r <= trusted_recover_q;
                recover_accept <= 1'b1;
                if (trusted_recover_reserved) begin
                    next_q_r <= trusted_recover_q + 1'b1;
                    pending_tx_r <= trusted_recover_tx + 1'b1;
                    state_r <= FINALIZE_PENDING;
                end else begin
                    next_q_r <= trusted_recover_q;
                    state_r <= trusted_recover_q == trusted_recover_q_limit ?
                        EXHAUSTED : IDLE;
                end
            end
        end else if (trusted_ack_valid) begin
            if (!pending) begin
                rejected <= 1'b1;
                error_code <= ERR_PHASE;
            end else if (!receipt_matches) begin
                rejected <= 1'b1;
                error_code <= ERR_RECEIPT;
            end else begin
                ack_accept <= 1'b1;
                last_tx_r <= pending_tx_r;
                if (state_r == RESERVE_PENDING) begin
                    next_q_r <= q_r + 1'b1;
                    state_r <= RESERVED_READY;
                end else begin
                    state_r <= next_q_r == q_limit_r ? EXHAUSTED : IDLE;
                    context_r <= 256'b0;
                    params_r <= 64'b0;
                end
            end
        end else if (abort_valid) begin
            if (state_r == RESERVE_PENDING) begin
                /* Persistence may have happened even when its receipt is lost.
                 * Do not locally reuse q: require reset and trusted recovery. */
                state_r <= ERROR_LOCKED;
            end else if (state_r == RESERVED_READY || state_r == SIGNING) begin
                state_r <= DRAINING;
            end else begin
                rejected <= 1'b1;
                error_code <= ERR_PHASE;
            end
        end else if (begin_valid) begin
            if (state_r != IDLE || !engine_quiescent) begin
                rejected <= 1'b1;
                error_code <= ERR_PHASE;
            end else if (begin_params != registered_params_r ||
                         (LATE_BIND_CONTEXT && begin_context != 256'b0)) begin
                rejected <= 1'b1;
                error_code <= ERR_CONTEXT;
            end else if (next_q_r >= q_limit_r) begin
                state_r <= ERROR_LOCKED;
                rejected <= 1'b1;
                error_code <= ERR_RANGE;
            end else if (last_tx_r >= 32'hfffffffe) begin
                /* Reserve both tx values now: reservation and finalization. */
                state_r <= ERROR_LOCKED;
                rejected <= 1'b1;
                error_code <= ERR_OVERFLOW;
            end else begin
                q_r <= next_q_r;
                pending_tx_r <= last_tx_r + 1'b1;
                context_r <= begin_context;
                params_r <= begin_params;
                state_r <= RESERVE_PENDING;
                begin_accept <= 1'b1;
            end
        end else if (start_valid) begin
            if (state_r != RESERVED_READY || !engine_quiescent) begin
                rejected <= 1'b1;
                error_code <= ERR_PHASE;
            end else if (start_q != q_r || (!LATE_BIND_CONTEXT && start_context != context_r) ||
                         start_params != params_r) begin
                rejected <= 1'b1;
                error_code <= ERR_CONTEXT;
            end else begin
                if (LATE_BIND_CONTEXT) context_r <= start_context;
                state_r <= SIGNING;
                start_accept <= 1'b1;
            end
        end else if (engine_done) begin
            if (state_r != SIGNING) begin
                rejected <= 1'b1;
                error_code <= ERR_PHASE;
            end else if (!engine_quiescent) begin
                state_r <= ERROR_LOCKED;
                rejected <= 1'b1;
                error_code <= ERR_ENGINE;
            end else begin
                pending_tx_r <= last_tx_r + 1'b1;
                state_r <= FINALIZE_PENDING;
            end
        end else if (state_r == DRAINING && engine_quiescent) begin
            pending_tx_r <= last_tx_r + 1'b1;
            state_r <= FINALIZE_PENDING;
        end
    end
endmodule
`default_nettype wire
