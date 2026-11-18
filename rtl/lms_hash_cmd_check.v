`default_nettype none

/* verilator lint_off UNUSEDSIGNAL */
/* verilator lint_off UNUSEDPARAM */

//

//

//

//

module lms_hash_cmd_check #(
    parameter INSECURE_TEST_MODE = 0,
    parameter HAS_SECURITY = 1,
    parameter [7:0] MAX_ONCE_BYTES = 8'd128,
    parameter HAS_HASH_ONCE_RAM = 0,
    parameter [11:0] MAX_ONCE_BYTES_RAM = 12'd2048,
    parameter HAS_STATE_COMMIT = 0,
    parameter ALLOW_XQ_DERIVE = 0
) (
    input  wire [31:0] command,
    input  wire [31:0] input_length,
    input  wire [31:0] output_length,
    input  wire [31:0] arg_i,
    input  wire [31:0] arg_start,
    input  wire [31:0] arg_steps,
    input  wire [31:0] arg_key,
    input  wire        seed_valid,
    input  wire        k_wrap_valid,
    input  wire        k_state_valid,
    input  wire        sign_coef_valid,  /* hardware MQC provenance; not a reservation */
    input  wire [31:0] lmots_sign_y_len,
    output reg         valid,
    output reg  [31:0] error_code,
    output reg  [3:0]  action
);
    localparam [31:0] CMD_HASH_ONCE        = 32'h00000001;
    localparam [31:0] CMD_CHAIN            = 32'h00000002;
    localparam [31:0] CMD_SEED_LOAD        = 32'h00000003;
    localparam [31:0] CMD_DERIVE_CHAIN     = 32'h00000004;
    localparam [31:0] CMD_DERIVE_RANDOMIZER= 32'h00000005;
    localparam [31:0] CMD_LMOTS_KEYGEN     = 32'h00000006;
    localparam [31:0] CMD_LMOTS_SIGN       = 32'h00000007;
    localparam [31:0] CMD_LMOTS_VERIFY     = 32'h00000008;
    localparam [31:0] CMD_MC_STEP          = 32'h00000010;
    localparam [31:0] CMD_MC_LOAD          = 32'h00000011;
    localparam [31:0] CMD_WRAP_SEED        = 32'h00000012;
    localparam [31:0] CMD_UNWRAP_SEED      = 32'h00000013;
    localparam [31:0] CMD_HMAC_KSTATE      = 32'h00000014;
    localparam [31:0] CMD_STATE_COMMIT     = 32'h00000015;
    localparam [31:0] CMD_LMOTS_KEYGEN_LEAF= 32'h0000000e;
    localparam [31:0] CMD_LMOTS_VERIFY_LEAF= 32'h0000000f;
    localparam [31:0] CMD_D_INTR_CHAIN     = 32'h00000018;
    localparam [31:0] CMD_HASH_ONCE_RAM    = 32'h00000019;
    localparam [31:0] CMD_MSG_Q_COEF       = 32'h0000001a;
    localparam [31:0] CMD_SEED_WRITE_SAFE  = 32'h0000001c;

    localparam [31:0] ERR_UNSUPPORTED_COMMAND = 32'h00000001;
    localparam [31:0] ERR_INPUT_LENGTH        = 32'h00000003;
    localparam [31:0] ERR_OUTPUT_LENGTH       = 32'h00000004;
    localparam [31:0] ERR_CHAIN_INDEX         = 32'h00000005;
    localparam [31:0] ERR_CHAIN_RANGE         = 32'h00000006;
    localparam [31:0] ERR_KEY_HANDLE          = 32'h00000008;
    localparam [31:0] ERR_SEED_NOT_LOADED     = 32'h00000009;
    localparam [31:0] ERR_INSECURE_DISABLED   = 32'h0000000a;
    localparam [31:0] ERR_SIGN_CONTEXT        = 32'h00000011;

    localparam [3:0] ACT_START       = 4'd0;
    localparam [3:0] ACT_DONE_SEED   = 4'd1;
    localparam [3:0] ACT_DONE_CHAIN0 = 4'd2;
    localparam [3:0] ACT_DONE_KWRAP  = 4'd3;
    localparam [3:0] ACT_DONE_KSTATE = 4'd4;
    localparam [3:0] ACT_DONE_MC     = 4'd5;
    localparam [3:0] ACT_START_HMAC  = 4'd6;
    localparam [3:0] ACT_START_WRAP  = 4'd7;
    localparam [3:0] ACT_START_STC   = 4'd8;

    always @* begin
        valid = 1'b0;
        error_code = 32'b0;
        action = ACT_START;

        if (command != CMD_HASH_ONCE && command != CMD_CHAIN &&
            command != CMD_SEED_LOAD && command != CMD_DERIVE_CHAIN &&
            command != CMD_DERIVE_RANDOMIZER &&
            command != CMD_LMOTS_KEYGEN && command != CMD_LMOTS_KEYGEN_LEAF &&
            command != CMD_LMOTS_SIGN && command != CMD_LMOTS_VERIFY &&
            command != CMD_LMOTS_VERIFY_LEAF &&
            command != CMD_D_INTR_CHAIN &&
            command != CMD_MSG_Q_COEF &&
            !(HAS_SECURITY && command == CMD_SEED_WRITE_SAFE) &&
            !(HAS_HASH_ONCE_RAM && command == CMD_HASH_ONCE_RAM) &&
            !(HAS_STATE_COMMIT && command == CMD_STATE_COMMIT) &&
            !(HAS_SECURITY &&
              (command == CMD_MC_STEP || command == CMD_MC_LOAD ||
               command == CMD_WRAP_SEED || command == CMD_UNWRAP_SEED ||
               command == CMD_HMAC_KSTATE))) begin
            error_code = ERR_UNSUPPORTED_COMMAND;
        end else if (!INSECURE_TEST_MODE &&
                     (command == CMD_DERIVE_CHAIN || command == CMD_DERIVE_RANDOMIZER)) begin
            /* Independent secret-derived outputs are diagnostic capabilities.
             * ALLOW_XQ_DERIVE must never override the deployment boundary. */
            error_code = ERR_INSECURE_DISABLED;
        end else if (command == CMD_HASH_ONCE_RAM && input_length > MAX_ONCE_BYTES_RAM) begin
            error_code = ERR_INPUT_LENGTH;
        end else if (command == CMD_MSG_Q_COEF && input_length > MAX_ONCE_BYTES_RAM) begin

            error_code = ERR_INPUT_LENGTH;
        end else if (HAS_SECURITY && command == CMD_HMAC_KSTATE && !k_state_valid) begin
            error_code = ERR_KEY_HANDLE;
        end else if (HAS_SECURITY && command == CMD_HMAC_KSTATE && input_length > 119) begin

            error_code = ERR_INPUT_LENGTH;
        end else if (HAS_SECURITY && command == CMD_HMAC_KSTATE) begin
            valid = 1'b1;
            action = ACT_START_HMAC;
        end else if (HAS_STATE_COMMIT && command == CMD_STATE_COMMIT && !k_state_valid) begin
            error_code = ERR_KEY_HANDLE;
        end else if (HAS_STATE_COMMIT && command == CMD_STATE_COMMIT) begin
            valid = 1'b1;
            action = ACT_START_STC;
        end else if (HAS_SECURITY && command == CMD_MC_STEP) begin
            valid = 1'b1;
            action = ACT_DONE_MC;
        end else if (HAS_SECURITY && command == CMD_MC_LOAD) begin
            valid = 1'b1;
            action = ACT_DONE_MC;
        end else if (HAS_SECURITY &&
                     (command == CMD_WRAP_SEED || command == CMD_UNWRAP_SEED) &&
                     !k_wrap_valid) begin
            error_code = ERR_KEY_HANDLE;
        end else if (HAS_SECURITY && command == CMD_WRAP_SEED && !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if (HAS_SECURITY &&
                     (command == CMD_WRAP_SEED || command == CMD_UNWRAP_SEED)) begin
            valid = 1'b1;
            action = ACT_START_WRAP;
        end else if (command == CMD_HASH_ONCE && input_length > MAX_ONCE_BYTES) begin
            error_code = ERR_INPUT_LENGTH;
        end else if (command == CMD_SEED_LOAD && !INSECURE_TEST_MODE &&
                     (!HAS_SECURITY || arg_key == 32'd0)) begin

            error_code = ERR_INSECURE_DISABLED;
        end else if (command == CMD_SEED_LOAD && HAS_SECURITY && arg_key > 2) begin
            error_code = ERR_KEY_HANDLE;
        end else if (command == CMD_SEED_LOAD && HAS_SECURITY && arg_key == 1) begin
            valid = 1'b1;
            action = ACT_DONE_KWRAP;
        end else if (command == CMD_SEED_LOAD && HAS_SECURITY && arg_key == 2) begin
            valid = 1'b1;
            action = ACT_DONE_KSTATE;
        end else if (HAS_SECURITY && command == CMD_SEED_WRITE_SAFE) begin

            valid = 1'b1;
            action = ACT_DONE_SEED;
        end else if (command == CMD_SEED_LOAD) begin
            valid = 1'b1;
            action = ACT_DONE_SEED;
        end else if ((command == CMD_LMOTS_SIGN && output_length != lmots_sign_y_len) ||
                     (command != CMD_LMOTS_SIGN && output_length != 32'd32)) begin
            error_code = ERR_OUTPUT_LENGTH;
        end else if ((command == CMD_CHAIN || command == CMD_DERIVE_CHAIN) &&
                     arg_i[31:16] != 0) begin
            error_code = ERR_CHAIN_INDEX;
        end else if ((command == CMD_CHAIN || command == CMD_DERIVE_CHAIN) &&
                     (arg_start[31:8] != 0 || arg_steps[31:8] != 0 ||
                      {1'b0, arg_start[7:0]} + {1'b0, arg_steps[7:0]} > 9'd255)) begin
            error_code = ERR_CHAIN_RANGE;
        end else if (command == CMD_DERIVE_CHAIN && arg_steps < 9'd2 &&
                     !(ALLOW_XQ_DERIVE && arg_steps == 32'd0)) begin

            error_code = ERR_CHAIN_RANGE;
        end else if (command == CMD_DERIVE_CHAIN && arg_key != 0) begin
            error_code = ERR_KEY_HANDLE;
        end else if (command == CMD_DERIVE_CHAIN && !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if (command == CMD_DERIVE_RANDOMIZER && arg_key != 0) begin
            error_code = ERR_KEY_HANDLE;
        end else if (command == CMD_DERIVE_RANDOMIZER && !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if ((command == CMD_LMOTS_KEYGEN || command == CMD_LMOTS_KEYGEN_LEAF) &&
                     arg_key != 0) begin
            error_code = ERR_KEY_HANDLE;
        end else if ((command == CMD_LMOTS_KEYGEN || command == CMD_LMOTS_KEYGEN_LEAF) &&
                     !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if (command == CMD_LMOTS_SIGN && arg_key != 0) begin
            error_code = ERR_KEY_HANDLE;
        end else if (command == CMD_LMOTS_SIGN && !seed_valid) begin
            error_code = ERR_SEED_NOT_LOADED;
        end else if (command == CMD_LMOTS_SIGN && !INSECURE_TEST_MODE && !sign_coef_valid) begin
            error_code = ERR_SIGN_CONTEXT;
        end else if (command == CMD_CHAIN && arg_steps == 0) begin
            valid = 1'b1;
            action = ACT_DONE_CHAIN0;
        end else begin
            valid = 1'b1;
            action = ACT_START;
        end
    end

endmodule

`default_nettype wire
