`default_nettype none

//

//

//   1 = CHAIN     :I||q||i||j||chain_value(32B)||0x1F@55||0x80@135

//   3 = RANDOMIZER:I||q||0x8585||seed(32B)||0x1F@54||0x80@135
//

module lms_shake256_blockgen (
    input  wire [2:0]   task_type,       // 0=hash_once 1=chain 2=derive 3=randomizer 4=dleaf 5=pblc
    input  wire [1023:0] input_words_flat,
    input  wire [127:0] identifier_flat,
    input  wire [31:0]  arg_q,
    input  wire [15:0]  arg_i,
    input  wire [7:0]   chain_j,
    input  wire [255:0] chain_value,
    input  wire [255:0] chain_value_b = 256'b0,
    input  wire         derive_phase,
    input  wire [7:0]   input_length,
    input  wire [255:0] seed_a,

    input  wire [1087:0] rnd_block = 1088'b0,
    input  wire [255:0] seed_b = 256'b0,

    input  wire [31:0]  arg_leaf_node = 32'b0,   /* D_LEAF/D_INTR:node 4B */
    input  wire [255:0] dleaf_kq = 256'b0,
    input  wire [1087:0] pblc_buffer = 1088'b0,
    input  wire [7:0]   pblc_fill = 8'b0,
    input  wire         pblc_phase = 1'b0,
    input  wire [255:0] dintr_left = 256'b0,
    input  wire [255:0] dintr_right = 256'b0,

    output wire [1087:0] rate_block,
    output wire [1087:0] rate_block_b,
    output reg          rate_init,

    input  wire [255:0] core_digest,
    input  wire [255:0] core_digest_a = 256'b0,
    input  wire [255:0] core_digest_b = 256'b0,
    input  wire [255:0] core_digest_c = 256'b0,
    output wire [255:0] digest_bigendian,
    output wire [255:0] digest_bigendian_a,
    output wire [255:0] digest_bigendian_b
);

    reg  [1087:0] rate_block_p;
    reg  [1087:0] rate_block_b_seed;

    localparam [2:0] TASK_CHAIN     = 3'd1;
    localparam [2:0] TASK_DERIVE    = 3'd2;
    localparam [2:0] TASK_RANDOMIZER= 3'd3;
    localparam [2:0] TASK_DLEAF     = 3'd4;
    localparam [2:0] TASK_PBLC      = 3'd5;
    localparam [2:0] TASK_DINTR     = 3'd6;

    assign digest_bigendian = {
        core_digest[7:0],   core_digest[15:8],  core_digest[23:16], core_digest[31:24],
        core_digest[39:32], core_digest[47:40], core_digest[55:48], core_digest[63:56],
        core_digest[71:64], core_digest[79:72], core_digest[87:80], core_digest[95:88],
        core_digest[103:96], core_digest[111:104], core_digest[119:112], core_digest[127:120],
        core_digest[135:128], core_digest[143:136], core_digest[151:144], core_digest[159:152],
        core_digest[167:160], core_digest[175:168], core_digest[183:176], core_digest[191:184],
        core_digest[199:192], core_digest[207:200], core_digest[215:208], core_digest[223:216],
        core_digest[231:224], core_digest[239:232], core_digest[247:240], core_digest[255:248]};

    function automatic [255:0] share_be(input [255:0] value);
        integer byte_index;
        begin
            for (byte_index = 0; byte_index < 32; byte_index = byte_index + 1)
                share_be[255 - byte_index * 8 -: 8] = value[byte_index * 8 +: 8];
        end
    endfunction
    assign digest_bigendian_a = share_be(core_digest_a);
    assign digest_bigendian_b = share_be(core_digest_b ^ core_digest_c);

    integer k;
    always @* begin
        rate_block_p = 1088'b0;
        rate_init = 1'b0;
        case (task_type)
            TASK_CHAIN: begin
                for (k = 0; k < 16; k = k + 1) begin
                    rate_block_p[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end

                rate_block_p[16 * 8 +: 32] = {arg_q[7:0], arg_q[15:8], arg_q[23:16], arg_q[31:24]};
                rate_block_p[20 * 8 +: 16] = {arg_i[7:0], arg_i[15:8]};
                rate_block_p[22 * 8 +: 8]  = chain_j;
                for (k = 0; k < 32; k = k + 1) begin

                    rate_block_p[(23 + k) * 8 +: 8] = chain_value[248 - k * 8 +: 8];
                end
                rate_block_p[55 * 8 +: 8]  = 8'h1f;
                rate_block_p[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_DERIVE: begin
                for (k = 0; k < 16; k = k + 1) begin
                    rate_block_p[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                rate_block_p[16 * 8 +: 32] = {arg_q[7:0], arg_q[15:8], arg_q[23:16], arg_q[31:24]};
                rate_block_p[20 * 8 +: 16] = {arg_i[7:0], arg_i[15:8]};
                rate_block_p[22 * 8 +: 8]  = derive_phase ? 8'hff : chain_j;
                for (k = 0; k < 32; k = k + 1) begin

                    rate_block_p[(23 + k) * 8 +: 8] = derive_phase
                        ? seed_a[(7 - k / 4) * 32 + (k % 4) * 8 +: 8]
                        : chain_value[248 - k * 8 +: 8];
                end
                rate_block_p[55 * 8 +: 8]  = 8'h1f;
                rate_block_p[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_RANDOMIZER: begin
                for (k = 0; k < 16; k = k + 1) begin
                    rate_block_p[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                rate_block_p[16 * 8 +: 32] = {arg_q[7:0], arg_q[15:8], arg_q[23:16], arg_q[31:24]};
                rate_block_p[20 * 8 +: 16] = 16'h8585;
                for (k = 0; k < 32; k = k + 1) begin
                    rate_block_p[(22 + k) * 8 +: 8] = seed_a[(7 - k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                rate_block_p[54 * 8 +: 8]  = 8'h1f;
                rate_block_p[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_DLEAF: begin

                for (k = 0; k < 16; k = k + 1) begin
                    rate_block_p[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                for (k = 0; k < 4; k = k + 1) begin
                    rate_block_p[(16 + k) * 8 +: 8] = arg_leaf_node[(3 - k) * 8 +: 8];
                end
                rate_block_p[20 * 8 +: 8]  = 8'h82;
                rate_block_p[21 * 8 +: 8]  = 8'h82;
                for (k = 0; k < 32; k = k + 1) begin
                    rate_block_p[(22 + k) * 8 +: 8] = dleaf_kq[k * 8 +: 8];
                end
                rate_block_p[54 * 8 +: 8]  = 8'h1f;
                rate_block_p[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_DINTR: begin

                for (k = 0; k < 16; k = k + 1) begin
                    rate_block_p[k * 8 +: 8] = identifier_flat[
                        (k / 4) * 32 + (k % 4) * 8 +: 8];
                end
                for (k = 0; k < 4; k = k + 1) begin
                    rate_block_p[(16 + k) * 8 +: 8] = arg_leaf_node[(3 - k) * 8 +: 8];
                end
                rate_block_p[20 * 8 +: 8]  = 8'h83;
                rate_block_p[21 * 8 +: 8]  = 8'h83;
                for (k = 0; k < 32; k = k + 1) begin
                    rate_block_p[(22 + k) * 8 +: 8] = dintr_left[248 - k * 8 +: 8];
                    rate_block_p[(54 + k) * 8 +: 8] = dintr_right[248 - k * 8 +: 8];
                end
                rate_block_p[86 * 8 +: 8]  = 8'h1f;
                rate_block_p[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
            TASK_PBLC: begin

                rate_block_p = pblc_buffer;
                if (pblc_phase) begin
                    for (k = 0; k < 136; k = k + 1) begin
                        if (k[7:0] == pblc_fill)
                            rate_block_p[k * 8 +: 8] = 8'h1f;
                    end
                    rate_block_p[135 * 8 +: 8] = 8'h80;
                end
                rate_init = 1'b1;
            end
            default: begin

                for (k = 0; k < 128; k = k + 1) begin
                    if (k[7:0] < input_length) begin
                        rate_block_p[k * 8 +: 8] = input_words_flat[
                            (k / 4) * 32 + (k % 4) * 8 +: 8];
                    end
                end
                for (k = 0; k < 136; k = k + 1) begin
                    if (k[7:0] == input_length) rate_block_p[k * 8 +: 8] = 8'h1f;
                end
                rate_block_p[135 * 8 +: 8] = 8'h80;
                rate_init = 1'b1;
            end
        endcase
    end

    always @* begin
        rate_block_b_seed = 1088'b0;
        case (task_type)
            TASK_DERIVE: begin
                if (derive_phase) begin
                    for (k = 0; k < 32; k = k + 1) begin
                        rate_block_b_seed[(23 + k) * 8 +: 8] = seed_b[(7 - k / 4) * 32 + (k % 4) * 8 +: 8];
                    end
                end
            end
            TASK_RANDOMIZER: begin
                for (k = 0; k < 32; k = k + 1) begin
                    rate_block_b_seed[(22 + k) * 8 +: 8] = seed_b[(7 - k / 4) * 32 + (k % 4) * 8 +: 8];
                end
            end
            default: ;
        endcase
    end

    reg [1087:0] rate_block_b_chain;
    always @* begin
        rate_block_b_chain = 1088'b0;
        if ((task_type == TASK_CHAIN) ||
            ((task_type == TASK_DERIVE) && !derive_phase)) begin
            for (k = 0; k < 32; k = k + 1)
                rate_block_b_chain[(23 + k) * 8 +: 8] = chain_value_b[248 - k * 8 +: 8];
        end
    end

    reg [1087:0] seed_region_r;
    reg [1087:0] chain_region_r;
    integer sr_k;
    always @* begin
        seed_region_r = 1088'b0;
        chain_region_r = 1088'b0;
        case (task_type)
            TASK_CHAIN: begin
                for (sr_k = 0; sr_k < 32; sr_k = sr_k + 1)
                    chain_region_r[(23 + sr_k) * 8 +: 8] = 8'hff;
            end
            TASK_DERIVE: begin
                for (sr_k = 0; sr_k < 32; sr_k = sr_k + 1) begin
                    if (derive_phase)
                        seed_region_r[(23 + sr_k) * 8 +: 8] = 8'hff;
                    else
                        chain_region_r[(23 + sr_k) * 8 +: 8] = 8'hff;
                end
            end
            TASK_RANDOMIZER: begin
                for (sr_k = 0; sr_k < 32; sr_k = sr_k + 1)
                    seed_region_r[(22 + sr_k) * 8 +: 8] = 8'hff;
            end
            default: ;
        endcase
    end

    wire [1087:0] mask_region_w = rnd_block & ~(seed_region_r | chain_region_r);

    assign rate_block   = rate_block_p ^ mask_region_w;
    assign rate_block_b = rate_block_b_seed | rate_block_b_chain | mask_region_w;

endmodule

`default_nettype wire
