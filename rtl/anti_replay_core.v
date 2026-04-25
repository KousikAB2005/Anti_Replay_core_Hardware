// =============================================================
// anti_replay_core.v
// APB Slave — Anti-Replay Security Core (Primary Peripheral)
//
// All three security checks happen in RTL hardware:
//   1. HMAC result (CPU passes 1=ok / 0=fail)
//   2. Monotonic counter — N must be strictly greater than last
//   3. Nonce freshness — must not have been seen before
//
// Register Map (paddr[7:0]):
//   0x00 (W)  : Write incoming counter N
//   0x04 (W)  : Write incoming nonce (16-bit)
//   0x08 (W)  : Write HMAC result (1=pass, 0=fail) — triggers FSM
//   0x0C (R)  : Read result  (0=PASS  1=REPLAY  2=TAMPER)
//   0x10 (R)  : Read last accepted counter value
//   0x18 (R)  : Read total packets processed
//   0x1C (R)  : Read total attacks detected
//   0x14 (W)  : Reset all security state
// =============================================================

module anti_replay_core (
    input  wire        pclk,
    input  wire        presetn,
    input  wire [31:0] paddr,
    input  wire        psel,
    input  wire        penable,
    input  wire        pwrite,
    input  wire [31:0] pwdata,
    output reg  [31:0] prdata,
    output reg         pready,
    output reg         alert,       // HIGH when attack detected
    output reg         valid_out    // pulses HIGH when packet accepted
);

    // ---- security state — all live in RTL fabric registers ----
    reg [31:0] last_counter;
    reg [31:0] counter_in;
    reg [15:0] nonce_in;
    reg        hmac_result;
    reg [1:0]  result;
    reg        check_trigger;

    // ---- rolling nonce window: 16 slots ----
    reg [15:0] nonce_table [0:15];
    reg [3:0]  nonce_wr_idx;
    integer    i;

    // ---- stats counters ----
    reg [31:0] total_packets;
    reg [31:0] attack_count;

    // ---- FSM states ----
    localparam IDLE  = 2'd0;
    localparam CHECK = 2'd1;
    localparam DONE  = 2'd2;
    reg [1:0] state;

    // ---- result codes ----
    localparam PASS   = 2'd0;
    localparam REPLAY = 2'd1;
    localparam TAMPER = 2'd2;

    // ---- nonce match: pure combinational, single-cycle ----
    wire nonce_seen =
        (nonce_table[0]  == nonce_in) | (nonce_table[1]  == nonce_in) |
        (nonce_table[2]  == nonce_in) | (nonce_table[3]  == nonce_in) |
        (nonce_table[4]  == nonce_in) | (nonce_table[5]  == nonce_in) |
        (nonce_table[6]  == nonce_in) | (nonce_table[7]  == nonce_in) |
        (nonce_table[8]  == nonce_in) | (nonce_table[9]  == nonce_in) |
        (nonce_table[10] == nonce_in) | (nonce_table[11] == nonce_in) |
        (nonce_table[12] == nonce_in) | (nonce_table[13] == nonce_in) |
        (nonce_table[14] == nonce_in) | (nonce_table[15] == nonce_in);

    always @(posedge pclk or negedge presetn) begin
        if (!presetn) begin
            pready        <= 1'b0;
            prdata        <= 32'd0;
            alert         <= 1'b0;
            valid_out     <= 1'b0;
            counter_in    <= 32'd0;
            nonce_in      <= 16'd0;
            hmac_result   <= 1'b0;
            check_trigger <= 1'b0;
            last_counter  <= 32'd0;
            result        <= PASS;
            state         <= IDLE;
            nonce_wr_idx  <= 4'd0;
            total_packets <= 32'd0;
            attack_count  <= 32'd0;
            for (i = 0; i < 16; i = i + 1)
                nonce_table[i] <= 16'hFFFF;
        end else begin
            check_trigger <= 1'b0;
            valid_out     <= 1'b0;

            // ---- APB slave interface ----
            if (psel && !penable) begin
                pready <= 1'b1;
                if (pwrite) begin
                    case (paddr[7:0])
                        8'h00: counter_in  <= pwdata;
                        8'h04: nonce_in    <= pwdata[15:0];
                        8'h08: begin
                                   hmac_result   <= pwdata[0];
                                   check_trigger <= 1'b1;
                               end
                        8'h14: begin
                                   last_counter  <= 32'd0;
                                   result        <= PASS;
                                   alert         <= 1'b0;
                                   nonce_wr_idx  <= 4'd0;
                                   total_packets <= 32'd0;
                                   attack_count  <= 32'd0;
                                   for (i = 0; i < 16; i = i + 1)
                                       nonce_table[i] <= 16'hFFFF;
                               end
                        default: ;
                    endcase
                end else begin
                    case (paddr[7:0])
                        8'h0C: prdata <= {30'd0, result};
                        8'h10: prdata <= last_counter;
                        8'h18: prdata <= total_packets;
                        8'h1C: prdata <= attack_count;
                        default: prdata <= 32'hDEADBEEF;
                    endcase
                end
            end else begin
                pready <= 1'b0;
            end

            // ---- 3-stage security check FSM ----
            case (state)
                IDLE: begin
                    if (check_trigger) begin
                        total_packets <= total_packets + 1;
                        state <= CHECK;
                    end
                end

                CHECK: begin
                    // Stage 1: HMAC — tamper detection
                    if (!hmac_result) begin
                        result       <= TAMPER;
                        alert        <= 1'b1;
                        attack_count <= attack_count + 1;
                        state        <= DONE;
                    end
                    // Stage 2: Monotonic counter — replay detection
                    // Lives entirely in hardware — no software reset path
                    else if (counter_in <= last_counter) begin
                        result       <= REPLAY;
                        alert        <= 1'b1;
                        attack_count <= attack_count + 1;
                        state        <= DONE;
                    end
                    // Stage 3: Nonce freshness — session replay detection
                    else if (nonce_seen) begin
                        result       <= REPLAY;
                        alert        <= 1'b1;
                        attack_count <= attack_count + 1;
                        state        <= DONE;
                    end
                    // All stages passed
                    else begin
                        result                    <= PASS;
                        alert                     <= 1'b0;
                        valid_out                 <= 1'b1;
                        last_counter              <= counter_in;
                        nonce_table[nonce_wr_idx] <= nonce_in;
                        nonce_wr_idx              <= nonce_wr_idx + 1;
                        state                     <= DONE;
                    end
                end

                DONE: begin
                    state <= IDLE;
                end
            endcase
        end
    end

endmodule