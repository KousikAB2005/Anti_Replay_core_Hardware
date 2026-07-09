// =============================================================
// top.v
// Tang Nano 4K — Top Level
// Cortex-M3 + Anti-Replay Security Core only
//
// APB Slot 1 (psel1) : anti_replay_core @ 0x40002400
//
// Pins used:
//   clk          — onboard 27MHz oscillator
//   reset_button — active-low reset (USR_KEY)
//   uart0_txd    — USB-C UART TX (via CH552 bridge)
//   uart0_rxd    — USB-C UART RX (via CH552 bridge)
//   alert_led    — lights when attack detected (connect to onboard LED)
//   valid_led    — lights when packet accepted
// =============================================================

module top (
    input  wire clk,
    input  wire reset_button,
    output wire alert_led,
    output wire valid_led,
    output wire uart0_txd,
    input  wire uart0_rxd
);

    // ---- APB bus wires ----
    wire        apb_pclk;
    wire        apb_prst;
    wire        apb_psel1;
    wire        apb_penable;
    wire        apb_pwrite;
    wire [7:0]  apb_paddr;
    wire [31:0] apb_pwdata;
    wire [31:0] apb_prdata1;
    wire        apb_pready1;

    // ---- Gowin EMPU — Cortex-M3 hard core ----
    Gowin_EMPU_Top m3_inst (
        .sys_clk       (clk),
        .reset_n       (reset_button),
        .uart0_rxd     (uart0_rxd),
        .uart0_txd     (uart0_txd),
        .master_pclk   (apb_pclk),
        .master_prst   (apb_prst),
        .master_psel1  (apb_psel1),
        .master_penable(apb_penable),
        .master_paddr  (apb_paddr),
        .master_pwrite (apb_pwrite),
        .master_pwdata (apb_pwdata),
        .master_prdata1(apb_prdata1),
        .master_pready1(apb_pready1)
    );

    // ---- Anti-Replay Security Core ----
    anti_replay_core sec_core (
        .pclk      (apb_pclk),
        .presetn   (apb_prst),
        .paddr     ({24'd0, apb_paddr}),
        .psel      (apb_psel1),
        .penable   (apb_penable),
        .pwrite    (apb_pwrite),
        .pwdata    (apb_pwdata),
        .prdata    (apb_prdata1),
        .pready    (apb_pready1),
        .alert     (alert_led),
        .valid_out (valid_led)
    );

endmodule