# Anti-Replay Security Core

A hardware-enforced anti-replay security peripheral implemented in Verilog, integrated with an ARM Cortex-M3 soft core on the **Gowin Tang Nano 4K** FPGA. All three security checks — HMAC validation, monotonic counter enforcement, and nonce freshness — execute entirely in RTL logic, making them tamper-resistant from the software layer.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Security Checks](#security-checks)
- [Register Map](#register-map)
- [Directory Structure](#directory-structure)
- [Hardware Setup](#hardware-setup)
- [Firmware Usage](#firmware-usage)
- [UART Protocol](#uart-protocol)
- [FSM Description](#fsm-description)
- [Building & Flashing](#building--flashing)
- [License](#license)

---

## Overview

Replay attacks occur when a valid authenticated message is captured and retransmitted to fool a receiver into accepting it again. This project implements a dedicated security peripheral that detects and blocks such attacks at the hardware level — no software can bypass it.

Key features:

- **3-stage security pipeline** running in a hardware FSM
- **APB slave interface** for Cortex-M3 integration
- **16-entry rolling nonce window** for session-level replay detection
- **Monotonic counter** enforced in silicon — cannot be rolled back
- **Hardware alert LED** triggers instantly on attack detection
- **Stats counters** for total packets and total attacks, readable over UART

---

## Architecture

```
                    ┌─────────────────────────────┐
                    │       Tang Nano 4K FPGA      │
                    │                              │
  USB-C UART ──────►│  Gowin Cortex-M3 (EMPU)     │
                    │         │                    │
                    │    APB Bus (psel1)            │
                    │         │                    │
                    │  ┌──────▼──────────────────┐ │
                    │  │  Anti-Replay Security   │ │
                    │  │       Core              │ │
                    │  │  ┌──────────────────┐  │ │──► alert_led
                    │  │  │ HMAC Check       │  │ │
                    │  │  │ Counter Check    │  │ │──► valid_led
                    │  │  │ Nonce Check      │  │ │
                    │  │  └──────────────────┘  │ │
                    │  └─────────────────────────┘ │
                    └─────────────────────────────┘
```

The Cortex-M3 receives packets over UART, parses them in firmware, and writes the fields into the security core over the APB bus. The RTL FSM performs all three security checks and writes back a pass/fail result code — the CPU only reads an outcome, it never makes the security decision.

---

## Security Checks

All three checks occur sequentially in a single 3-state FSM:

| Stage | Check | Failure Code |
|-------|-------|--------------|
| 1 | **HMAC Validation** — CPU passes `1` (pass) or `0` (fail) | `TAMPER (2)` |
| 2 | **Monotonic Counter** — incoming `N` must be strictly greater than `last_counter` | `REPLAY (1)` |
| 3 | **Nonce Freshness** — 16-bit nonce must not exist in the rolling 16-entry table | `REPLAY (1)` |

If all three pass, the packet is accepted, `last_counter` is updated, and the nonce is stored in the circular table. `valid_out` pulses high for one clock cycle.

---

## Register Map

Base address: `0x40002400` (APB Slot 1)

| Offset | Access | Description |
|--------|--------|-------------|
| `0x00` | W | Incoming counter value `N` |
| `0x04` | W | Incoming nonce (16-bit) |
| `0x08` | W | HMAC result (`1`=pass, `0`=fail) — **triggers FSM** |
| `0x0C` | R | Result code (`0`=PASS, `1`=REPLAY, `2`=TAMPER) |
| `0x10` | R | Last accepted counter value |
| `0x14` | W | Reset all security state |
| `0x18` | R | Total packets processed |
| `0x1C` | R | Total attacks detected |

> **Note:** Writing to `0x08` is the FSM trigger. Always write `0x00` and `0x04` first.

---

## Directory Structure

```
.
├── rtl/
│   ├── anti_replay_core.v   # APB security peripheral (primary RTL)
│   └── top_m3.v             # Top-level: Cortex-M3 + security core
├── firmware/
│   └── main.c               # Cortex-M3 firmware — UART shell + APB driver
├── docs/
│   └── register_map.md      # Detailed register descriptions
├── README.md
└── LICENSE
```

---

## Hardware Setup

**Target board:** Gowin Tang Nano 4K

| Signal | FPGA Pin | Description |
|--------|----------|-------------|
| `clk` | — | Onboard 27 MHz oscillator |
| `reset_button` | USR_KEY | Active-low reset |
| `uart0_txd` | — | USB-C UART TX (via CH552 bridge) |
| `uart0_rxd` | — | USB-C UART RX (via CH552 bridge) |
| `alert_led` | Onboard LED | Lights on attack detection |
| `valid_led` | Onboard LED | Pulses on accepted packet |

Connect to the board via USB-C. The CH552 bridge exposes a virtual COM port — use any serial terminal at **115200 baud, 8N1**.

---

## Firmware Usage

The firmware presents a simple UART shell. After reset you will see:

```
--- Anti-Replay Security Core Online ---
Format : N=001,nonce=A3F2,data=25,hmac=OK
         use hmac=FAIL to simulate tamper
Commands: RESET | STATS
>
```

### Send a packet

```
> N=001,nonce=A3F2,data=25,hmac=OK
[OK]     N=1  nonce=0xA3F2  data=25  -- ACCEPTED
```

### Simulate a replay attack (reuse same N)

```
> N=001,nonce=B100,data=10,hmac=OK
[ATTACK] N=1  nonce=0xB100  -- REPLAY DETECTED
```

### Simulate HMAC tamper

```
> N=002,nonce=C200,data=99,hmac=FAIL
[ATTACK] N=2  -- TAMPER DETECTED (HMAC failed)
```

### View stats

```
> STATS

--- stats ---
total packets : 3
attacks caught: 2
last good N   : 1
-------------
```

### Reset security state

```
> RESET
[SYS] Cleared.
```

---

## UART Protocol

Packet format (comma-separated, single line):

```
N=<decimal>,nonce=<4-hex-digits>,data=<signed-decimal>,hmac=<OK|FAIL>
```

Examples:

```
N=042,nonce=1A2B,data=-7,hmac=OK
N=043,nonce=FFFF,data=0,hmac=FAIL
```

---

## FSM Description

```
         ┌──────┐   check_trigger=1    ┌───────┐
  RST ──►│ IDLE │──────────────────────► CHECK │
         └──────┘                      └───┬───┘
             ▲                             │
             │                      HMAC? Counter? Nonce?
             │                             │
         ┌───┴──┐   (1 cycle)         ┌───▼───┐
         │ DONE │◄────────────────────│ result│
         └──────┘                     └───────┘
```

The FSM takes **3 clock cycles** per packet: IDLE → CHECK → DONE → IDLE. The CPU busy-wait loop in firmware (20 NOP iterations) is sufficient to cover this latency.

---

## Building & Flashing

### RTL — Gowin EDA

1. Open Gowin EDA and create a new project targeting the **GW1NSR-4C** device.
2. Add `rtl/anti_replay_core.v` and `rtl/top_m3.v` as source files.
3. Instantiate the **Gowin_EMPU** IP core (Cortex-M3) and link it to the top module.
4. Set pin constraints as per the Hardware Setup table.
5. Run Synthesis → Place & Route → Generate Bitstream.
6. Flash via **Gowin Programmer** over USB.

### Firmware — ARM GCC

```bash
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O1 \
  -o main.elf firmware/main.c \
  -T linker.ld -nostdlib

arm-none-eabi-objcopy -O binary main.elf main.bin
```

Load `main.bin` as the embedded ROM image in your Gowin EMPU IP configuration before generating the bitstream.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
