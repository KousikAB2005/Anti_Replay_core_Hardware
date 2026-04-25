#include <stdint.h>
#include "uart.h"

// ---- Anti-Replay Security Core registers ----
#define SEC_BASE        0x40002400
#define SEC_COUNTER    (*(volatile uint32_t *)(SEC_BASE + 0x00))
#define SEC_NONCE      (*(volatile uint32_t *)(SEC_BASE + 0x04))
#define SEC_HMAC_OK    (*(volatile uint32_t *)(SEC_BASE + 0x08))
#define SEC_RESULT     (*(volatile uint32_t *)(SEC_BASE + 0x0C))
#define SEC_LAST_N     (*(volatile uint32_t *)(SEC_BASE + 0x10))
#define SEC_RESET      (*(volatile uint32_t *)(SEC_BASE + 0x14))
#define SEC_TOTAL      (*(volatile uint32_t *)(SEC_BASE + 0x18))
#define SEC_ATTACKS    (*(volatile uint32_t *)(SEC_BASE + 0x1C))

#define RESULT_PASS    0
#define RESULT_REPLAY  1
#define RESULT_TAMPER  2

typedef struct {
    uint32_t counter;
    uint16_t nonce;
    int32_t  data;
    uint8_t  hmac_valid;
} Packet;

// ---- print helpers — exact same pattern as your working code ----
void print_u32(uint32_t n) {
    char buf[12];
    char char_str[2] = {0, 0};
    if (n == 0) { uart_puts(UART0, "0"); return; }
    int i = 0;
    while (n > 0) { buf[i++] = (n % 10) + '0'; n /= 10; }
    while (--i >= 0) { char_str[0] = buf[i]; uart_puts(UART0, char_str); }
}

void print_i32(int32_t n) {
    if (n < 0) { uart_puts(UART0, "-"); print_u32((uint32_t)(-n)); }
    else        print_u32((uint32_t)n);
}

void print_hex16(uint16_t v) {
    char char_str[2] = {0, 0};
    int i;
    for (i = 3; i >= 0; i--) {
        uint8_t nibble = (v >> (i * 4)) & 0xF;
        char_str[0] = nibble < 10 ? '0' + nibble : 'A' + nibble - 10;
        uart_puts(UART0, char_str);
    }
}

// ---- uart readline with echo ----
// uart_getchar blocks until a char is ready — matches your uart.h
void uart_readline(char *buf, int maxlen) {
    int  i = 0;
    char c;
    char echo[2] = {0, 0};
    while (i < maxlen - 1) {
        c = uart_getchar(UART0);
        if (c == '\r' || c == '\n') break;
        echo[0] = c;
        uart_puts(UART0, echo);
        buf[i++] = c;
    }
    buf[i] = '\0';
    uart_puts(UART0, "\r\n");
}

// ---- minimal string helpers (no stdlib needed) ----
int str_startswith(const char *s, const char *pre) {
    while (*pre) { if (*s++ != *pre++) return 0; }
    return 1;
}

const char *str_find(const char *s, const char *needle) {
    int nlen = 0;
    const char *p = needle;
    while (*p++) nlen++;
    while (*s) {
        int match = 1, j;
        for (j = 0; j < nlen; j++) {
            if (s[j] != needle[j]) { match = 0; break; }
        }
        if (match) return s;
        s++;
    }
    return 0;
}

// ---- packet parser ----
// Format: N=001,nonce=A3F2,data=25,hmac=OK
int parse_packet(const char *line, Packet *pkt) {
    const char *p;
    uint32_t n = 0, nonce = 0;
    int32_t  data = 0;
    int      neg = 0;

    p = str_find(line, "N=");
    if (!p) return 0;
    p += 2;
    while (*p >= '0' && *p <= '9') n = n * 10 + (*p++ - '0');

    p = str_find(line, "nonce=");
    if (!p) return 0;
    p += 6;
    while (1) {
        char c = *p;
        if      (c >= '0' && c <= '9') nonce = (nonce << 4) | (uint32_t)(c - '0');
        else if (c >= 'A' && c <= 'F') nonce = (nonce << 4) | (uint32_t)(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') nonce = (nonce << 4) | (uint32_t)(c - 'a' + 10);
        else break;
        p++;
    }

    p = str_find(line, "data=");
    if (!p) return 0;
    p += 5;
    if (*p == '-') { neg = 1; p++; }
    while (*p >= '0' && *p <= '9') data = data * 10 + (*p++ - '0');
    if (neg) data = -data;

    p = str_find(line, "hmac=");
    if (!p) return 0;
    p += 5;

    pkt->counter    = n;
    pkt->nonce      = (uint16_t)(nonce & 0xFFFF);
    pkt->data       = data;
    pkt->hmac_valid = (p[0]=='O' && p[1]=='K') ? 1 : 0;
    return 1;
}

// ---- submit to RTL security core over APB ----
uint32_t check_packet(const Packet *pkt) {
    volatile int d;
    SEC_COUNTER = pkt->counter;
    SEC_NONCE   = (uint32_t)pkt->nonce;
    SEC_HMAC_OK = (uint32_t)pkt->hmac_valid;  // write triggers RTL FSM
    for (d = 0; d < 20; d++);                 // wait for FSM to complete
    return SEC_RESULT;
}

void print_result(uint32_t result, const Packet *pkt) {
    if (result == RESULT_PASS) {
        uart_puts(UART0, "[OK]     N=");   print_u32(pkt->counter);
        uart_puts(UART0, "  nonce=0x");    print_hex16(pkt->nonce);
        uart_puts(UART0, "  data=");       print_i32(pkt->data);
        uart_puts(UART0, "  -- ACCEPTED\r\n");
    } else if (result == RESULT_REPLAY) {
        uart_puts(UART0, "[ATTACK] N=");   print_u32(pkt->counter);
        uart_puts(UART0, "  nonce=0x");    print_hex16(pkt->nonce);
        uart_puts(UART0, "  -- REPLAY DETECTED\r\n");
    } else {
        uart_puts(UART0, "[ATTACK] N=");   print_u32(pkt->counter);
        uart_puts(UART0, "  -- TAMPER DETECTED (HMAC failed)\r\n");
    }
}

void print_stats(void) {
    uart_puts(UART0, "\r\n--- stats ---\r\n");
    uart_puts(UART0, "total packets : "); print_u32(SEC_TOTAL);   uart_puts(UART0, "\r\n");
    uart_puts(UART0, "attacks caught: "); print_u32(SEC_ATTACKS); uart_puts(UART0, "\r\n");
    uart_puts(UART0, "last good N   : "); print_u32(SEC_LAST_N);  uart_puts(UART0, "\r\n");
    uart_puts(UART0, "-------------\r\n");
}

void delay(int ms) {
    for (volatile int i = 0; i < ms * 2000; i++);
}

int main() {
    char   line[80];
    Packet pkt;

    uart_init(UART0, 234);

    uart_puts(UART0, "\r\n--- Anti-Replay Security Core Online ---\r\n");
    uart_puts(UART0, "Format : N=001,nonce=A3F2,data=25,hmac=OK\r\n");
    uart_puts(UART0, "         use hmac=FAIL to simulate tamper\r\n");
    uart_puts(UART0, "Commands: RESET | STATS\r\n");
    uart_puts(UART0, "> ");

    while (1) {
        uart_readline(line, sizeof(line));

        if (line[0] == '\0') {
            uart_puts(UART0, "> ");
            continue;
        }

        if (str_startswith(line, "RESET")) {
            SEC_RESET = 1;
            uart_puts(UART0, "[SYS] Cleared.\r\n> ");
            continue;
        }

        if (str_startswith(line, "STATS")) {
            print_stats();
            uart_puts(UART0, "> ");
            continue;
        }

        if (!parse_packet(line, &pkt)) {
            uart_puts(UART0, "[ERR] Bad format. Try: N=001,nonce=A3F2,data=25,hmac=OK\r\n> ");
            continue;
        }

        print_result(check_packet(&pkt), &pkt);
        uart_puts(UART0, "> ");
    }

    return 0;
}
