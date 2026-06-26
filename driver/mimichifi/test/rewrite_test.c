/*
 * Off-target unit test for MimicHiFi_RewriteIpId (mimichifi.h).
 *
 * The core is pure byte arithmetic with no NDIS/WDK types, so it compiles and runs on
 * the host. We shim the few WDK macros the header's IOCTL #defines use.
 *
 *   gcc -Wall -Wextra -o rewrite_test rewrite_test.c && ./rewrite_test
 *
 * Covers the 2026-06-26 offload fix: recomputeChecksum==0 must leave the IP checksum
 * field UNTOUCHED (the NIC fills it); recomputeChecksum!=0 computes a valid checksum.
 */
#include <stdio.h>
#include <string.h>

#ifndef __forceinline
#define __forceinline static inline
#endif
#ifndef CTL_CODE
#define CTL_CODE(t, f, m, a) (((t) << 16) | ((a) << 14) | ((f) << 2) | (m))
#define METHOD_BUFFERED 0
#define FILE_WRITE_ACCESS 2
#endif

#include "../mimichifi.h"

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } \
    else { printf("ok:   %s\n", msg); } \
} while (0)

/* Build a minimal IPv4 header (20 bytes) at buf with given proto + id. */
static void mkip(unsigned char *buf, unsigned char proto, unsigned short id,
                 unsigned char ck_hi, unsigned char ck_lo)
{
    memset(buf, 0, 20);
    buf[0] = 0x45;                 /* v4, ihl=5 (20 bytes) */
    buf[2] = 0; buf[3] = 40;       /* total length (arbitrary) */
    buf[4] = (unsigned char)(id >> 8); buf[5] = (unsigned char)(id & 0xFF);
    buf[8] = 64;                   /* ttl */
    buf[9] = proto;
    buf[10] = ck_hi; buf[11] = ck_lo;  /* checksum field (placeholder/sentinel) */
    buf[12] = 10; buf[13] = 0; buf[14] = 0; buf[15] = 1;   /* src */
    buf[16] = 10; buf[17] = 0; buf[18] = 0; buf[19] = 2;   /* dst */
}

static unsigned short ipid(const unsigned char *b){ return (unsigned short)((b[4]<<8)|b[5]); }
static unsigned short ipck(const unsigned char *b){ return (unsigned short)((b[10]<<8)|b[11]); }

int main(void)
{
    unsigned char b[64];
    int r;

    /* 1. TCP, recompute=1 (in-band): id->0 and checksum valid. */
    mkip(b, MIMICHIFI_PROTO_TCP, 0x1234, 0xDE, 0xAD);
    r = MimicHiFi_RewriteIpId(b, 20, MIMICHIFI_MODE_LINUX, 0, 1);
    CHECK(r == 1, "TCP recompute: returns modified");
    CHECK(ipid(b) == 0, "TCP recompute: IP-ID -> 0 (TI=Z)");
    CHECK(MimicHiFi_IpChecksum16(b, 20) == 0, "TCP recompute: checksum validates to 0");

    /* 2. TCP, recompute=0 (offload): id->0 BUT checksum field left untouched (NIC fills). */
    mkip(b, MIMICHIFI_PROTO_TCP, 0x1234, 0xAB, 0xCD);
    r = MimicHiFi_RewriteIpId(b, 20, MIMICHIFI_MODE_LINUX, 0, 0);
    CHECK(r == 1, "TCP offload: returns modified");
    CHECK(ipid(b) == 0, "TCP offload: IP-ID -> 0 (TI=Z)");
    CHECK(ipck(b) == 0xABCD, "TCP offload: checksum field UNTOUCHED (the fix)");

    /* 2b. Offload with the stack's 0 placeholder stays 0 (NIC computes over modified hdr). */
    mkip(b, MIMICHIFI_PROTO_TCP, 0x1234, 0x00, 0x00);
    MimicHiFi_RewriteIpId(b, 20, MIMICHIFI_MODE_LINUX, 0, 0);
    CHECK(ipck(b) == 0x0000, "TCP offload: 0 placeholder stays 0");

    /* 3. ICMP, recompute=1: id -> supplied icmpId, checksum valid. */
    mkip(b, MIMICHIFI_PROTO_ICMP, 0x0000, 0x00, 0x00);
    r = MimicHiFi_RewriteIpId(b, 20, MIMICHIFI_MODE_LINUX, 0x0042, 1);
    CHECK(r == 1, "ICMP: returns modified");
    CHECK(ipid(b) == 0x0042, "ICMP: IP-ID -> supplied icmpId (II=I)");
    CHECK(MimicHiFi_IpChecksum16(b, 20) == 0, "ICMP: checksum validates to 0");

    /* 4. UDP / non-IPv4 / short / not-armed: untouched. */
    mkip(b, 17 /*UDP*/, 0x1234, 0xDE, 0xAD);
    r = MimicHiFi_RewriteIpId(b, 20, MIMICHIFI_MODE_LINUX, 0, 1);
    CHECK(r == 0 && ipid(b) == 0x1234, "UDP: untouched");

    mkip(b, MIMICHIFI_PROTO_TCP, 0x1234, 0xDE, 0xAD);
    b[0] = 0x65; /* version 6 nibble */
    r = MimicHiFi_RewriteIpId(b, 20, MIMICHIFI_MODE_LINUX, 0, 1);
    CHECK(r == 0, "non-IPv4: untouched");

    mkip(b, MIMICHIFI_PROTO_TCP, 0x1234, 0xDE, 0xAD);
    r = MimicHiFi_RewriteIpId(b, 19, MIMICHIFI_MODE_LINUX, 0, 1);
    CHECK(r == 0, "iplen<20: untouched");

    mkip(b, MIMICHIFI_PROTO_TCP, 0x1234, 0xDE, 0xAD);
    r = MimicHiFi_RewriteIpId(b, 20, MIMICHIFI_MODE_OFF, 0, 1);
    CHECK(r == 0, "mode OFF: untouched");

    /* 5. TCP already 0: no-op (avoids needless work). */
    mkip(b, MIMICHIFI_PROTO_TCP, 0x0000, 0xAB, 0xCD);
    r = MimicHiFi_RewriteIpId(b, 20, MIMICHIFI_MODE_LINUX, 0, 1);
    CHECK(r == 0 && ipck(b) == 0xABCD, "TCP id already 0: no-op, checksum untouched");

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
