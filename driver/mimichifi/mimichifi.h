/*
 * mimichifi.h — shared contract + core IP-ID rewrite for the mimic-hifi NDIS LWF.
 *
 * The high-fidelity corrector: while ARMED, an outbound IPv4 TCP packet gets IP-ID 0
 * (nmap TI/CI=Z) and ICMP gets an incrementing IP-ID (nmap II=I), then the IPv4 header
 * checksum is recomputed. Done at the NDIS miniport edge, BELOW the Windows IP transmit
 * re-stamp that defeats WinDivert. Per-protocol only — no per-flow state.
 *
 * The IOCTL codes + device name below are the contract the Go client speaks
 * (internal/stack/hifi_windows.go). Keep them in lockstep.
 */
#pragma once

/* ---- control channel contract (must match internal/stack/hifi_windows.go) ---- */

#define MIMICHIFI_NT_DEVICE_NAME   L"\\Device\\MimicHiFi"
#define MIMICHIFI_DOS_DEVICE_NAME  L"\\DosDevices\\MimicHiFi"   /* user mode: \\.\MimicHiFi */

/* CTL_CODE(FILE_DEVICE_NETWORK=0x12, fn, METHOD_BUFFERED=0, FILE_WRITE_ACCESS=0x2) */
#define IOCTL_MIMICHIFI_ARM     CTL_CODE(0x12, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS) /* 0x0012A000 */
#define IOCTL_MIMICHIFI_DISARM  CTL_CODE(0x12, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS) /* 0x0012A004 */

#define MIMICHIFI_MODE_OFF     0  /* pass-through */
#define MIMICHIFI_MODE_LINUX   1  /* TCP IP-ID 0, ICMP IP-ID incrementing */

/* ---- IPv4 / proto constants ---- */
#define MIMICHIFI_ETHERTYPE_IPV4  0x0800
#define MIMICHIFI_PROTO_ICMP      1
#define MIMICHIFI_PROTO_TCP       6

/*
 * MimicHiFi_IpChecksum16 — standard IPv4 header one's-complement checksum over `len`
 * bytes starting at `hdr` (with the checksum field already zeroed). Kernel-safe (no CRT).
 */
__forceinline unsigned short
MimicHiFi_IpChecksum16(const unsigned char *hdr, unsigned int len)
{
    unsigned int sum = 0;
    unsigned int i;
    for (i = 0; i + 1 < len; i += 2) {
        sum += ((unsigned int)hdr[i] << 8) | hdr[i + 1];
    }
    if (i < len) {
        sum += (unsigned int)hdr[i] << 8;   /* odd trailing byte */
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)(~sum & 0xFFFF);
}

/*
 * MimicHiFi_RewriteIpId — the corrector core. `ip` points at the IPv4 header (already
 * past any Ethernet header), `iplen` is the bytes available from `ip`. `mode` is the
 * armed mode; `icmpCounter` is the driver's shared ICMP IP-ID counter (caller owns its
 * lifetime / synchronization). Returns 1 if the packet was modified, else 0.
 *
 * Pure byte arithmetic — no NDIS/WDK types — so it is unit-testable off-target and
 * identical in intent to the Go applyEgress IP-ID block (TCP->0, ICMP->increment).
 */
__forceinline int
MimicHiFi_RewriteIpId(unsigned char *ip, unsigned int iplen,
                      unsigned char mode, unsigned short *icmpCounter)
{
    unsigned int ihl;
    unsigned char proto;
    unsigned short newid;

    if (mode != MIMICHIFI_MODE_LINUX || iplen < 20) {
        return 0;
    }
    if ((ip[0] >> 4) != 4) {           /* IPv4 only (IPv6 has no base-header ID) */
        return 0;
    }
    ihl = (unsigned int)(ip[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > iplen) {
        return 0;
    }
    proto = ip[9];
    if (proto == MIMICHIFI_PROTO_TCP) {
        newid = 0;                     /* nmap TI=Z / CI=Z */
    } else if (proto == MIMICHIFI_PROTO_ICMP) {
        newid = ++(*icmpCounter);      /* nmap II=I (incrementing) */
    } else {
        return 0;                      /* leave UDP/other untouched */
    }

    /* already correct? avoid needless checksum work */
    if (((unsigned short)((ip[4] << 8) | ip[5])) == newid) {
        return 0;
    }
    ip[4] = (unsigned char)(newid >> 8);
    ip[5] = (unsigned char)(newid & 0xFF);

    /* recompute the IPv4 header checksum */
    ip[10] = 0;
    ip[11] = 0;
    {
        unsigned short ck = MimicHiFi_IpChecksum16(ip, ihl);
        ip[10] = (unsigned char)(ck >> 8);
        ip[11] = (unsigned char)(ck & 0xFF);
    }
    return 1;
}
