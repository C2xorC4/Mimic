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
 * armed mode. `icmpId` is a caller-supplied monotonic IP-ID for ICMP (nmap II=I); the
 * caller assigns it atomically (only for ICMP) so concurrent sends don't tear a shared
 * counter — it is ignored for TCP (which always gets 0). `recomputeChecksum` selects
 * whether THIS code computes the IPv4 header checksum:
 *
 *   recomputeChecksum != 0  → in-band checksum: we zero + recompute it (correct for
 *                             non-offloaded sends and WinDivert-reinjected packets).
 *   recomputeChecksum == 0  → the NIC will compute the IP header checksum (TX
 *                             IP-checksum offload is requested on this NBL). We change
 *                             ONLY the IP-ID and leave the field as the stack's 0
 *                             placeholder; the miniport fills it over the final header.
 *                             Recomputing here while the offload request stays set makes
 *                             the NIC re-checksum ON TOP of our value (one's-complement
 *                             double-add → 0xffff) and the receiver drops every packet.
 *                             (Root-caused on a virtio NIC, 2026-06-26: armed driver +
 *                             IP-checksum offload broke ALL outbound TCP; TI=Z was on the
 *                             wire but `bad cksum ffff`.)
 *
 * Returns 1 if the packet was modified, else 0.
 *
 * Pure byte arithmetic — no NDIS/WDK types — so it is unit-testable off-target and
 * identical in intent to the Go applyEgress IP-ID block (TCP->0, ICMP->increment).
 */
__forceinline int
MimicHiFi_RewriteIpId(unsigned char *ip, unsigned int iplen,
                      unsigned char mode, unsigned short icmpId,
                      int recomputeChecksum)
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
        newid = icmpId;                /* nmap II=I (caller supplies a monotonic id) */
    } else {
        return 0;                      /* leave UDP/other untouched */
    }

    /* already correct? avoid needless checksum work */
    if (((unsigned short)((ip[4] << 8) | ip[5])) == newid) {
        return 0;
    }
    ip[4] = (unsigned char)(newid >> 8);
    ip[5] = (unsigned char)(newid & 0xFF);

    if (recomputeChecksum) {
        /* in-band checksum: zero + recompute the IPv4 header checksum */
        ip[10] = 0;
        ip[11] = 0;
        {
            unsigned short ck = MimicHiFi_IpChecksum16(ip, ihl);
            ip[10] = (unsigned char)(ck >> 8);
            ip[11] = (unsigned char)(ck & 0xFF);
        }
    }
    /* else: NIC computes the IP checksum (offload) — leave the field untouched. */
    return 1;
}
