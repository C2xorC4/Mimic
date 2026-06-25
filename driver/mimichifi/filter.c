/*
 * filter.c — mimic-hifi NDIS Lightweight Filter (modifying).
 *
 * SKELETON for the WDK build loop. The NDIS LWF boilerplate (FilterRegister/Attach/
 * Detach/Pause/Restart/ReturnNetBufferLists, the FILTER_REQUEST plumbing, the dispatch
 * table) is a near-verbatim fork of Microsoft's sample:
 *   Windows-driver-samples/network/ndis/filter  (ndislwf: filter.c, device.c, flt_dbg.c)
 * Copy that sample in, then graft the three mimic-specific pieces marked ★ below. This
 * file documents exactly those grafts so the boilerplate stays a clean sample diff.
 *
 * Build only inside a WDK/EWDK environment (ntddk.h + ndis.h). Will NOT compile without it.
 */
#include <ndis.h>
#include "mimichifi.h"

/* ★1. Global armed state. No per-flow state — per-protocol only (keeps it minimal +
 *     auditable). Set by the control IOCTL (device.c), read on the send hot path. */
typedef struct _MIMICHIFI_GLOBALS {
    volatile LONG   Mode;          /* MIMICHIFI_MODE_OFF | _LINUX (interlocked) */
    USHORT          IcmpIpId;      /* ICMP IP-ID counter (II=I); send path is serialized
                                      per filter module, a plain ++ via the inline is fine */
    NDIS_HANDLE     FilterDriverHandle;
} MIMICHIFI_GLOBALS;
extern MIMICHIFI_GLOBALS g;

/* DriverEntry / FilterRegister / FilterAttach / FilterDetach / FilterPause /
 * FilterRestart / FilterReturnNetBufferLists  →  copy from ndislwf unchanged, except:
 *   - register the control device (device.c: MimicHiFiRegisterDevice) in DriverEntry,
 *   - store FilterDriverHandle in g.FilterDriverHandle.
 */

/*
 * ★2. FilterSendNetBufferLists — the corrector. For each NBL→NB, if armed, map the
 * frame's first data, locate the IPv4 header (past the Ethernet header), and call the
 * verified MimicHiFi_RewriteIpId(). Then pass the (possibly mutated) NBLs down with
 * NdisFSendNetBufferLists. This is the ONLY hot-path change vs the sample's pass-through.
 *
 * Notes for the build loop:
 *   - Ethernet header is 14 bytes (DIX); handle VLAN-tagged (0x8100 → +4) by checking
 *     the ethertype at offset 12; only act on ethertype 0x0800 (IPv4).
 *   - Use NdisGetDataBuffer() with a small stack scratch (>= 14 + 60 max IP header) to
 *     get a contiguous, WRITABLE pointer; if the buffer was copied to scratch, write the
 *     rewrite back with the appropriate MDL update, or only rewrite when NdisGetDataBuffer
 *     returns the in-place pointer (storage==NULL path). Simplest correct approach: ensure
 *     the leading bytes are in the first MDL (they always are for our small headers) and
 *     edit in place.
 *   - Mode read: LONG mode = InterlockedCompareExchange(&g.Mode, 0, 0);
 *   - Only outbound (this callback is the send path) and only when (mode == _LINUX).
 */
VOID
MimicHiFiSendNetBufferLists(
    NDIS_HANDLE FilterModuleContext, PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber, ULONG SendFlags)
{
    /* PSEUDOCODE (fill against ndislwf send path):
     *
     * LONG mode = InterlockedCompareExchange(&g.Mode, 0, 0);
     * if (mode == MIMICHIFI_MODE_LINUX) {
     *   for (nbl = NetBufferLists; nbl; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl))
     *     for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb; nb = NET_BUFFER_NEXT_NB(nb)) {
     *       UCHAR scratch[14 + 60];
     *       UCHAR *eth = NdisGetDataBuffer(nb, 14 + 60, scratch, 1, 0);
     *       if (!eth) continue;
     *       USHORT et = (eth[12] << 8) | eth[13]; ULONG l2 = 14;
     *       if (et == 0x8100) { et = (eth[16] << 8) | eth[17]; l2 = 18; }   // VLAN
     *       if (et != MIMICHIFI_ETHERTYPE_IPV4) continue;
     *       UCHAR *ip = eth + l2;  ULONG iplen = NET_BUFFER_DATA_LENGTH(nb) - l2;
     *       // ensure 'ip' is the in-place writable pointer (eth==scratch ? must write-back)
     *       MimicHiFi_RewriteIpId(ip, iplen, (UCHAR)mode, &g.IcmpIpId);
     *     }
     * }
     * NdisFSendNetBufferLists(((PMS_FILTER)FilterModuleContext)->FilterHandle,
     *                         NetBufferLists, PortNumber, SendFlags);
     */
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(NetBufferLists);
    UNREFERENCED_PARAMETER(PortNumber);
    UNREFERENCED_PARAMETER(SendFlags);
}

/* ★3. Control IOCTL → device.c:
 *   IOCTL_MIMICHIFI_ARM    : read 1 mode byte, InterlockedExchange(&g.Mode, mode);
 *   IOCTL_MIMICHIFI_DISARM : InterlockedExchange(&g.Mode, MIMICHIFI_MODE_OFF);
 *   IRP_MJ_CLOSE/CLEANUP   : InterlockedExchange(&g.Mode, MIMICHIFI_MODE_OFF);  // fail-safe
 */
