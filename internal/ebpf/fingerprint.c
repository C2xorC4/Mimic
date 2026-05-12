//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// IP ID behavior
#define IPID_INCREMENTAL 0
#define IPID_RANDOM      1
#define IPID_ZERO        2

// TCP option kinds
#define TCPOPT_EOL       0
#define TCPOPT_NOP       1
#define TCPOPT_MSS       2
#define TCPOPT_WSCALE    3
#define TCPOPT_SACK_PERM 4
#define TCPOPT_SACK      5
#define TCPOPT_TIMESTAMP 8

// TCP option lengths
#define TCPOLEN_MSS       4
#define TCPOLEN_WSCALE    3
#define TCPOLEN_SACK_PERM 2
#define TCPOLEN_TIMESTAMP 10

// Max TCP options we handle
#define MAX_TCP_OPTIONS 10
#define MAX_TCP_OPT_LEN 40


// OS fingerprint profile structure - must match Go struct exactly
struct os_profile {
    // IP layer
    __u8  ttl;
    __u8  df_bit;
    __u8  ip_id_behavior;
    __u8  _pad1;

    // TCP layer
    __u16 window_size;
    __u8  window_scale;
    __u8  tcp_timestamps;
    __u16 mss;
    __u8  sack_permitted;
    __u8  ecn_support;

    // TCP options order (max 10 options, 0 = end)
    __u8  tcp_options_order[10];
    __u8  tcp_options_count;
    __u8  _pad2;

    // RST behavior
    __u8  ack_in_rst;
    __u8  _pad3;
    __u16 window_in_rst;

    // ICMP
    __u8  icmp_quote_size;
    __u8  icmp_df_in_quote;
    __u8  icmp_ttl_in_quote;
    __u8  icmp_rate_limit;

    // UDP
    __u8  udp_closed_port_response;
    __u8  _pad4[3];
};

// Global state for IP ID generation
struct ip_id_state {
    __u16 counter;
    __u16 _pad;       // Explicit padding for alignment
    __u32 random_seed;
};

// BPF maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct os_profile);
} profile_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ip_id_state);
} ip_id_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} enabled_map SEC(".maps");

SEC("tc")
int fingerprint_egress(struct __sk_buff *skb) {
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&enabled_map, &key);
    if (!enabled || *enabled == 0) {
        return TC_ACT_OK;
    }

    struct os_profile *profile = bpf_map_lookup_elem(&profile_map, &key);
    if (!profile) {
        return TC_ACT_OK;
    }

    // Ensure packet data is in linear memory and accessible
    if (bpf_skb_pull_data(skb, 0) < 0) {
        return TC_ACT_OK;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Verify we have enough data for Ethernet + IP header (14 + 20 = 34 bytes)
    if (data + 34 > data_end) {
        return TC_ACT_OK;
    }

    // Check for IPv4 (EtherType at offset 12-13)
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    // Get IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Read all fields BEFORE any store operations (stores invalidate pointers)
    __u8 old_ttl = ip->ttl;
    __u8 proto = ip->protocol;
    __be16 old_frag_off = ip->frag_off;
    __be16 old_id = ip->id;

    // === TTL Modification ===
    if (old_ttl != profile->ttl && profile->ttl > 0) {
        __u8 new_ttl = profile->ttl;

        if (bpf_skb_store_bytes(skb, 14 + 8, &new_ttl, 1, 0) < 0) {
            return TC_ACT_OK;
        }

        // Checksum update: on little-endian, [TTL][Proto] loads as (Proto<<8)|TTL
        __u16 old_val = ((__u16)proto << 8) | old_ttl;
        __u16 new_val = ((__u16)proto << 8) | new_ttl;
        bpf_l3_csum_replace(skb, 14 + 10, old_val, new_val, 2);
    }

    // === DF Bit Modification ===
    // DF is bit 14 of frag_off field (big-endian), which is 0x4000 in network order
    __u8 current_df = (bpf_ntohs(old_frag_off) & 0x4000) ? 1 : 0;
    if (current_df != profile->df_bit) {
        __be16 new_frag_off;
        if (profile->df_bit) {
            new_frag_off = old_frag_off | bpf_htons(0x4000);  // Set DF
        } else {
            new_frag_off = old_frag_off & bpf_htons(~0x4000); // Clear DF
        }

        if (bpf_skb_store_bytes(skb, 14 + 6, &new_frag_off, 2, 0) < 0) {
            return TC_ACT_OK;
        }

        // Checksum update for frag_off change
        bpf_l3_csum_replace(skb, 14 + 10, old_frag_off, new_frag_off, 2);
    }

    // === IP ID Modification ===
    // Always override using our shared counter so TCP and ICMP share the same
    // sequence (SS=S in nmap). Linux uses per-flow counters that diverge.
    {
        struct ip_id_state *id_state = bpf_map_lookup_elem(&ip_id_map, &key);
        if (id_state) {
            __be16 new_id;

            if (profile->ip_id_behavior == IPID_ZERO) {
                new_id = 0;
            } else if (profile->ip_id_behavior == IPID_RANDOM) {
                __u32 seed = id_state->random_seed;
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                id_state->random_seed = seed;
                new_id = bpf_htons((__u16)seed);
            } else {
                // Incremental — shared counter across all protocols
                __u16 next = id_state->counter + 1;
                id_state->counter = next;
                new_id = bpf_htons(next);
            }

            if (old_id != new_id) {
                if (bpf_skb_store_bytes(skb, 14 + 4, &new_id, 2, 0) < 0) {
                    return TC_ACT_OK;
                }
                bpf_l3_csum_replace(skb, 14 + 10, old_id, new_id, 2);
            }
        }
    }

    // === TCP Modifications ===
    if (proto == IPPROTO_TCP) {
        // IP header length (IHL is in low 4 bits of first byte, in 4-byte units)
        __u8 ihl_byte;
        if (bpf_skb_load_bytes(skb, 14, &ihl_byte, 1) < 0) {
            return TC_ACT_OK;
        }
        __u8 ip_hdr_len = (ihl_byte & 0x0F) * 4;

        // TCP header starts after Ethernet (14) + IP header
        __u32 tcp_offset = 14 + ip_hdr_len;

        // Read TCP data offset (high 4 bits of byte 12, in 4-byte units)
        __u8 tcp_doff_byte;
        if (bpf_skb_load_bytes(skb, tcp_offset + 12, &tcp_doff_byte, 1) < 0) {
            return TC_ACT_OK;
        }
        __u8 tcp_hdr_len = (tcp_doff_byte >> 4) * 4;

        // Ensure we can read full TCP header
        if (tcp_offset + tcp_hdr_len > skb->len) {
            return TC_ACT_OK;
        }

        // === TCP Window Size ===
        if (profile->window_size > 0) {
            __be16 old_window;
            if (bpf_skb_load_bytes(skb, tcp_offset + 14, &old_window, 2) < 0) {
                return TC_ACT_OK;
            }

            __be16 new_window = bpf_htons(profile->window_size);

            if (old_window != new_window) {
                if (bpf_skb_store_bytes(skb, tcp_offset + 14, &new_window, 2, 0) < 0) {
                    return TC_ACT_OK;
                }
                bpf_l4_csum_replace(skb, tcp_offset + 16, old_window, new_window, 2);
            }
        }

        // === TCP Options Reordering ===
        // Only rewrite options on SYN or SYN-ACK packets (SYN bit set) to prevent
        // corrupting TCP options on data packets that happen to have the same length.
        __u8 tcp_flags_early;
        if (bpf_skb_load_bytes(skb, tcp_offset + 13, &tcp_flags_early, 1) < 0) {
            return TC_ACT_OK;
        }
        __u8 is_syn = tcp_flags_early & 0x02;  // SYN bit

        __u8 opt_len = tcp_hdr_len - 20;
        if (opt_len == 20 && profile->tcp_options_count > 0 && is_syn) {
            __u32 opt_start = tcp_offset + 20;

            // Read original 20 bytes of options
            __u8 old_opts[20];
            if (bpf_skb_load_bytes(skb, opt_start, old_opts, 20) < 0) {
                return TC_ACT_OK;
            }

            // Extract MSS value from original options
            __u16 mss_val = profile->mss;
            if (old_opts[0] == TCPOPT_MSS && old_opts[1] == 4) {
                mss_val = ((__u16)old_opts[2] << 8) | old_opts[3];
            }

            // Detect negotiated options — only reflect back what the peer offered.
            // (e.g. nmap probe 3 omits SACK, so Windows responds without it too.)
            __u8 had_sack = 0;
            if (old_opts[4] == TCPOPT_SACK_PERM || old_opts[6] == TCPOPT_SACK_PERM ||
                old_opts[8] == TCPOPT_SACK_PERM || old_opts[10] == TCPOPT_SACK_PERM ||
                old_opts[12] == TCPOPT_SACK_PERM || old_opts[16] == TCPOPT_SACK_PERM) {
                had_sack = 1;
            }
            __u8 use_sack = profile->sack_permitted && had_sack;

            // Initialize with NOPs
            __u8 new_opts[20] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};

            // Select template based on profile characteristics
            __u8 opt1 = profile->tcp_options_order[1];

            // Template 1: MSS, NOP, NOP, SACK (Windows XP style) - no window scale
            // Template 2: MSS, NOP, WS, NOP, NOP, SACK (Windows 7/10/11 style)
            // Template 3: MSS, SACK, TS, NOP, WS (Linux style)
            // Template 4: MSS, NOP, WS, NOP, NOP, TS, SACK (macOS style)

            if (profile->window_scale == 0 && profile->tcp_timestamps == 0) {
                // Windows XP style: MSS(4) + NOP + NOP + SACK(2)
                new_opts[0] = TCPOPT_MSS;
                new_opts[1] = 4;
                new_opts[2] = (mss_val >> 8) & 0xFF;
                new_opts[3] = mss_val & 0xFF;
                new_opts[4] = TCPOPT_NOP;
                new_opts[5] = TCPOPT_NOP;
                if (use_sack) {
                    new_opts[6] = TCPOPT_SACK_PERM;
                    new_opts[7] = 2;
                }
            } else if (profile->window_scale > 0 && profile->tcp_timestamps == 0) {
                // Windows 7/10/11 style: MSS(4) + NOP + WS(3) + NOP + NOP + SACK(2)
                new_opts[0] = TCPOPT_MSS;
                new_opts[1] = 4;
                new_opts[2] = (mss_val >> 8) & 0xFF;
                new_opts[3] = mss_val & 0xFF;
                new_opts[4] = TCPOPT_NOP;
                new_opts[5] = TCPOPT_WSCALE;
                new_opts[6] = 3;
                new_opts[7] = profile->window_scale;
                new_opts[8] = TCPOPT_NOP;
                new_opts[9] = TCPOPT_NOP;
                if (use_sack) {
                    new_opts[10] = TCPOPT_SACK_PERM;
                    new_opts[11] = 2;
                }
            } else if (profile->window_scale > 0 && profile->tcp_timestamps) {
                // Windows 10/11: MSS(4) + NOP(1) + WS(3) + SACK(2) + TS(10) = 20 bytes
                // The kernel already set TSecr correctly in the original packet (it echoes
                // the peer's TSval). We extract it before overwriting, then write a
                // Windows-ordered template with a Windows-like TSval (1 kHz counter).
                __u32 orig_tsecr = 0;
                // Check the three common TS positions in Linux SYN-ACK options:
                //   offset 8: MSS(0-3) NOP(4) WS(5-7) TS(8-17) SACK(18-19)
                //   offset 6: MSS(0-3) SACK(4-5) TS(6-15) NOP(16) WS(17-19)
                //   offset 4: MSS(0-3) TS(4-13) ...
                if (old_opts[8] == TCPOPT_TIMESTAMP && old_opts[9] == TCPOLEN_TIMESTAMP) {
                    orig_tsecr = ((__u32)old_opts[14]<<24)|((__u32)old_opts[15]<<16)|((__u32)old_opts[16]<<8)|old_opts[17];
                } else if (old_opts[6] == TCPOPT_TIMESTAMP && old_opts[7] == TCPOLEN_TIMESTAMP) {
                    orig_tsecr = ((__u32)old_opts[12]<<24)|((__u32)old_opts[13]<<16)|((__u32)old_opts[14]<<8)|old_opts[15];
                } else if (old_opts[4] == TCPOPT_TIMESTAMP && old_opts[5] == TCPOLEN_TIMESTAMP) {
                    orig_tsecr = ((__u32)old_opts[10]<<24)|((__u32)old_opts[11]<<16)|((__u32)old_opts[12]<<8)|old_opts[13];
                }
                __u32 win_tsval = (__u32)(bpf_ktime_get_ns() / 1000000ULL);

                new_opts[0] = TCPOPT_MSS;
                new_opts[1] = 4;
                new_opts[2] = (mss_val >> 8) & 0xFF;
                new_opts[3] = mss_val & 0xFF;
                new_opts[4] = TCPOPT_NOP;
                new_opts[5] = TCPOPT_WSCALE;
                new_opts[6] = 3;
                new_opts[7] = profile->window_scale;
                if (use_sack) {
                    new_opts[8] = TCPOPT_SACK_PERM;
                    new_opts[9] = 2;
                }
                new_opts[10] = TCPOPT_TIMESTAMP;
                new_opts[11] = TCPOLEN_TIMESTAMP;
                new_opts[12] = (win_tsval >> 24) & 0xFF;
                new_opts[13] = (win_tsval >> 16) & 0xFF;
                new_opts[14] = (win_tsval >> 8) & 0xFF;
                new_opts[15] = win_tsval & 0xFF;
                new_opts[16] = (orig_tsecr >> 24) & 0xFF;
                new_opts[17] = (orig_tsecr >> 16) & 0xFF;
                new_opts[18] = (orig_tsecr >> 8) & 0xFF;
                new_opts[19] = orig_tsecr & 0xFF;
            } else if (profile->tcp_timestamps && opt1 == TCPOPT_SACK_PERM) {
                // Linux style: MSS(4) + SACK(2) + TS(10) + NOP + WS(3)
                new_opts[0] = TCPOPT_MSS;
                new_opts[1] = 4;
                new_opts[2] = (mss_val >> 8) & 0xFF;
                new_opts[3] = mss_val & 0xFF;
                if (use_sack) {
                    new_opts[4] = TCPOPT_SACK_PERM;
                    new_opts[5] = 2;
                }
                // Skip timestamp (leave as NOPs) - bytes 6-15
                new_opts[16] = TCPOPT_NOP;
                if (profile->window_scale > 0) {
                    new_opts[17] = TCPOPT_WSCALE;
                    new_opts[18] = 3;
                    new_opts[19] = profile->window_scale;
                }
            } else {
                // Default/macOS style: MSS(4) + NOP + WS(3) + SACK(2) + NOPs
                new_opts[0] = TCPOPT_MSS;
                new_opts[1] = 4;
                new_opts[2] = (mss_val >> 8) & 0xFF;
                new_opts[3] = mss_val & 0xFF;
                new_opts[4] = TCPOPT_NOP;
                if (profile->window_scale > 0) {
                    new_opts[5] = TCPOPT_WSCALE;
                    new_opts[6] = 3;
                    new_opts[7] = profile->window_scale;
                }
                if (use_sack) {
                    new_opts[8] = TCPOPT_SACK_PERM;
                    new_opts[9] = 2;
                }
            }

            // Write new options
            if (bpf_skb_store_bytes(skb, opt_start, new_opts, 20, 0) < 0) {
                return TC_ACT_OK;
            }

            // Update TCP checksum for all 10 words
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[0] << 8) | old_opts[1],
                ((__u16)new_opts[0] << 8) | new_opts[1], 2);
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[2] << 8) | old_opts[3],
                ((__u16)new_opts[2] << 8) | new_opts[3], 2);
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[4] << 8) | old_opts[5],
                ((__u16)new_opts[4] << 8) | new_opts[5], 2);
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[6] << 8) | old_opts[7],
                ((__u16)new_opts[6] << 8) | new_opts[7], 2);
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[8] << 8) | old_opts[9],
                ((__u16)new_opts[8] << 8) | new_opts[9], 2);
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[10] << 8) | old_opts[11],
                ((__u16)new_opts[10] << 8) | new_opts[11], 2);
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[12] << 8) | old_opts[13],
                ((__u16)new_opts[12] << 8) | new_opts[13], 2);
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[14] << 8) | old_opts[15],
                ((__u16)new_opts[14] << 8) | new_opts[15], 2);
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[16] << 8) | old_opts[17],
                ((__u16)new_opts[16] << 8) | new_opts[17], 2);
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                ((__u16)old_opts[18] << 8) | old_opts[19],
                ((__u16)new_opts[18] << 8) | new_opts[19], 2);
        }

        // === 12-byte options template (ECN probe, no timestamps negotiated) ===
        // nmap's ECN probe sends SYN with MSS+NOP+NOP+SACK+NOP+WS(7) = 12 bytes.
        // Rewrite to Windows order: MSS+NOP+WS(profile)+NOP+NOP+SACK = 12 bytes.
        if (opt_len == 12 && profile->window_scale > 0 && profile->tcp_options_count > 0 && is_syn) {
            __u32 opt12_start = tcp_offset + 20;
            __u8 old12[12];
            if (bpf_skb_load_bytes(skb, opt12_start, old12, 12) >= 0) {
                __u16 mss12 = profile->mss;
                if (old12[0] == TCPOPT_MSS && old12[1] == 4) {
                    mss12 = ((__u16)old12[2] << 8) | old12[3];
                }
                __u8 had_sack12 = (old12[2] == TCPOPT_SACK_PERM || old12[4] == TCPOPT_SACK_PERM ||
                                   old12[6] == TCPOPT_SACK_PERM || old12[8] == TCPOPT_SACK_PERM ||
                                   old12[10] == TCPOPT_SACK_PERM) ? 1 : 0;
                __u8 new12[12] = {1,1,1,1,1,1,1,1,1,1,1,1};
                new12[0] = TCPOPT_MSS;
                new12[1] = 4;
                new12[2] = (mss12 >> 8) & 0xFF;
                new12[3] = mss12 & 0xFF;
                new12[4] = TCPOPT_NOP;
                new12[5] = TCPOPT_WSCALE;
                new12[6] = 3;
                new12[7] = profile->window_scale;
                new12[8] = TCPOPT_NOP;
                new12[9] = TCPOPT_NOP;
                if (profile->sack_permitted && had_sack12) {
                    new12[10] = TCPOPT_SACK_PERM;
                    new12[11] = 2;
                }
                if (bpf_skb_store_bytes(skb, opt12_start, new12, 12, 0) >= 0) {
                    bpf_l4_csum_replace(skb, tcp_offset + 16,
                        ((__u16)old12[0]<<8)|old12[1], ((__u16)new12[0]<<8)|new12[1], 2);
                    bpf_l4_csum_replace(skb, tcp_offset + 16,
                        ((__u16)old12[2]<<8)|old12[3], ((__u16)new12[2]<<8)|new12[3], 2);
                    bpf_l4_csum_replace(skb, tcp_offset + 16,
                        ((__u16)old12[4]<<8)|old12[5], ((__u16)new12[4]<<8)|new12[5], 2);
                    bpf_l4_csum_replace(skb, tcp_offset + 16,
                        ((__u16)old12[6]<<8)|old12[7], ((__u16)new12[6]<<8)|new12[7], 2);
                    bpf_l4_csum_replace(skb, tcp_offset + 16,
                        ((__u16)old12[8]<<8)|old12[9], ((__u16)new12[8]<<8)|new12[9], 2);
                    bpf_l4_csum_replace(skb, tcp_offset + 16,
                        ((__u16)old12[10]<<8)|old12[11], ((__u16)new12[10]<<8)|new12[11], 2);
                }
            }
        }

        // === TSval Override for 16-byte options (no WS negotiated) ===
        // nmap's O6 probe sends SYN without WS, kernel responds with MSS+SACK+TS=16 bytes.
        // The 20-byte template above skips this packet, so the kernel's randomized TSval
        // leaks through and breaks nmap's TS rate calculation. Override TSval here.
        // Also set window to 0xFFDC (65500): Windows 10/11 uses this value for W6 (probe
        // without WS), while probes 1-5 (WS negotiated) get W=FFFF.
        if (opt_len == 16 && profile->tcp_timestamps && is_syn) {
            if (profile->window_size == 0xFFFF) {
                __be16 w6_new = bpf_htons((__u16)0xFFDC);
                __be16 w6_cur;
                if (bpf_skb_load_bytes(skb, tcp_offset + 14, &w6_cur, 2) >= 0) {
                    if (w6_cur != w6_new) {
                        if (bpf_skb_store_bytes(skb, tcp_offset + 14, &w6_new, 2, 0) >= 0) {
                            bpf_l4_csum_replace(skb, tcp_offset + 16, w6_cur, w6_new, 2);
                        }
                    }
                }
            }
            __u32 opt16_start = tcp_offset + 20;
            __u8 old16[8];
            if (bpf_skb_load_bytes(skb, opt16_start + 6, old16, 8) >= 0) {
                if (old16[0] == TCPOPT_TIMESTAMP && old16[1] == TCPOLEN_TIMESTAMP) {
                    // TS at options offset 6: MSS(0-3) + SACK(4-5) + TS(6-15)
                    // TSval is at options offset 8..11 → packet offset opt16_start+8
                    __u32 win_tsval16 = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
                    __u8 new_tsval16[4] = {
                        (win_tsval16 >> 24) & 0xFF,
                        (win_tsval16 >> 16) & 0xFF,
                        (win_tsval16 >> 8) & 0xFF,
                        win_tsval16 & 0xFF
                    };
                    if (bpf_skb_store_bytes(skb, opt16_start + 8, new_tsval16, 4, 0) >= 0) {
                        bpf_l4_csum_replace(skb, tcp_offset + 16,
                            ((__u16)old16[2] << 8) | old16[3],
                            ((__u16)new_tsval16[0] << 8) | new_tsval16[1], 2);
                        bpf_l4_csum_replace(skb, tcp_offset + 16,
                            ((__u16)old16[4] << 8) | old16[5],
                            ((__u16)new_tsval16[2] << 8) | new_tsval16[3], 2);
                    }
                }
            }
        }

        // === RST Packet Behavior ===
        // Enforce window_in_rst=0 on outgoing RST packets.
        // Note: do NOT strip the ACK flag from RSTs — Linux already omits ACK for
        // stray-ACK probes (T4/T6) and includes ACK for SYN-to-closed (T5/T7).
        // Stripping ACK would break T5/T7 which nmap expects as F=AR.
        __u8 tcp_flags;
        if (bpf_skb_load_bytes(skb, tcp_offset + 13, &tcp_flags, 1) < 0) {
            return TC_ACT_OK;
        }
        if (tcp_flags & 0x04) {  // RST flag set
            if (profile->window_in_rst == 0) {
                __be16 rst_window;
                if (bpf_skb_load_bytes(skb, tcp_offset + 14, &rst_window, 2) < 0) {
                    return TC_ACT_OK;
                }
                if (rst_window != 0) {
                    __be16 zero_window = 0;
                    if (bpf_skb_store_bytes(skb, tcp_offset + 14, &zero_window, 2, 0) < 0) {
                        return TC_ACT_OK;
                    }
                    bpf_l4_csum_replace(skb, tcp_offset + 16, rst_window, zero_window, 2);
                }
            }
        }

        // === ECN SYN-ACK: clear ECE flag for Windows behavior ===
        // Linux sets ECE in SYN-ACK when responding to an ECN-capable SYN (nmap CC=Y).
        // All Windows versions respond without ECE in SYN-ACK (CC=N). Clear it always —
        // ecn_support in the profile means the OS initiates ECN connections, not that it
        // echoes ECE in SYN-ACK back to probers.
        // Only applies to SYN-ACK (SYN=1 + ACK=1, flags & 0x12 == 0x12).
        if ((tcp_flags & 0x12) == 0x12 && (tcp_flags & 0x40)) {
            __u8 no_ece = tcp_flags & ~(__u8)0x40;  // clear ECE (bit 6)
            if (bpf_skb_store_bytes(skb, tcp_offset + 13, &no_ece, 1, 0) >= 0) {
                bpf_l4_csum_replace(skb, tcp_offset + 16,
                    (__u16)tcp_flags << 8, (__u16)no_ece << 8, 2);
            }
        }
    }

    // === ICMP Behavior ===
    // Windows does not set DF bit in ICMP responses (nmap: IE DFI=N, U1 DF=N).
    // Our DF section above forces DF=1 on all packets; undo it for ICMP.
    // Linux also echoes the ICMP code from echo requests; Windows sends code=0 (CD=Z).
    if (proto == IPPROTO_ICMP) {
        // Clear DF bit in ICMP packets
        __be16 icmp_frag_off;
        if (bpf_skb_load_bytes(skb, 14 + 6, &icmp_frag_off, 2) >= 0) {
            __be16 icmp_no_df = icmp_frag_off & bpf_htons((__u16)(~0x4000U));
            if (icmp_no_df != icmp_frag_off) {
                if (bpf_skb_store_bytes(skb, 14 + 6, &icmp_no_df, 2, 0) >= 0) {
                    bpf_l3_csum_replace(skb, 14 + 10, icmp_frag_off, icmp_no_df, 2);
                }
            }
        }
        // For ICMP echo replies (type=0): force code=0 (Windows: CD=Z)
        // Linux echoes the probe's code back which gives CD=S.
        __u8 icmp_ihl;
        if (bpf_skb_load_bytes(skb, 14, &icmp_ihl, 1) >= 0) {
            __u32 icmp_start = 14 + ((__u32)(icmp_ihl & 0x0F) * 4);
            __u8 icmp_hdr2[2];
            if (bpf_skb_load_bytes(skb, icmp_start, icmp_hdr2, 2) >= 0) {
                if (icmp_hdr2[0] == 0 && icmp_hdr2[1] != 0) {
                    __u8 zero_code = 0;
                    if (bpf_skb_store_bytes(skb, icmp_start + 1, &zero_code, 1, 0) >= 0) {
                        bpf_l4_csum_replace(skb, icmp_start + 2,
                            ((__u16)icmp_hdr2[0] << 8) | icmp_hdr2[1],
                            (__u16)icmp_hdr2[0] << 8, 2);
                    }
                }
            }
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
