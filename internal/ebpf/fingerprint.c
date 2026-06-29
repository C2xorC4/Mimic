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
    __u8  ecn_echo;   // 1 = echo ECE in SYN-ACK (Linux/macOS CC=Y) + keep native ECN opts; 0 = Windows (clear ECE, force Win ECN opts)

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
    __u8  win_quirks;   // 1 = Windows profile: apply Windows-only stack quirks (shared IP-ID/SS=S, A=O RST, ICMP CD=Z). 0 (Linux/macOS) leaves the host's native behavior.

    // RST behavior
    __u8  ack_in_rst;
    __u8  ecn_cc;       // 1 = reflect ECE on the ECN-probe SYN-ACK → nmap CC=Y (Linux/macOS, and Windows Server via explicit_congestion: echo); 0 = clear ECE → CC=N (Windows workstation). Repurposes the former _pad3 byte.
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

// Key: {remote_ip, remote_port, local_port} of an incoming TCP probe.
// Used to set ack_seq in bare RST replies (T4/T6 A=O Windows behavior).
struct seq_cache_key {
    __u32 saddr;
    __u16 sport;
    __u16 dport;
};

struct seq_cache_val {
    __u32 seq;     // probe SEQ in host byte order
    __u32 ack_num; // probe ACK in host byte order — used as RST's ack_seq for A=O
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct seq_cache_key);
    __type(value, struct seq_cache_val);
} seq_cache SEC(".maps");

// macOS DFI=S: ingress captures ICMP echo request DF bit by source IP;
// egress applies it to the matching echo reply. LRU size 64 (nmap sends 2 probes).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);   // source IP of the ICMP echo probe
    __type(value, __u8);  // probe's DF bit (0 or 1)
} icmp_df_map SEC(".maps");

// macOS T7 A=S: track FIN+PSH+URG probes so egress RST+ACK uses ACK=seq (not seq+1).
// macOS does not consume the FIN's sequence number for closed-port RST+ACK (unlike Linux).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, struct seq_cache_key);  // {probe_src_ip, probe_src_port, our_dst_port}
    __type(value, __u32);               // FIN probe seq in host byte order
} fin_probe_map SEC(".maps");

// shrink_tcp_options physically shortens a SYN-ACK's TCP options from old_optlen to
// new_optlen bytes (both multiples of 4). Used for TS-off Windows personas on a Linux
// host: the kernel's SYN-ACK carries a timestamp option the persona must not advertise,
// so the option templates overwrite the TS bytes with NOPs and this removes the pad so
// nmap reads the real option length (e.g. M5B4NW8NNS, not M5B4NW8NNS+NNNNNNNN). The caller
// must have already (a) written the real option bytes and (b) subtracted the trailing
// NOP-pad words from the L4 checksum. This fixes the TCP data offset, the TCP
// pseudo-header length, the IP total length, and truncates the packet. change_tail
// invalidates direct data/data_end pointers — the egress path below uses only
// skb-relative helpers after this, so that is safe here.
static __always_inline void
shrink_tcp_options(struct __sk_buff *skb, __u32 tcp_offset, __u32 old_optlen, __u32 new_optlen) {
    __u32 trim = old_optlen - new_optlen;
    // TCP data offset (high nibble of the byte at tcp+12): (20 + new_optlen)/4 words.
    __u8 doff_old = 0;
    if (bpf_skb_load_bytes(skb, tcp_offset + 12, &doff_old, 1) >= 0) {
        __u8 doff_new = (__u8)((((20 + new_optlen) / 4) << 4) | (doff_old & 0x0F));
        if (bpf_skb_store_bytes(skb, tcp_offset + 12, &doff_new, 1, 0) >= 0) {
            bpf_l4_csum_replace(skb, tcp_offset + 16,
                (__u16)doff_old << 8, (__u16)doff_new << 8, 2);
        }
    }
    // TCP checksum's pseudo-header carries the segment length; it shrank by trim.
    bpf_l4_csum_replace(skb, tcp_offset + 16,
        (__u16)(20 + old_optlen), (__u16)(20 + new_optlen), 2);
    // IP total length (at 14+2) -= trim; fix the IP header checksum (at 14+10).
    __be16 iptot_old = 0;
    if (bpf_skb_load_bytes(skb, 16, &iptot_old, 2) >= 0) {
        __be16 iptot_new = bpf_htons((__u16)(bpf_ntohs(iptot_old) - (__u16)trim));
        if (bpf_skb_store_bytes(skb, 16, &iptot_new, 2, 0) >= 0) {
            bpf_l3_csum_replace(skb, 24, iptot_old, iptot_new, 2);
        }
    }
    // Physically remove the trailing pad. MUST be last — invalidates packet pointers.
    bpf_skb_change_tail(skb, skb->len - trim, 0);
}

// expand_tcp_options physically extends a SYN-ACK's TCP options from old_optlen to
// new_optlen bytes (both multiples of 4). Used for macOS personas on a Linux host:
// macOS SYN-ACK carries 24 bytes of options; the Linux kernel generates 20.
// The caller must: (a) have already written and checksummed the first old_optlen bytes,
// (b) write the added bytes at tcp_offset+20+old_optlen and update their checksum after.
// bpf_skb_change_tail invalidates direct data/data_end — use only skb-relative helpers after.
static __always_inline int
expand_tcp_options(struct __sk_buff *skb, __u32 tcp_offset, __u32 old_optlen, __u32 new_optlen) {
    __u32 added = new_optlen - old_optlen;
    __u8 doff_old = 0;
    if (bpf_skb_load_bytes(skb, tcp_offset + 12, &doff_old, 1) < 0) return -1;
    __u8 doff_new = (__u8)((((20 + new_optlen) / 4) << 4) | (doff_old & 0x0F));
    __be16 iptot_old = 0;
    if (bpf_skb_load_bytes(skb, 16, &iptot_old, 2) < 0) return -1;
    __be16 iptot_new = bpf_htons((__u16)(bpf_ntohs(iptot_old) + (__u16)added));
    if (bpf_skb_change_tail(skb, skb->len + added, 0) < 0) return -1;
    if (bpf_skb_store_bytes(skb, tcp_offset + 12, &doff_new, 1, 0) < 0) return -1;
    bpf_l4_csum_replace(skb, tcp_offset + 16,
        (__u16)doff_old << 8, (__u16)doff_new << 8, 2);
    bpf_l4_csum_replace(skb, tcp_offset + 16,
        (__u16)(20 + old_optlen), (__u16)(20 + new_optlen), 2);
    if (bpf_skb_store_bytes(skb, 16, &iptot_new, 2, 0) < 0) return -1;
    bpf_l3_csum_replace(skb, 24, iptot_old, iptot_new, 2);
    return 0;
}

SEC("tc/ingress")
int fingerprint_ingress(struct __sk_buff *skb) {
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&enabled_map, &key);
    if (!enabled || *enabled == 0) {
        return TC_ACT_OK;
    }

    if (bpf_skb_pull_data(skb, 0) < 0) {
        return TC_ACT_OK;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + 34 > data_end) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    __u8 ihl_byte;
    if (bpf_skb_load_bytes(skb, 14, &ihl_byte, 1) < 0) {
        return TC_ACT_OK;
    }
    if ((ihl_byte >> 4) != 4) {
        return TC_ACT_OK;
    }

    __u8 proto;
    if (bpf_skb_load_bytes(skb, 14 + 9, &proto, 1) < 0) {
        return TC_ACT_OK;
    }

    __u32 ip_hlen = (ihl_byte & 0x0F) * 4;
    if (ip_hlen < 20) {
        return TC_ACT_OK;
    }

    __u32 saddr;
    if (bpf_skb_load_bytes(skb, 14 + 12, &saddr, 4) < 0) {
        return TC_ACT_OK;
    }

    if (proto == IPPROTO_ICMP) {
        // macOS DFI=S: capture ICMP echo request DF bit, keyed by source IP.
        // The egress hook applies it to the echo reply for DFI=S behavior.
        __u8 icmp_type;
        if (bpf_skb_load_bytes(skb, 14 + ip_hlen, &icmp_type, 1) == 0 && icmp_type == 8) {
            __be16 frag_off;
            if (bpf_skb_load_bytes(skb, 14 + 6, &frag_off, 2) == 0) {
                __u8 df = (bpf_ntohs(frag_off) & 0x4000) ? 1 : 0;
                bpf_map_update_elem(&icmp_df_map, &saddr, &df, BPF_ANY);
            }
        }
        return TC_ACT_OK;
    }

    if (proto != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    __u32 tcp_off = 14 + ip_hlen;
    __be16 sport, dport;
    __be32 tcp_seq_be, tcp_ack_be;

    if (bpf_skb_load_bytes(skb, tcp_off,     &sport, 2) < 0 ||
        bpf_skb_load_bytes(skb, tcp_off + 2, &dport, 2) < 0 ||
        bpf_skb_load_bytes(skb, tcp_off + 4, &tcp_seq_be, 4) < 0 ||
        bpf_skb_load_bytes(skb, tcp_off + 8, &tcp_ack_be, 4) < 0) {
        return TC_ACT_OK;
    }

    struct seq_cache_key ckey = {};
    ckey.saddr = saddr;
    ckey.sport = sport;
    ckey.dport = dport;

    struct seq_cache_val cval = {};
    cval.seq     = bpf_ntohl(tcp_seq_be);
    cval.ack_num = bpf_ntohl(tcp_ack_be);

    bpf_map_update_elem(&seq_cache, &ckey, &cval, BPF_ANY);

    // macOS T7 A=S: if FIN+PSH+URG (nmap T7 probe), record the probe SEQ.
    // The egress RST+ACK handler will use ACK=seq instead of seq+1.
    __u8 tcp_ingress_flags;
    if (bpf_skb_load_bytes(skb, tcp_off + 13, &tcp_ingress_flags, 1) == 0) {
        if ((tcp_ingress_flags & 0x29) == 0x29) {
            struct seq_cache_key fin_key = {};
            fin_key.saddr = saddr;
            fin_key.sport = sport;
            fin_key.dport = dport;
            __u32 fin_seq_val = bpf_ntohl(tcp_seq_be);
            bpf_map_update_elem(&fin_probe_map, &fin_key, &fin_seq_val, BPF_ANY);
        }
    }

    return TC_ACT_OK;
}

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
    // macOS ICMP: skip DF override so the Linux kernel mirrors the probe's DF bit
    // naturally → DFI=S. Forcing DF=1 on ICMP would give DFI=Y (always set).
    __u8 is_macos_profile = (!profile->win_quirks && profile->ip_id_behavior == IPID_ZERO);
    __u8 current_df = (bpf_ntohs(old_frag_off) & 0x4000) ? 1 : 0;
    if (current_df != profile->df_bit && !(is_macos_profile && proto == IPPROTO_ICMP)) {
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

    // macOS: RST+ACK (T5/T7 — closed-port SYN/FIN response) has DF=N per nmap-os-db.
    // Open-port RSTs (T4/T6, pure RST) keep DF=Y from profile->df_bit above.
    if (is_macos_profile && proto == IPPROTO_TCP) {
        __u8 rst_ihl;
        if (bpf_skb_load_bytes(skb, 14, &rst_ihl, 1) == 0) {
            __u32 rst_hlen = (__u32)((rst_ihl & 0x0F) * 4);
            __u8 rst_flags;
            if (bpf_skb_load_bytes(skb, 14 + rst_hlen + 13, &rst_flags, 1) == 0) {
                if ((rst_flags & 0x14) == 0x14) { // RST+ACK
                    // T5/T7: macOS RST+ACK to closed port has DF=N.
                    __be16 rst_frag;
                    if (bpf_skb_load_bytes(skb, 14 + 6, &rst_frag, 2) == 0) {
                        __be16 rst_no_df = rst_frag & bpf_htons((__u16)(~0x4000U));
                        if (rst_no_df != rst_frag) {
                            if (bpf_skb_store_bytes(skb, 14 + 6, &rst_no_df, 2, 0) >= 0) {
                                bpf_l3_csum_replace(skb, 14 + 10, rst_frag, rst_no_df, 2);
                            }
                        }
                    }
                    // T7 A=S: for FIN+PSH+URG probes, macOS RST+ACK uses ACK=seq not seq+1.
                    // Look up fin_probe_map keyed by (nmap_ip, nmap_port, our_closed_port).
                    __u32 rst_daddr;
                    __be16 rst_tcp_sport, rst_tcp_dport;
                    if (bpf_skb_load_bytes(skb, 14 + 16, &rst_daddr, 4) == 0 &&
                        bpf_skb_load_bytes(skb, 14 + rst_hlen, &rst_tcp_sport, 2) == 0 &&
                        bpf_skb_load_bytes(skb, 14 + rst_hlen + 2, &rst_tcp_dport, 2) == 0) {
                        struct seq_cache_key fin_key = {};
                        fin_key.saddr = rst_daddr;     // nmap's IP
                        fin_key.sport = rst_tcp_dport; // nmap's ephemeral port (RST tcp dst)
                        fin_key.dport = rst_tcp_sport; // our closed port (RST tcp src)
                        __u32 *fin_seq = bpf_map_lookup_elem(&fin_probe_map, &fin_key);
                        if (fin_seq) {
                            __be32 old_ack_be;
                            if (bpf_skb_load_bytes(skb, 14 + rst_hlen + 8, &old_ack_be, 4) == 0) {
                                __be32 new_ack_be = bpf_htonl(*fin_seq);
                                if (new_ack_be != old_ack_be) {
                                    if (bpf_skb_store_bytes(skb, 14 + rst_hlen + 8,
                                                            &new_ack_be, 4, 0) >= 0) {
                                        bpf_l4_csum_replace(skb, 14 + rst_hlen + 16,
                                            old_ack_be, new_ack_be, 4);
                                    }
                                }
                            }
                            bpf_map_delete_elem(&fin_probe_map, &fin_key);
                        }
                    }
                }
            }
        }
    }

    // === IP ID Modification ===
    // Windows: shared counter across TCP+ICMP gives SS=S (#13 — win_quirks gate).
    // macOS: TCP IP-ID=0 (TI=Z), ICMP left native Linux-random (II=RI, CI=RD).
    //        ip_id_behavior==IPID_ZERO && !win_quirks identifies macOS profiles.
    // Linux: native per-socket random (SS=O) — no override needed.
    if (profile->win_quirks) {
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
    } else if (profile->ip_id_behavior == IPID_ZERO && !profile->win_quirks) {
        if (proto == IPPROTO_TCP) {
            // macOS TCP: IP-ID=0 for SYN/data (TI=Z). RSTs get random IP-ID (CI=RD)
            // because the kernel also generates RSTs with IP-ID=0, so we must actively
            // override to random (not just skip) to avoid CI=Z.
            __u8 ihl_nip = 0;
            bpf_skb_load_bytes(skb, 14, &ihl_nip, 1);
            __u32 ip_hdr_len = (__u32)((ihl_nip & 0x0F) * 4);
            __u8 tcp_flags_byte = 0;
            bpf_skb_load_bytes(skb, 14 + ip_hdr_len + 13, &tcp_flags_byte, 1);
            if (tcp_flags_byte & 0x04) { // RST: active random for CI=RD
                __u32 rand_id = bpf_get_prandom_u32();
                __be16 new_id = bpf_htons((__u16)(rand_id & 0xFFFF));
                if (old_id != new_id) {
                    if (bpf_skb_store_bytes(skb, 14 + 4, &new_id, 2, 0) >= 0) {
                        bpf_l3_csum_replace(skb, 14 + 10, old_id, new_id, 2);
                    }
                }
            } else { // not RST: zero IP-ID for TI=Z
                __be16 zero_id = 0;
                if (old_id != zero_id) {
                    if (bpf_skb_store_bytes(skb, 14 + 4, &zero_id, 2, 0) >= 0) {
                        bpf_l3_csum_replace(skb, 14 + 10, old_id, zero_id, 2);
                    }
                }
            }
        } else if (proto == IPPROTO_ICMP) {
            // macOS ICMP: Linux sequential IP-ID would give II=I; override with
            // per-packet random so nmap sees II=RI (random incremental).
            __u32 rand_id = bpf_get_prandom_u32();
            __be16 new_id = bpf_htons((__u16)(rand_id & 0xFFFF));
            if (old_id != new_id) {
                if (bpf_skb_store_bytes(skb, 14 + 4, &new_id, 2, 0) >= 0) {
                    bpf_l3_csum_replace(skb, 14 + 10, old_id, new_id, 2);
                }
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
            } else if (profile->tcp_timestamps && opt1 == TCPOPT_SACK_PERM) {
                // Linux style: MSS(4) + SACK(2) + TS(10) + NOP + WS(3) = 20 bytes.
                // Checked BEFORE the Windows ws>0&&ts branch: Linux profiles put
                // SACK_PERM at option index 1, Windows profiles put NOP there — so
                // opt1==SACK_PERM cleanly selects the Linux order. Emits a REAL
                // timestamp (was previously skipped as NOPs, which broke TS=A and
                // left a Windows-ordered OPS on a Linux profile — the #10 bug).
                __u32 lin_tsecr = 0;
                if (old_opts[8] == TCPOPT_TIMESTAMP && old_opts[9] == TCPOLEN_TIMESTAMP) {
                    lin_tsecr = ((__u32)old_opts[14]<<24)|((__u32)old_opts[15]<<16)|((__u32)old_opts[16]<<8)|old_opts[17];
                } else if (old_opts[6] == TCPOPT_TIMESTAMP && old_opts[7] == TCPOLEN_TIMESTAMP) {
                    lin_tsecr = ((__u32)old_opts[12]<<24)|((__u32)old_opts[13]<<16)|((__u32)old_opts[14]<<8)|old_opts[15];
                } else if (old_opts[4] == TCPOPT_TIMESTAMP && old_opts[5] == TCPOLEN_TIMESTAMP) {
                    lin_tsecr = ((__u32)old_opts[10]<<24)|((__u32)old_opts[11]<<16)|((__u32)old_opts[12]<<8)|old_opts[13];
                }
                __u32 lin_tsval = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
                new_opts[0] = TCPOPT_MSS;
                new_opts[1] = 4;
                new_opts[2] = (mss_val >> 8) & 0xFF;
                new_opts[3] = mss_val & 0xFF;
                if (use_sack) {
                    new_opts[4] = TCPOPT_SACK_PERM;
                    new_opts[5] = 2;
                }
                new_opts[6] = TCPOPT_TIMESTAMP;
                new_opts[7] = TCPOLEN_TIMESTAMP;
                new_opts[8]  = (lin_tsval >> 24) & 0xFF;
                new_opts[9]  = (lin_tsval >> 16) & 0xFF;
                new_opts[10] = (lin_tsval >> 8) & 0xFF;
                new_opts[11] = lin_tsval & 0xFF;
                new_opts[12] = (lin_tsecr >> 24) & 0xFF;
                new_opts[13] = (lin_tsecr >> 16) & 0xFF;
                new_opts[14] = (lin_tsecr >> 8) & 0xFF;
                new_opts[15] = lin_tsecr & 0xFF;
                new_opts[16] = TCPOPT_NOP;
                if (profile->window_scale > 0) {
                    new_opts[17] = TCPOPT_WSCALE;
                    new_opts[18] = 3;
                    new_opts[19] = profile->window_scale;
                }
            } else if (!profile->win_quirks && profile->ip_id_behavior == IPID_ZERO &&
                       profile->window_scale > 0 && profile->tcp_timestamps) {
                // macOS: first 20B = MSS(4)+NOP+WS(3)+NOP+NOP+TS(10).
                // Followed by expand to 24B: +SACK(2)+EOL+EOL (done after the write below).
                __u32 mac_tsecr = 0;
                if (old_opts[8] == TCPOPT_TIMESTAMP && old_opts[9] == TCPOLEN_TIMESTAMP) {
                    mac_tsecr = ((__u32)old_opts[14]<<24)|((__u32)old_opts[15]<<16)|((__u32)old_opts[16]<<8)|old_opts[17];
                } else if (old_opts[6] == TCPOPT_TIMESTAMP && old_opts[7] == TCPOLEN_TIMESTAMP) {
                    mac_tsecr = ((__u32)old_opts[12]<<24)|((__u32)old_opts[13]<<16)|((__u32)old_opts[14]<<8)|old_opts[15];
                } else if (old_opts[4] == TCPOPT_TIMESTAMP && old_opts[5] == TCPOLEN_TIMESTAMP) {
                    mac_tsecr = ((__u32)old_opts[10]<<24)|((__u32)old_opts[11]<<16)|((__u32)old_opts[12]<<8)|old_opts[13];
                }
                __u32 mac_tsval = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
                new_opts[0] = TCPOPT_MSS;      new_opts[1] = 4;
                new_opts[2] = (mss_val >> 8) & 0xFF; new_opts[3] = mss_val & 0xFF;
                new_opts[4] = TCPOPT_NOP;
                new_opts[5] = TCPOPT_WSCALE;   new_opts[6] = 3;
                new_opts[7] = profile->window_scale;
                new_opts[8] = TCPOPT_NOP;      new_opts[9] = TCPOPT_NOP;
                new_opts[10] = TCPOPT_TIMESTAMP; new_opts[11] = TCPOLEN_TIMESTAMP;
                new_opts[12] = (mac_tsval >> 24) & 0xFF; new_opts[13] = (mac_tsval >> 16) & 0xFF;
                new_opts[14] = (mac_tsval >> 8) & 0xFF;  new_opts[15] = mac_tsval & 0xFF;
                new_opts[16] = (mac_tsecr >> 24) & 0xFF; new_opts[17] = (mac_tsecr >> 16) & 0xFF;
                new_opts[18] = (mac_tsecr >> 8) & 0xFF;  new_opts[19] = mac_tsecr & 0xFF;
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

            // TS-off Windows: the real template is shorter than 20B (the kernel's
            // timestamp option was overwritten with trailing NOPs above). Shrink the
            // header to the real length so nmap reads M5B4NW8NNS (12B) / M5B4NW8 (8B, the
            // no-SACK O3) instead of a NOP-padded OPS. TS-on Windows + Linux keep 20B
            // (their options legitimately fill it).
            if (profile->win_quirks && profile->tcp_timestamps == 0) {
                __u32 keep = (profile->window_scale > 0) ? (use_sack ? 12 : 8) : 8;
                // Subtract the trailing NOP-pad words (new_opts[keep..19], each 0x0101)
                // from the L4 checksum: 12→4 words, 8→6 words.
                bpf_l4_csum_replace(skb, tcp_offset + 16, 0x0101, 0, 2);
                bpf_l4_csum_replace(skb, tcp_offset + 16, 0x0101, 0, 2);
                bpf_l4_csum_replace(skb, tcp_offset + 16, 0x0101, 0, 2);
                bpf_l4_csum_replace(skb, tcp_offset + 16, 0x0101, 0, 2);
                if (keep == 8) {
                    bpf_l4_csum_replace(skb, tcp_offset + 16, 0x0101, 0, 2);
                    bpf_l4_csum_replace(skb, tcp_offset + 16, 0x0101, 0, 2);
                }
                shrink_tcp_options(skb, tcp_offset, 20, keep);
            }
            // macOS: expand 20B → 24B, append SACK(2)+EOL+EOL at the tail.
            // Only when the client negotiated SACK (use_sack=1): nmap P3 omits SACK so
            // O3 stays 20B (= M5B4NW6NNT11, no SLL), matching the nmap-os-db entry.
            if (!profile->win_quirks && profile->ip_id_behavior == IPID_ZERO &&
                profile->window_scale > 0 && profile->tcp_timestamps && use_sack) {
                if (expand_tcp_options(skb, tcp_offset, 20, 24) == 0) {
                    __u8 mac_extra[4] = {TCPOPT_SACK_PERM, 2, TCPOPT_EOL, TCPOPT_EOL};
                    if (bpf_skb_store_bytes(skb, opt_start + 20, mac_extra, 4, 0) >= 0) {
                        bpf_l4_csum_replace(skb, tcp_offset + 16, 0, bpf_htons((__u16)0x0402), 2);
                    }
                }
            }
        }

        // === 12-byte options template (ECN probe, no timestamps negotiated) ===
        // nmap's ECN probe sends SYN with MSS+NOP+NOP+SACK+NOP+WS(7) = 12 bytes.
        // Rewrite to Windows order: MSS+NOP+WS(profile)+NOP+NOP+SACK = 12 bytes.
        if (opt_len == 12 && profile->window_scale > 0 && profile->tcp_options_count > 0 && is_syn && !profile->ecn_echo) {
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
                if (!profile->win_quirks && profile->ip_id_behavior == IPID_ZERO) {
                    // macOS ECN: MSS+NOP+WS+SACK+EOL+EOL (per nmap-os-db O field in ECN probe)
                    if (profile->sack_permitted && had_sack12) {
                        new12[8] = TCPOPT_SACK_PERM;
                        new12[9] = 2;
                    }
                    new12[10] = TCPOPT_EOL;
                    new12[11] = TCPOPT_EOL;
                } else {
                    // Windows: MSS+NOP+WS+NOP+NOP+SACK
                    new12[8] = TCPOPT_NOP;
                    new12[9] = TCPOPT_NOP;
                    if (profile->sack_permitted && had_sack12) {
                        new12[10] = TCPOPT_SACK_PERM;
                        new12[11] = 2;
                    }
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
        if (opt_len == 16 && profile->tcp_timestamps && is_syn && profile->win_quirks) {
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

        // === TS-off Windows O6 (no-WS probe): rewrite to M5B4NNS + shrink ===
        // The kernel's O6 SYN-ACK is MSS+SACK+TS = 16B. A TS-off Windows persona must
        // advertise M5B4NNS (MSS NOP NOP SACK = 8B, no timestamp). Rewrite + shrink to 8B.
        // W6 (no-WS window): a 65535-window no-TS Server (Server 2019) advertises FF70
        // here; smaller-window editions (Win10 = 2000) keep the general window value.
        if (opt_len == 16 && profile->win_quirks && profile->tcp_timestamps == 0 && is_syn) {
            __u32 o6 = tcp_offset + 20;
            __u8 o6_old[16];
            if (bpf_skb_load_bytes(skb, o6, o6_old, 16) >= 0) {
                __u16 mss6 = profile->mss;
                if (o6_old[0] == TCPOPT_MSS && o6_old[1] == 4) {
                    mss6 = ((__u16)o6_old[2] << 8) | o6_old[3];
                }
                __u8 o6_new[16] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
                o6_new[0] = TCPOPT_MSS; o6_new[1] = 4;
                o6_new[2] = (mss6 >> 8) & 0xFF; o6_new[3] = mss6 & 0xFF;
                o6_new[4] = TCPOPT_NOP; o6_new[5] = TCPOPT_NOP;
                o6_new[6] = TCPOPT_SACK_PERM; o6_new[7] = 2;
                // o6_new[8..15] stay NOP (the timestamp is dropped)
                if (bpf_skb_store_bytes(skb, o6, o6_new, 16, 0) >= 0) {
                    bpf_l4_csum_replace(skb, tcp_offset+16, ((__u16)o6_old[0]<<8)|o6_old[1], ((__u16)o6_new[0]<<8)|o6_new[1], 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, ((__u16)o6_old[2]<<8)|o6_old[3], ((__u16)o6_new[2]<<8)|o6_new[3], 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, ((__u16)o6_old[4]<<8)|o6_old[5], ((__u16)o6_new[4]<<8)|o6_new[5], 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, ((__u16)o6_old[6]<<8)|o6_old[7], ((__u16)o6_new[6]<<8)|o6_new[7], 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, ((__u16)o6_old[8]<<8)|o6_old[9], ((__u16)o6_new[8]<<8)|o6_new[9], 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, ((__u16)o6_old[10]<<8)|o6_old[11], ((__u16)o6_new[10]<<8)|o6_new[11], 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, ((__u16)o6_old[12]<<8)|o6_old[13], ((__u16)o6_new[12]<<8)|o6_new[13], 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, ((__u16)o6_old[14]<<8)|o6_old[15], ((__u16)o6_new[14]<<8)|o6_new[15], 2);
                    // remove the trailing 4 NOP-pad words [8..15] (now 0x0101)
                    bpf_l4_csum_replace(skb, tcp_offset+16, 0x0101, 0, 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, 0x0101, 0, 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, 0x0101, 0, 2);
                    bpf_l4_csum_replace(skb, tcp_offset+16, 0x0101, 0, 2);
                    // W6: a 65535-window no-TS Server advertises FF70 on the no-WS probe.
                    if (profile->window_size == 0xFFFF) {
                        __be16 w6n = bpf_htons((__u16)0xFF70), w6c = 0;
                        if (bpf_skb_load_bytes(skb, tcp_offset + 14, &w6c, 2) >= 0 && w6c != w6n) {
                            if (bpf_skb_store_bytes(skb, tcp_offset + 14, &w6n, 2, 0) >= 0) {
                                bpf_l4_csum_replace(skb, tcp_offset + 16, w6c, w6n, 2);
                            }
                        }
                    }
                    shrink_tcp_options(skb, tcp_offset, 16, 8);
                }
            }
        }

        // === macOS O6 (no-WS probe): expand 16B → 24B with full macOS options ===
        // nmap P6 sends SYN without WS; Linux kernel replies with MSS+SACK+TS = 16B.
        // macOS Darwin: when client omits WS, server also omits it (TCP option negotiation).
        // O6 = M5B4NNT11SLL = MSS(4)+NOP+NOP+TS(10)+SACK(2)+EOL+EOL = 20B.
        // (O1-O5 are 24B with WS; O6 is 20B without WS — per nmap-os-db.)
        if (opt_len == 16 && !profile->win_quirks && profile->ip_id_behavior == IPID_ZERO &&
            profile->window_scale > 0 && profile->tcp_timestamps && is_syn) {
            __u32 opt16m_start = tcp_offset + 20;
            __u8 old16m[16];
            if (bpf_skb_load_bytes(skb, opt16m_start, old16m, 16) == 0) {
                // Extract MSS from probe echo
                __u16 mss16m = profile->mss;
                if (old16m[0] == TCPOPT_MSS && old16m[1] == 4) {
                    mss16m = ((__u16)old16m[2] << 8) | old16m[3];
                }
                __u32 mac_tsval16 = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
                // Extract TSecr from Linux SYN-ACK: MSS+SACK+TS in 16B.
                // TS at offset 6: [6]=kind=8, [7]=len=10, [8-11]=TSval, [12-15]=TSecr
                __u32 mac_tsecr16 = 0;
                if (old16m[6] == TCPOPT_TIMESTAMP && old16m[7] == TCPOLEN_TIMESTAMP) {
                    mac_tsecr16 = ((__u32)old16m[12]<<24)|((__u32)old16m[13]<<16)|
                                  ((__u32)old16m[14]<<8)|old16m[15];
                }
                // Build 16B template: MSS(4)+NOP+NOP+TS(10) — no WS, TSecr at [12-15].
                // Expand to 20B for SACK+EOL+EOL at [16-19].
                __u8 new16m[16];
                new16m[0]  = TCPOPT_MSS;         new16m[1]  = 4;
                new16m[2]  = (mss16m >> 8) & 0xFF; new16m[3] = mss16m & 0xFF;
                new16m[4]  = TCPOPT_NOP;          new16m[5]  = TCPOPT_NOP;
                new16m[6]  = TCPOPT_TIMESTAMP;    new16m[7]  = TCPOLEN_TIMESTAMP;
                new16m[8]  = (mac_tsval16 >> 24) & 0xFF; new16m[9]  = (mac_tsval16 >> 16) & 0xFF;
                new16m[10] = (mac_tsval16 >> 8) & 0xFF;  new16m[11] = mac_tsval16 & 0xFF;
                new16m[12] = (mac_tsecr16 >> 24) & 0xFF; new16m[13] = (mac_tsecr16 >> 16) & 0xFF;
                new16m[14] = (mac_tsecr16 >> 8) & 0xFF;  new16m[15] = mac_tsecr16 & 0xFF;
                if (bpf_skb_store_bytes(skb, opt16m_start, new16m, 16, 0) >= 0) {
                    #pragma unroll
                    for (int j = 0; j < 8; j++) {
                        __u16 old_w = ((__u16)old16m[j*2] << 8) | old16m[j*2+1];
                        __u16 new_w = ((__u16)new16m[j*2] << 8) | new16m[j*2+1];
                        if (old_w != new_w) {
                            bpf_l4_csum_replace(skb, tcp_offset + 16,
                                bpf_htons(old_w), bpf_htons(new_w), 2);
                        }
                    }
                    // Expand 16B → 20B: 4 new bytes at [16-19] = SACK+len+EOL+EOL.
                    if (expand_tcp_options(skb, tcp_offset, 16, 20) == 0) {
                        __u8 mac_trail4[4] = {TCPOPT_SACK_PERM, 2, TCPOPT_EOL, TCPOPT_EOL};
                        if (bpf_skb_store_bytes(skb, opt16m_start + 16, mac_trail4, 4, 0) >= 0) {
                            bpf_l4_csum_replace(skb, tcp_offset + 16, 0, bpf_htons((__u16)0x0402), 2);
                        }
                    }
                }
            }
        }

        // === TSval coherence for established-connection data / pure-ACK segments ===
        // The 20- and 16-byte SYN/SYN-ACK templates above rewrite TSval to a clean
        // bpf_ktime millisecond clock — stripping Linux's per-connection RANDOM
        // timestamp offset — so nmap reads a Windows-like ~1 kHz rate (TS=A). But the
        // kernel keeps applying that random offset to DATA and pure-ACK segments,
        // which the eBPF previously left untouched. The result was a huge TSval
        // discontinuity between the handshake (offset stripped) and the data path
        // (offset retained) — e.g. SYN-ACK 7.88M vs data 3.3B. Standard clients
        // (PAWS / RTT validation) then silently DROP the payload, which broke real
        // co-located services (vsftpd) AND Mimic's own honeypots (SMB negotiate) in
        // the OSE-2026-001 exercise. Rewrite the data-path TSval to the SAME clock so
        // the entire flow is coherent. Established segments carry options
        // NOP,NOP,TS(10) = 12 bytes: TSval at option offset 4, TSecr at 8 (TSecr is
        // left untouched — it must keep echoing the peer's TSval).
        // Gate matches the SYN-ACK branch that emits the ktime TSval (window_scale>0
        // && tcp_timestamps — the Win11/25H2 template). Other profiles handle the
        // SYN-ACK TS option differently, so leave their data path untouched.
        if (opt_len == 12 && !is_syn && profile->tcp_timestamps && profile->window_scale > 0) {
            __u32 ts_opt_start = tcp_offset + 20;
            __u8 sig[4];
            if (bpf_skb_load_bytes(skb, ts_opt_start, sig, 4) >= 0) {
                if (sig[0] == TCPOPT_NOP && sig[1] == TCPOPT_NOP &&
                    sig[2] == TCPOPT_TIMESTAMP && sig[3] == TCPOLEN_TIMESTAMP) {
                    __u8 old_tsval[4];
                    if (bpf_skb_load_bytes(skb, ts_opt_start + 4, old_tsval, 4) >= 0) {
                        __u32 win_tsval = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
                        __u8 new_tsval[4] = {
                            (win_tsval >> 24) & 0xFF,
                            (win_tsval >> 16) & 0xFF,
                            (win_tsval >> 8) & 0xFF,
                            win_tsval & 0xFF
                        };
                        if (bpf_skb_store_bytes(skb, ts_opt_start + 4, new_tsval, 4, 0) >= 0) {
                            bpf_l4_csum_replace(skb, tcp_offset + 16,
                                ((__u16)old_tsval[0] << 8) | old_tsval[1],
                                ((__u16)new_tsval[0] << 8) | new_tsval[1], 2);
                            bpf_l4_csum_replace(skb, tcp_offset + 16,
                                ((__u16)old_tsval[2] << 8) | old_tsval[3],
                                ((__u16)new_tsval[2] << 8) | new_tsval[3], 2);
                        }
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

            // A=O: bare RST (no ACK flag) — set ack_seq to probe's SEQ.
            // Linux sends bare RST with ack_seq=0 (A=Z); Windows uses incoming SEQ (A=O).
            // Applies to T4 (ACK→open port) and T6 (ACK→closed port). Windows profiles
            // only — a Linux profile keeps the host's native A=Z (#13).
            if (!(tcp_flags & 0x10) && profile->win_quirks) {
                __u32 ip_daddr;
                __be16 tcp_sport, tcp_dport;
                if (bpf_skb_load_bytes(skb, 14 + 16, &ip_daddr, 4) >= 0 &&
                    bpf_skb_load_bytes(skb, tcp_offset,     &tcp_sport, 2) >= 0 &&
                    bpf_skb_load_bytes(skb, tcp_offset + 2, &tcp_dport, 2) >= 0) {
                    // Egress packet: sport=our_port, dport=remote_port, daddr=remote_ip
                    // Cache key was stored as: {saddr=remote_ip, sport=remote_port, dport=our_port}
                    struct seq_cache_key rkey = {};
                    rkey.saddr = ip_daddr;
                    rkey.sport = tcp_dport;
                    rkey.dport = tcp_sport;
                    struct seq_cache_val *sv = bpf_map_lookup_elem(&seq_cache, &rkey);
                    if (sv && sv->ack_num != 0) {
                        __u8 old_ack_b[4], new_ack_b[4];
                        if (bpf_skb_load_bytes(skb, tcp_offset + 8, old_ack_b, 4) >= 0) {
                            new_ack_b[0] = (sv->ack_num >> 24) & 0xFF;
                            new_ack_b[1] = (sv->ack_num >> 16) & 0xFF;
                            new_ack_b[2] = (sv->ack_num >>  8) & 0xFF;
                            new_ack_b[3] =  sv->ack_num        & 0xFF;
                            if (bpf_skb_store_bytes(skb, tcp_offset + 8, new_ack_b, 4, 0) >= 0) {
                                bpf_l4_csum_replace(skb, tcp_offset + 16,
                                    ((__u16)old_ack_b[0] << 8) | old_ack_b[1],
                                    ((__u16)new_ack_b[0] << 8) | new_ack_b[1], 2);
                                bpf_l4_csum_replace(skb, tcp_offset + 16,
                                    ((__u16)old_ack_b[2] << 8) | old_ack_b[3],
                                    ((__u16)new_ack_b[2] << 8) | new_ack_b[3], 2);
                            }
                        }
                    }
                }
            }
        }

        // === ECN SYN-ACK: clear ECE flag for Windows behavior ===
        // Linux sets ECE in SYN-ACK when responding to an ECN-capable SYN (nmap CC=Y).
        // All Windows versions respond without ECE in SYN-ACK (CC=N). Clear it always —
        // ecn_support in the profile means the OS initiates ECN connections, not that it
        // echoes ECE in SYN-ACK back to probers.
        // Only applies to SYN-ACK (SYN=1 + ACK=1, flags & 0x12 == 0x12).
        // Gated by !ecn_echo && !ecn_cc: Linux/macOS (ecn_echo) AND modern Windows Server
        // editions that reflect ECE (ecn_cc, from explicit_congestion: echo) keep it →
        // CC=Y; only Windows workstation clears it → CC=N (#12; Server 2019 needs CC=Y).
        if ((tcp_flags & 0x12) == 0x12 && (tcp_flags & 0x40) && !profile->ecn_echo && !profile->ecn_cc) {
            __u8 no_ece = tcp_flags & ~(__u8)0x40;  // clear ECE (bit 6)
            if (bpf_skb_store_bytes(skb, tcp_offset + 13, &no_ece, 1, 0) >= 0) {
                bpf_l4_csum_replace(skb, tcp_offset + 16,
                    (__u16)tcp_flags << 8, (__u16)no_ece << 8, 2);
            }
        }

        // === ECN-probe SYN-ACK window (nmap ECN W=) ===
        // A real Linux kernel advertises a SMALLER rwnd on the ECN probe's SYN-ACK
        // than on the OS-detection probes — e.g. FAF0 vs the WIN= FE88. The general
        // window-set above stamped window_size on every TCP packet, so the ECN probe
        // came out FE88 (the lone field keeping a Linux persona at 99%, not exact).
        // Identify the ECN-probe response by the ECE bit (only nmap's ECN probe elicits
        // it) and override the window to its band companion. Linux/macOS only (ecn_echo).
        if ((tcp_flags & 0x12) == 0x12 && (tcp_flags & 0x40) && profile->ecn_echo) {
            __be16 ecn_w = 0;
            if (profile->window_size == 0xFE88) {
                ecn_w = bpf_htons((__u16)0xFAF0);       // Linux 4.15-5.19 / 5.4-5.10
            } else if (profile->window_size == 0x7120) {
                ecn_w = bpf_htons((__u16)0x7210);       // Linux 3.2-4.14
            }
            if (ecn_w != 0) {
                __be16 cur_w = 0;
                if (bpf_skb_load_bytes(skb, tcp_offset + 14, &cur_w, 2) >= 0) {
                    if (cur_w != ecn_w) {
                        if (bpf_skb_store_bytes(skb, tcp_offset + 14, &ecn_w, 2, 0) >= 0) {
                            bpf_l4_csum_replace(skb, tcp_offset + 16, cur_w, ecn_w, 2);
                        }
                    }
                }
            }
        }
    }

    // === ICMP Behavior ===
    // Windows/Linux: DF cleared in ICMP responses (IE DFI=N, U1 DF=N).
    // macOS: DF MIRRORED from probe (IE DFI=S) — ingress captures probe's DF bit in
    //   icmp_df_map; egress applies it to echo replies so each reply mirrors its probe.
    // Linux also echoes the ICMP code from echo requests; Windows sends code=0 (CD=Z).
    if (proto == IPPROTO_ICMP) {
        // Read IHL to find ICMP header offset (shared between macOS DFI=S and CD=Z paths).
        __u8 icmp_ihl;
        __u32 icmp_start = 0;
        if (bpf_skb_load_bytes(skb, 14, &icmp_ihl, 1) >= 0) {
            icmp_start = 14 + ((__u32)(icmp_ihl & 0x0F) * 4);
        }

        if (is_macos_profile) {
            // macOS U1: truncate port-unreachable (type=3,code=3) quote to
            // icmp_quote_size bytes past the inner IP header (IPL=38h=56d for 8-byte quote).
            // Linux includes the full inner datagram; macOS quotes only 8 bytes.
            if (icmp_start > 0 && profile->icmp_quote_size > 0) {
                __u8 u1_type, u1_code;
                if (bpf_skb_load_bytes(skb, icmp_start, &u1_type, 1) == 0 &&
                    bpf_skb_load_bytes(skb, icmp_start + 1, &u1_code, 1) == 0 &&
                    u1_type == 3 && u1_code == 3) {
                    // Determine inner IP header length (default 20; nmap U1 probe uses no opts)
                    __u8 inner_ihl;
                    __u32 inner_ip_len = 20;
                    if (bpf_skb_load_bytes(skb, icmp_start + 8, &inner_ihl, 1) == 0) {
                        __u32 tmp = (__u32)((inner_ihl & 0x0F) * 4);
                        if (tmp >= 20 && tmp <= 60) inner_ip_len = tmp;
                    }
                    // Target outer IP total length = 20 + 8 (ICMP hdr) + inner_ip + quote_size
                    __u32 target_ip_len = 20 + 8 + inner_ip_len + (__u32)profile->icmp_quote_size;
                    __be16 old_tot;
                    if (bpf_skb_load_bytes(skb, 14 + 2, &old_tot, 2) == 0) {
                        __u32 cur_ip_len = (__u32)bpf_ntohs(old_tot);
                        if (cur_ip_len > target_ip_len) {
                            __be16 new_tot = bpf_htons((__u16)target_ip_len);
                            if (bpf_skb_change_tail(skb, 14 + target_ip_len, 0) == 0) {
                                // Update outer IP total length and fix IP checksum
                                if (bpf_skb_store_bytes(skb, 14 + 2, &new_tot, 2, 0) >= 0) {
                                    bpf_l3_csum_replace(skb, 14 + 10, old_tot, new_tot, 2);
                                }
                                // Recompute ICMP checksum over 36 bytes:
                                // ICMP hdr(8) + inner IP(20) + 8-byte quote = 36 bytes.
                                // Hard-coded 36 (18 × u16) keeps the verifier happy.
                                __u8 icmp_msg[36];
                                if (bpf_skb_load_bytes(skb, icmp_start, icmp_msg, 36) == 0) {
                                    icmp_msg[2] = 0; icmp_msg[3] = 0; // zero checksum field
                                    icmp_msg[34] = 0; icmp_msg[35] = 0; // zero inner UDP csum (RUCK=0)
                                    __u32 csum32 = 0;
                                    #pragma unroll
                                    for (int k = 0; k < 18; k++) {
                                        csum32 += ((__u32)icmp_msg[k * 2] << 8) |
                                                  (__u32)icmp_msg[k * 2 + 1];
                                    }
                                    csum32 = (csum32 >> 16) + (csum32 & 0xFFFF);
                                    csum32 += (csum32 >> 16);
                                    __u16 icmp_csum = (__u16)(~csum32);
                                    bpf_skb_store_bytes(skb, icmp_start + 2, &icmp_csum, 2, 0);
                                    // Write zeroed inner UDP checksum to packet
                                    __be16 zero16 = 0;
                                    bpf_skb_store_bytes(skb, icmp_start + 34, &zero16, 2, 0);
                                }
                                return TC_ACT_OK; // packet structure changed; done
                            }
                        }
                    }
                }
            }

            // macOS DFI=S: for echo replies (type=0), look up the probe's DF bit.
            if (icmp_start > 0) {
                __u8 icmp_type;
                if (bpf_skb_load_bytes(skb, icmp_start, &icmp_type, 1) == 0 && icmp_type == 0) {
                    __u32 daddr;
                    if (bpf_skb_load_bytes(skb, 14 + 16, &daddr, 4) == 0) {
                        __u8 *probe_df = bpf_map_lookup_elem(&icmp_df_map, &daddr);
                        if (probe_df) {
                            __be16 rep_frag;
                            if (bpf_skb_load_bytes(skb, 14 + 6, &rep_frag, 2) == 0) {
                                __be16 new_frag;
                                if (*probe_df) {
                                    new_frag = rep_frag | bpf_htons(0x4000);
                                } else {
                                    new_frag = rep_frag & bpf_htons((__u16)(~0x4000U));
                                }
                                if (new_frag != rep_frag) {
                                    if (bpf_skb_store_bytes(skb, 14 + 6, &new_frag, 2, 0) >= 0) {
                                        bpf_l3_csum_replace(skb, 14 + 10, rep_frag, new_frag, 2);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Windows/Linux: clear DF bit on ICMP responses (DFI=N).
            __be16 icmp_frag_off;
            if (bpf_skb_load_bytes(skb, 14 + 6, &icmp_frag_off, 2) >= 0) {
                __be16 icmp_no_df = icmp_frag_off & bpf_htons((__u16)(~0x4000U));
                if (icmp_no_df != icmp_frag_off) {
                    if (bpf_skb_store_bytes(skb, 14 + 6, &icmp_no_df, 2, 0) >= 0) {
                        bpf_l3_csum_replace(skb, 14 + 10, icmp_frag_off, icmp_no_df, 2);
                    }
                }
            }
        }

        // For ICMP echo replies (type=0): force code=0 (Windows: CD=Z). Windows
        // profiles only — Linux echoes the probe's code (CD=S), which is the host's
        // native behavior, so a Linux profile leaves it untouched (#13).
        if (profile->win_quirks && icmp_start > 0) {
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
