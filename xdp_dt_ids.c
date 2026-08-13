#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 1. Khai báo Struct chứa Feature (Chỉ dùng số nguyên)
struct pkt_features {
    __u32 src_port;
    __u32 dst_port;
    __u32 pkt_len;
    __u8  tcp_flags;
    __u8  ttl;
};
static __always_inline int classify_packet(struct pkt_features *features) {
        if (features->tcp_flags <=  0.7437) {
                if (features->dst_port <= -1.9603) {
                        if (features->pkt_len <=  0.0016) {
                                if (features->ttl <= -2.1651) {
                                        if (features->src_port <= -3.0003) {
                                                return XDP_DROP; // Du doan: Class1
                                        } else {
                                                return XDP_PASS; // Du doan: Class0
                                        }
                                } else {
                                        if (features->tcp_flags <= -2.3060) {
                                                return XDP_DROP; // Du doan: Class1
                                        } else {
                                                return XDP_PASS; // Du doan: Class0
                                        }
                                }
                        } else {
                                if (features->src_port <= -1.4052) {
                                        if (features->ttl <= -1.1478) {
                                                return XDP_DROP; // Du doan: Class1
                                        } else {
                                                return XDP_PASS; // Du doan: Class0
                                        }
                                } else {
                                        if (features->pkt_len <=  0.3311) {
                                                return XDP_PASS; // Du doan: Class0
                                        } else {
                                                return XDP_DROP; // Du doan: Class1
                                        }
                                }
                        }
                } else {
                        if (features->src_port <=  0.9812) {
                                if (features->pkt_len <=  1.3321) {
                                        if (features->pkt_len <= -1.1638) {
                                                return XDP_PASS; // Du doan: Class0
                                        } else {
                                                return XDP_PASS; // Du doan: Class0
                                        }
                                } else {
                                        if (features->ttl <=  2.9868) {
                                                return XDP_PASS; // Du doan: Class0
                                        } else {
                                                return XDP_DROP; // Du doan: Class1
                                        }
                                }
                        } else {
                                if (features->dst_port <=  0.2828) {
                                        if (features->tcp_flags <= -0.9825) {
                                                return XDP_DROP; // Du doan: Class1
                                        } else {
                                                return XDP_PASS; // Du doan: Class0
                                        }
                                } else {
                                        if (features->tcp_flags <= -1.1326) {
                                                return XDP_PASS; // Du doan: Class0
                                        } else {
                                                return XDP_DROP; // Du doan: Class1
                                        }
                                }
                        }
                }
        } else {
                if (features->src_port <= -1.2944) {
                        if (features->ttl <= -0.3338) {
                                if (features->src_port <= -3.1795) {
                                        if (features->pkt_len <=  0.4964) {
                                                return XDP_DROP; // Du doan: Class1
                                        } else {
                                                return XDP_PASS; // Du doan: Class0
                                        }
                                } else {
                                        if (features->ttl <= -0.6483) {
                                                return XDP_DROP; // Du doan: Class1
                                        } else {
                                                return XDP_DROP; // Du doan: Class1
                                        }
                                }
                        } else {
                                if (features->dst_port <=  1.4192) {
                                        if (features->pkt_len <=  0.0849) {
                                                return XDP_DROP; // Du doan: Class1
                                        } else {
                                                return XDP_PASS; // Du doan: Class0
                                        }
                                } else {
                                        if (features->ttl <=  1.6547) {
                                                return XDP_PASS; // Du doan: Class0
                                        } else {
                                                return XDP_DROP; // Du doan: Class1
                                        }
                                }
                        }
                } else {
                        if (features->dst_port <=  1.7970) {
                                if (features->ttl <=  0.7608) {
                                        if (features->pkt_len <=  0.7794) {
                                                return XDP_PASS; // Du doan: Class0
                                        } else {
                                                return XDP_DROP; // Du doan: Class1
                                        }
                                } else {
                                        if (features->ttl <=  1.8048) {
                                                return XDP_PASS; // Du doan: Class0
                                        } else {
                                                return XDP_PASS; // Du doan: Class0
                                        }
                                }
                        } else {
                                if (features->src_port <= -0.1567) {
                                        if (features->tcp_flags <=  1.4026) {
                                                return XDP_DROP; // Du doan: Class1
                                        } else {
                                                return XDP_DROP; // Du doan: Class1
                                        }
                                } else {
                                        if (features->src_port <=  0.3057) {
                                                return XDP_DROP; // Du doan: Class1
                                        } else {
                                                return XDP_DROP; // Du doan: Class1
                                        }
                                }
                        }
                }
        }
}

SEC("xdp")
int xdp_dt_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Khởi tạo struct features với giá trị 0
    struct pkt_features feat = {0};

    // Feature 1: Chiều dài toàn bộ gói tin
    feat.pkt_len = data_end - data;

    // Phân tích Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // Phân tích IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    
    // Feature 2: TTL
    feat.ttl = ip->ttl;

    // Chỉ xét TCP
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    // Phân tích TCP
    struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // Feature 3 & 4: Source và Dest Port
    // Lưu ý dùng bpf_ntohs để chuyển từ Network Order (Big Endian) sang Host Order để DT so sánh chuẩn xác
    feat.src_port = bpf_ntohs(tcp->source);
    feat.dst_port = bpf_ntohs(tcp->dest);

    // Feature 5: TCP Flags (Nằm ở byte thứ 14 của TCP Header)
    __u8 *flags = (__u8 *)tcp + 13;
    if ((void *)(flags + 1) > data_end) return XDP_PASS;
    feat.tcp_flags = *flags;

    // Đẩy features vào "Bộ não" Decision Tree để ra quyết định
    int action = classify_packet(&feat);
    
    if (action == XDP_DROP) {
        bpf_printk("XDP-DT: Pkt dropped! Len: %d, DstPort: %d\n", feat.pkt_len, feat.dst_port);
    }

    return action;
}

char _license[] SEC("license") = "GPL";
