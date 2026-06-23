//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_PORT 53
#define MAX_QNAME 128
#define TC_ACT_OK 0

struct dns_hdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

struct dns_event {
    __u64 timestamp_ns;
    __u8 src_ip[4];
    __u8 dst_ip[4];
    __u16 src_port;
    __u16 dst_port;
    __u16 txid;
    __u16 qtype;
    __u8 rcode;
    __u8 direction;
    __u8 kind;
    __u8 qname_len;
    char qname[MAX_QNAME];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int load_u8(struct __sk_buff *skb, int off, __u8 *v) {
    return bpf_skb_load_bytes(skb, off, v, sizeof(*v));
}

static __always_inline int parse_qname(struct __sk_buff *skb, int *off, struct dns_event *event) {
    int out = 0;
    int pos = *off;

#pragma clang loop unroll(disable)
    for (int labels = 0; labels < 32; labels++) {
        __u8 len = 0;
        if (load_u8(skb, pos, &len) < 0) {
            return -1;
        }
        pos++;

        if (len == 0) {
            break;
        }

        // DNS name compression pointer. We intentionally skip compressed names
        // in the eBPF parser and let unmatched responses be ignored in user space.
        if ((len & 0xc0) == 0xc0) {
            return -1;
        }
        if (len > 63) {
            return -1;
        }
        if (out != 0) {
            if (out >= MAX_QNAME - 1) {
                return -1;
            }
            event->qname[out++] = '.';
        }

#pragma clang loop unroll(disable)
        for (int i = 0; i < 63; i++) {
            if (i >= len) {
                break;
            }
            if (out >= MAX_QNAME - 1) {
                return -1;
            }
            char c = 0;
            if (bpf_skb_load_bytes(skb, pos + i, &c, sizeof(c)) < 0) {
                return -1;
            }
            event->qname[out++] = c;
        }
        pos += len;
    }

    event->qname[out] = 0;
    event->qname_len = out;
    *off = pos;
    return out > 0 ? 0 : -1;
}

static __always_inline int handle_dns(struct __sk_buff *skb, __u8 direction) {
    __u16 eth_proto = 0;
    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &eth_proto, sizeof(eth_proto)) < 0) {
        return TC_ACT_OK;
    }
    if (eth_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    int ip_off = sizeof(struct ethhdr);
    struct iphdr iph = {};
    if (bpf_skb_load_bytes(skb, ip_off, &iph, sizeof(iph)) < 0) {
        return TC_ACT_OK;
    }
    if (iph.protocol != IPPROTO_UDP) {
        return TC_ACT_OK;
    }
    int ip_len = iph.ihl * 4;
    if (ip_len < (int)sizeof(struct iphdr)) {
        return TC_ACT_OK;
    }

    int udp_off = ip_off + ip_len;
    struct udphdr udph = {};
    if (bpf_skb_load_bytes(skb, udp_off, &udph, sizeof(udph)) < 0) {
        return TC_ACT_OK;
    }

    __u16 sport = bpf_ntohs(udph.source);
    __u16 dport = bpf_ntohs(udph.dest);
    if (sport != DNS_PORT && dport != DNS_PORT) {
        return TC_ACT_OK;
    }

    int dns_off = udp_off + sizeof(struct udphdr);
    struct dns_hdr dh = {};
    if (bpf_skb_load_bytes(skb, dns_off, &dh, sizeof(dh)) < 0) {
        return TC_ACT_OK;
    }
    if (bpf_ntohs(dh.qdcount) == 0) {
        return TC_ACT_OK;
    }

    struct dns_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return TC_ACT_OK;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(event->src_ip, &iph.saddr, 4);
    __builtin_memcpy(event->dst_ip, &iph.daddr, 4);
    event->src_port = sport;
    event->dst_port = dport;
    event->txid = bpf_ntohs(dh.id);
    __u16 flags = bpf_ntohs(dh.flags);
    event->rcode = flags & 0x0f;
    event->direction = direction;
    event->kind = (flags & 0x8000) ? 2 : 1;
    event->qtype = 0;
    event->qname_len = 0;
    __builtin_memset(event->qname, 0, sizeof(event->qname));

    int qoff = dns_off + sizeof(struct dns_hdr);
    if (parse_qname(skb, &qoff, event) < 0) {
        bpf_ringbuf_discard(event, 0);
        return TC_ACT_OK;
    }

    __u16 qtype = 0;
    if (bpf_skb_load_bytes(skb, qoff, &qtype, sizeof(qtype)) < 0) {
        bpf_ringbuf_discard(event, 0);
        return TC_ACT_OK;
    }
    event->qtype = bpf_ntohs(qtype);

    bpf_ringbuf_submit(event, 0);
    return TC_ACT_OK;
}

SEC("classifier/egress")
int dns_egress(struct __sk_buff *skb) {
    return handle_dns(skb, 1);
}

SEC("classifier/ingress")
int dns_ingress(struct __sk_buff *skb) {
    return handle_dns(skb, 2);
}

char _license[] SEC("license") = "GPL";
