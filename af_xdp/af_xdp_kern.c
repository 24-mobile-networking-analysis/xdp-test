/* SPDX-License-Identifier: GPL-2.0 */
/* This file has been modified by Lee Sangyeop, 2024-12-13. */

#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdbool.h>

struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx) {
  int index = ctx->rx_queue_index;

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) > data_end ||
      eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *ip = (void *)eth + sizeof(*eth);
  if ((void *)ip + sizeof(*ip) > data_end || ip->protocol != IPPROTO_UDP)
    return XDP_PASS;

  struct udphdr *udp = (void *)ip + sizeof(*ip);

  if ((void *)udp + sizeof(*udp) > data_end || udp->dest != bpf_htons(7589))
    return XDP_PASS;

  if (bpf_map_lookup_elem(&xsks_map, &index))
    return bpf_redirect_map(&xsks_map, index, 0);

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
