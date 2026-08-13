#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>

SEC("xdp")
int xdp_hello(struct xdp_md *ctx)
{
	bpf_printk("Hello from XDP! Packet received.\n");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

