#include<linux/bpf.h>
#include<linux/if_ether.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/in.h>
#include<bpf/bpf_helpers.h>
#include<bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_port_8080(struct xdp_md *ctx){
	//Ep kieu cac con tro  trong gioi han cua goi tin 
	void *data = (void *)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;
	
	//1.Phan tich Ethernet Header
	struct ethhdr *eth = data;
	if((void *)(eth+1) > data_end) return XDP_PASS;

	//Chi xu ly goi tin IPv4
	if(eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

	//2.Phan tich IP header
	struct iphdr *ip = (void *)(eth+1);
	if((void*)(ip+1) >data_end) return XDP_PASS;

	if(ip->protocol != IPPROTO_TCP) return XDP_PASS;
	
	//3.Phan tich TCP Header
	struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
	if ((void *)(tcp + 1) > data_end) {
        	return XDP_PASS;
    	}
	if(tcp->dest == bpf_htons(8080)){
		bpf_printk("XDP: DROPPED TCP PACKET TO PORT 8080 \n");
		return XDP_DROP;
	}
	return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
