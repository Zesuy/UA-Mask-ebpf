//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// 兼容性
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pkt_count_map SEC(".maps");

//ebpf test program to count packets in TC hook
SEC("tc")
int mvp_handle(struct __sk_buff *skb) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_count_map, &key);
    
    if (count) {
        // 原子操作自增，保证并发安全
        __sync_fetch_and_add(count, 1);
    }

    // TC_ACT_OK 表示“放行”，什么都不改
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";