package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	ifaceName := flag.String("iface", "wan", "Interface to attach to")
	flag.Parse()

	// 1. 解除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("RemoveMemlock:", err)
	}

	// 2. 加载 eBPF 程序
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal("Load objects:", err)
	}
	defer objs.Close()

	// 3. 获取网卡对象 (Netlink 方式)
	link, err := netlink.LinkByName(*ifaceName)
	if err != nil {
		log.Fatalf("Link %s not found: %v", *ifaceName, err)
	}

	// 4. TC 挂载核心逻辑 (Classic Netlink)

	// A. 创建 clsact Qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0), // ffff:0
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// 尝试添加 Qdisc
	if err := netlink.QdiscReplace(qdisc); err != nil {
		log.Fatalf("Creating clsact qdisc: %v", err)
	}
	log.Println("Qdisc clsact created.")

	// B. 创建 Filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.MvpHandle.FD(),
		Name:         "mvp_prog",
		DirectAction: true,
	}

	// 方向：Egress
	// Ingress: netlink.HANDLE_MIN_INGRESS (ffff:fff2)
	// Egress:  netlink.HANDLE_MIN_EGRESS (ffff:fff3)
	filter.Parent = netlink.HANDLE_MIN_EGRESS

	// 挂载 Filter
	if err := netlink.FilterAdd(filter); err != nil {
		// 如果挂载失败，尝试清理一下再挂
		log.Printf("Attach failed, cleaning up and retrying: %v", err)
		netlink.FilterDel(filter)
		if err := netlink.FilterAdd(filter); err != nil {
			log.Fatalf("Retry failed: %v", err)
		}
	}

	log.Printf("eBPF Attached to %s (Egress)!", *ifaceName)

	// 5. 退出清理逻辑

	// 捕捉信号
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// 统计循环
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			var count uint64
			// 读取 Map (Key = 0)
			if err := objs.PktCountMap.Lookup(uint32(0), &count); err != nil {
			} else {
				log.Printf("Packets passed: %d", count)
			}
		}
	}()

	<-stop
	log.Println("Detaching filter and qdisc...")

	// 删除 Filter
	if err := netlink.FilterDel(filter); err != nil {
		log.Printf("Error removing filter: %v", err)
	}
	// 删除 Qdisc
	if err := netlink.QdiscDel(qdisc); err != nil {
		log.Printf("Error removing qdisc: %v", err)
	}
}
