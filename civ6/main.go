package main

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	packets = make(chan *pkt, 100)
	mtxmp   = make(map[int]*sync.Mutex)
	mtmtx   sync.RWMutex
)

type pkt struct {
	SrcPort int
	DstPort int
	Payload []byte
}

func main() {
	fmt.Println("欢迎使用文明6联机工具 v0.1.0\n此工具会把UDP广播包转发到联机用的局域网内（仅支持ipv4）")
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("找不到网络设备：", err)
		log.Println("程序将自动退出...")
		return
	}
	var ipls []pcap.InterfaceAddress
	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if len(addr.IP) == net.IPv4len && addr.IP[0] != 0x7F {
				if addr.Broadaddr == nil {
					addr.Broadaddr = net.IPv4((addr.IP[0]&addr.Netmask[0])|^addr.Netmask[0], (addr.IP[1]&addr.Netmask[1])|^addr.Netmask[1], (addr.IP[2]&addr.Netmask[2])|^addr.Netmask[2], (addr.IP[3]&addr.Netmask[3])|^addr.Netmask[3])
				}
				if addr.IP[0] == 0xC0 && addr.IP[1] == 0xA8 && addr.IP[2] == 0x98 {
					ipls = append(ipls, addr)
				}
				go handle(dev.Name, addr.IP)
			}
		}
	}

	entities := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}
	for {
		packet := <-packets
		for _, addr := range ipls {
			for _, entity := range entities {
				go send(packet, addr.IP, net.IPv4(0xC0, 0xA8, 0x98, entity))
			}
		}
	}
}

func handle(dev string, addr net.IP) {
	if dev == "any" {
		return
	}
	h, err := pcap.OpenLive(dev, int32(65535), false, pcap.BlockForever)
	if h == nil {
		log.Printf("已跳过设备 %s - %s：%v\n", dev, addr.String(), err)
		return
	}
	defer h.Close()

	filstr := "udp and dst 255.255.255.255 and src " + addr.String()
	ferr := h.SetBPFFilter(filstr)
	if ferr != nil {
		log.Printf("已跳过设备 %s - %s：%v\n", dev, addr.String(), ferr)
		return
	}
	log.Printf("开始监听 %s - %s\n", dev, addr.String())
	var (
		ethLyr  layers.Ethernet
		ip4Lyr  layers.IPv4
		udpLyr  layers.UDP
		payload gopacket.Payload
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLyr, &ip4Lyr, &udpLyr, &payload)
	decoded := make([]gopacket.LayerType, 0)
	for {
		data, _, err := h.ReadPacketData()
		if err != nil {
			log.Printf("监听中断 %s - %s：%v\n", dev, addr.String(), err)
			return
		}
		if err := parser.DecodeLayers(data, &decoded); err != nil {
			log.Printf("%s - %s 报文解析失败：%v\n", dev, addr.String(), err.Error())
			continue
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeUDP:
				var packet pkt
				packet.SrcPort = int(udpLyr.SrcPort)
				packet.DstPort = int(udpLyr.DstPort)
				packet.Payload = payload.LayerContents()
				packets <- &packet
			}
		}
	}
}

func send(packet *pkt, srcIP net.IP, dstIP net.IP) {
	laddr := &net.UDPAddr{IP: srcIP, Port: packet.SrcPort}
	raddr := &net.UDPAddr{IP: dstIP, Port: packet.DstPort}
	mtmtx.Lock()
	mtx, ok := mtxmp[packet.SrcPort]
	if !ok {
		mtxmp[packet.SrcPort] = &sync.Mutex{}
		mtx = mtxmp[packet.SrcPort]
	}
	mtmtx.Unlock()
	mtx.Lock()
	defer mtx.Unlock()
	var (
		conn *net.UDPConn
		err  error
	)
	for {
		conn, err = net.DialUDP("udp", laddr, raddr)
		if err != nil {
			log.Printf("正在抢占端口：%d\n", packet.SrcPort)
		} else {
			break
		}
	}
	defer conn.Close()
	if _, err := conn.Write(packet.Payload); err != nil {
		log.Printf("已转发 %d 字节数据报：%v --> %v\n", len(packet.Payload), laddr, raddr)
	} else {
		log.Printf("已转发数据报：%v --> %v\n", laddr, raddr)
	}
}
