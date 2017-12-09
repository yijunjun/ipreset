/*
* 网页广告太烦了,实在受不了就搞了这个项目
 */

package main

import (
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/astaxie/beego/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var gHandle *pcap.Handle

func main() {
	confFilePath := flag.String("config", "conf.json", "config file json format")
	flag.Parse()

	jsonConf, err := config.NewConfig("json", *confFilePath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	blackIPMap := make(map[string]struct{})

	for _, ds := range jsonConf.Strings("domains") {
		ips, err := net.LookupIP(ds)
		if err != nil {
			fmt.Println(ds, err.Error())
			continue
		}
		for _, ip := range ips {
			blackIPMap[ip.String()] = struct{}{}
		}

	}

	for _, ipStr := range jsonConf.Strings("ips") {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			blackIPMap[ip.String()] = struct{}{}
		}
	}

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Print device information
	devName := ""
	for _, device := range devices {
		for _, address := range device.Addresses {
			if address.Netmask == nil || address.Broadaddr == nil || address.P2P != nil {
				continue
			}
			devName = device.Name
			break
		}
	}

	if devName == "" {
		fmt.Println("can not found dev")
		return
	}

	gHandle, err = pcap.OpenLive(devName, 1024, false, 10*time.Second)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer gHandle.Close()

	fmt.Println("listen device", devName)

	err = gHandle.SetBPFFilter("tcp and port 80")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	ps := gopacket.NewPacketSource(gHandle, gHandle.LinkType())
	for p := range ps.Packets() {
		ipLayer := p.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			if _, ok := blackIPMap[ip.DstIP.String()]; ok {
				reset(p, ip)
			}

		}
	}

}

func reset(pack gopacket.Packet, ip *layers.IPv4) {
	ethLayer := pack.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		fmt.Println("not ethernet")
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	tcpLayer := pack.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		fmt.Println("not tcp")
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC: eth.DstMAC,
			DstMAC: eth.SrcMAC,
		},
		&layers.IPv4{
			SrcIP: ip.DstIP,
			DstIP: ip.SrcIP,
		},
		&layers.TCP{
			SrcPort: tcp.DstPort,
			DstPort: tcp.SrcPort,
			Ack:     tcp.Seq - 1,
			RST:     true,
		},
	)
	err := gHandle.WritePacketData(buf.Bytes())
	if err != nil {
		fmt.Println(ip.DstIP.String(), err.Error())
	}
}
