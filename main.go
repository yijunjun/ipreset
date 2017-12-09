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

func main() {
	confFilePath := flag.String("config", "config.json", "config file json format")
	flag.Parse()

	jsonConf, err := config.NewConfig("json", *confFilePath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	blackIpMap := make(map[net.Ip]struct{})

	for _, ds := range jsonConf.Strings("domains") {
		ips, err := net.LookupIP(ds)
		if err != nil {
			fmt.Println(ds, err.Error())
			continue
		}
		for _, ip := range ips {
			blackIpMap[ip] = struct{}{}
		}

	}

	for _, ipStr := range jsonConf.Strings("ips") {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			blackIpMap[ip] = struct{}{}
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

	handle, err := pcap.OpenLive(devName, 1024, false, 10*time.Second)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer handle.Close()

	fmt.Println("listen device", devName)

	err = handle.SetBPFFilter("tcp and port 80")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range ps.Packets() {
		ipLayer := p.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			if _, ok := blackIpMap[ip.DstIP]; ok {
				Reset(p)
			}

		}
	}

}

func Reset(pack gopacket.Packet) {

}
