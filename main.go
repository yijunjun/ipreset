/*
* 网页广告太烦了,实在受不了就搞了这个项目
 */

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type config struct {
	Domains []string
	Ips     []string
}

func loadConfig(filePath string) (*config, error) {
	bs, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	c := &config{}

	err = json.Unmarshal(bs, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

var gHandle *pcap.Handle

func main() {
	confFilePath := flag.String("config", "conf.json", "config file json format")
	flag.Parse()

	jsonConf, err := loadConfig(*confFilePath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	blackIPMap := make(map[string]struct{})

	for _, ds := range jsonConf.Domains {
		ips, err := net.LookupIP(ds)
		if err != nil {
			fmt.Println(ds, err.Error())
			continue
		}
		fmt.Println(ds, ips)
		for _, ip := range ips {
			blackIPMap[ip.String()] = struct{}{}
		}
	}

	for _, ipStr := range jsonConf.Ips {
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

	gHandle, err = pcap.OpenLive(devName, 64, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer gHandle.Close()

	fmt.Println("listen device", devName)

	err = gHandle.SetBPFFilter("tcp and (dst port 80 or dst port 443)")
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
	if !tcp.SYN {
		return
	}

	tcpDataLen := uint32(ip.Length - uint16(ip.IHL)*4)
	tcpDataLen -= uint32((tcp.DataOffset & 0x0F) * 4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       eth.DstMAC,
			DstMAC:       eth.SrcMAC,
			EthernetType: eth.EthernetType,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      255,
			TOS:      ip.TOS,
			SrcIP:    ip.DstIP,
			DstIP:    ip.SrcIP,
			Protocol: ip.Protocol,
		},
		&layers.TCP{
			SrcPort: tcp.DstPort,
			DstPort: tcp.SrcPort,
			Ack:     tcp.Seq + tcpDataLen + 1,
			Seq:     tcp.Ack,
			RST:     true,
			ACK:     true,
			PSH:     true,
			URG:     true,
		},
	)

	bbs := buf.Bytes()
	fmt.Println(len(bbs), bbs)
	err := gHandle.WritePacketData(bbs) //buf.Bytes())
	if err != nil {
		fmt.Println("error:", ip.DstIP.String(), err.Error())
	}

	fmt.Println(time.Now().Unix(), ip.DstIP.String(), ip.Length, ip.IHL*4, tcp.DataOffset&0x0F, tcpDataLen)
}
