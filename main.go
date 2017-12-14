/*
* 网页广告太烦了,实在受不了就搞了这个项目
 */

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/fsnotify/fsnotify"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ConfJSONFile 默认配置文件
const ConfJSONFile = "conf.json"

var (
	// GitHash 编译代码版本
	GitHash string
	// CompileTime 编译时间
	CompileTime string
)

type config struct {
	Domains []string
	Ips     []string
	Log     string
	Daemon  bool
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
	confFilePath := flag.String("config", ConfJSONFile, "config file json format")
	flag.Parse()

	jsonConf, err := loadConfig(*confFilePath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	logFile, err := os.OpenFile(jsonConf.Log, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer logFile.Close()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(logFile)

	logOut(GitHash, CompileTime)

	blackIPMap := make(map[string]struct{})

	for _, ds := range jsonConf.Domains {
		rds := strings.TrimSpace(ds)
		if rds == "" {
			continue
		}
		ips, err := net.LookupIP(rds)
		if err != nil {
			logOut(err.Error())
			continue
		}
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

	if jsonConf.Daemon {
		restart(0)
		os.Exit(0)
	}

	watch, err := fsnotify.NewWatcher()
	if err != nil {
		logOut(err.Error())
		return
	}
	defer watch.Close()
	go func() {
		for e := range watch.Events {
			if e.Op&fsnotify.Write == fsnotify.Write {
				if err := restart(3); err != nil {
					logOut(err.Error())
					continue
				}
				// 自已退出
				os.Exit(0)
			}
		}
	}()

	watch.Add(*confFilePath)

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logOut(err.Error())
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
		logOut("can not found dev")
		return
	}

	gHandle, err = pcap.OpenLive(devName, 64, true, pcap.BlockForever)
	if err != nil {
		logOut(err.Error())
		return
	}
	defer gHandle.Close()

	logOut("listen device", devName)

	err = gHandle.SetBPFFilter("tcp and (dst port 80 or dst port 443)")
	if err != nil {
		logOut(err.Error())
		return
	}

	go func() {
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
	}()

	signalChan := make(chan os.Signal, 1)

	signal.Notify(signalChan, os.Interrupt, os.Kill, syscall.SIGTERM)

	s := <-signalChan

	logOut("recvice signal:" + s.String())
}

func reset(pack gopacket.Packet, ip *layers.IPv4) {
	ethLayer := pack.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		logOut("not ethernet")
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	tcpLayer := pack.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		logOut("not tcp")
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

	tcpObj := &layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		Ack:     tcp.Seq + tcpDataLen + 1,
		Seq:     tcp.Ack,
		RST:     true,
		ACK:     true,
		PSH:     true,
		URG:     true,
	}

	// 非常重要,否则无法序列化成功,因为计算检验值需要ip4/6
	tcpObj.SetNetworkLayerForChecksum(ip)

	err := gopacket.SerializeLayers(buf, opts,
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
		tcpObj,
	)
	if err != nil {
		logOut("Serial:", err.Error())
		return
	}

	err = gHandle.WritePacketData(buf.Bytes())
	if err != nil {
		logOut("write:", ip.DstIP.String(), err.Error())
	}
}

func restart(seconds int) error {
	selfPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return err
	}

	confPath := ConfJSONFile
	if len(os.Args) >= 2 {
		confPath, err = filepath.Abs(os.Args[1])
		if err != nil {
			return err
		}
	}

	return exec.Command("sh", "-c",
		fmt.Sprintf(
			"sleep %vs && %v -c %v",
			seconds,
			selfPath,
			confPath,
		),
	).Start()
}

// 日志输出
func logOut(strs ...string) {
	log.Println(strings.Join(strs, ","))

	// fmt.Println(append(
	// 	[]string{sourcePos(2)},
	// 	strs...,
	// ))
}

// opts第一个参数是函数层级
func sourcePos(opts ...int) string {
	skip := 1
	if len(opts) > 0 {
		skip = opts[0]
	}
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return ""
	}
	fun := runtime.FuncForPC(pc)
	return fmt.Sprintf(
		"[%v %v:%v]",
		path.Base(file),
		fun.Name(),
		line,
	)
}
