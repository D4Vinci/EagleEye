package main

// Before start do: go get github.com/google/gopacket
// Then install npcap https://nmap.org/npcap/
import (
	"fmt"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
	"strings"
	"net/http"
	"bytes"
	"net"
	"encoding/json"
	"os"
	"os/user"
	"golang.org/x/sys/windows/registry"
)

type Packet_data struct {
		PacketLayers       []string    `json:"PacketLayers"`
		CreatedAt          string			 `json:"createdAt"`
		EthernetSrcMac     string			 `json:"ethernetSrcMac,omitempty"`
		EthernetDstMac     string			 `json:"ethernetDstMac,omitempty"`
		EthernetType       string			 `json:"ethernetType,omitempty"`
		DnsQuery           string			 `json:"dnsQuery,omitempty"`
		IPv4SrcIP          string			 `json:"IPv4SrcIP,omitempty"`
		IPv4DstIP          string			 `json:"IPv4DstIP,omitempty"`
		IPv4Protocol       string			 `json:"IPv4Protocol,omitempty"`
		TCPSrcPort         string			 `json:"TCPSrcPort,omitempty"`
		TCPDstPort         string			 `json:"TCPDstPort,omitempty"`
		TCPSeq             string			 `json:"TCPSeq,omitempty"`
		UDPSrcPort         string			 `json:"UDPSrcPort,omitempty"`
		UDPDstPort         string			 `json:"UDPDstPort,omitempty"`
		UDPLength          string			 `json:"UDPLength,omitempty"`
		ICMPType					 string			 `json:"ICMPType,omitempty"`
		ICMPSeq						 string			 `json:"ICMPSeq,omitempty"`
		ICMPChecksum			 string			 `json:"ICMPChecksum,omitempty"`
		Payload            string      `json:"Payload,omitempty"`}

type Packet_request struct {
	RequestType		string					`json:RequestType`
	Deviceip			string					`json:Deviceip`
	Data					Packet_data			`json:data`}

type Info_request struct{
	RequestType string		`json:RequestType`
	Deviceip		string		`json:Deviceip`
	DeviceName  string		`json:deviceName`
	Username    string		`json:username`
	OS          string		`json:os`}

var (
	url						string = "http://127.0.0.1:8000/"
	// for windows the device name should always start with \\Device\\NPF_
	// If it starts with \\Device\\Tcpip_ or anything just replace it
	device				string = "\\Device\\NPF_{394B19E7-D72C-47A2-8915-62201EF9901B}"
	snapshot_len	int32  = 102400
	promiscuous		bool   = false
	err						error
	// timeout      time.Duration = 30 * time.Second
	handle *pcap.Handle
	// Packets filter in bpf syntax (https://docs.extrahop.com/8.3/bpf-syntax/)
	filter string = " "
	// dns only "udp and port 53"
	// http only "tcp and dst port 80" or "tcp and port 80" for more the whole packets
	// http get requests only "tcp and tcp[20:4] = 0x47455420"
	// http and https "tcp and (dst port 80 or dst port 8080 or dst port 443)"
	// for range of ports "portrange 0-10000"
)

func GetOutboundIP() string {
		conn, err := net.Dial("udp", "8.8.8.8:80")
		if err != nil {
				log.Fatal(err)
		}
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
}

func main() {
	// Sending device info to master
	fmt.Printf("Device ip %v\n", GetOutboundIP())
	hostname, err := os.Hostname()
	u, err := user.Current()
	username:= u.Username
	key, _ := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	defer key.Close()
	winver, _, _ := key.GetStringValue("ProductName")
	info := &Info_request{
		RequestType:"info",
		Deviceip:GetOutboundIP(),
		DeviceName:hostname,
		Username:username,
		OS:winver,
	}
	jsonStr, _ := json.Marshal(info)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	for{
		client := &http.Client{}
		resp, err := client.Do(req)
		if err == nil {
				// panic(err)
				defer resp.Body.Close()
				break
		} else{
			fmt.Printf(".")
			// defer resp.Body.Close()
		}
	}
	//-------------------------------------
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n\tCapturing/Listening for packets, filter='%v'\n\n", filter)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		processPacket(packet)
	}

}

func processPacket(packet gopacket.Packet) {
	fmt.Println("---------------------")
	layers_names := []string{}
	for _, layer := range packet.Layers() {
		layers_names = append(layers_names, fmt.Sprintf("%v", layer.LayerType()))
	}
	fmt.Println("Packet layers: " + strings.Join(layers_names, ", "))
	dt := time.Now()
	Request := &Packet_request{
		RequestType:"packet",
		Deviceip:GetOutboundIP(),
		Data:Packet_data{
			PacketLayers:layers_names,
			CreatedAt: dt.Format("01-02-2006 15:04:05.0"),
		},
	}
	netLayer := packet.NetworkLayer()
	if netLayer != nil {
		netFlow := netLayer.NetworkFlow()
		src, dst := netFlow.Endpoints()
		fmt.Printf("<NetFlow> Src: %v, Dst: %v \n", src, dst)
	} else {
		fmt.Println()
	}
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	tcpLayer := packet.Layer(layers.LayerTypeTCP) //packet.NetworkLayer()
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	applicationLayer := packet.ApplicationLayer()
	// if ipLayer != nil &&  tcpLayer != nil && applicationLayer != nil {
	if ethernetLayer != nil {
		// Ethernet type is typically IPv4 but could be ARP or other
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Printf("[Ethernet] Source MAC: %v, Destination MAC: %v and Ethernet type: %v \n", ethernetPacket.SrcMAC, ethernetPacket.DstMAC, ethernetPacket.EthernetType)
		Request.Data.EthernetSrcMac = fmt.Sprintf("%v",ethernetPacket.SrcMAC)
		Request.Data.EthernetDstMac = fmt.Sprintf("%v",ethernetPacket.DstMAC)
		Request.Data.EthernetType   = fmt.Sprintf("%v",ethernetPacket.EthernetType)
	}
	// if strings.Contains(string(applicationLayer.Payload()), "HTTP") {

	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		fmt.Printf("[DNS Query] %s\n", dns.Questions)
		Request.Data.DnsQuery = fmt.Sprintf("%v",dns.Questions)
	}
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		// IP layer variables:
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("[IPv4] From %s -> %s (Protocol: %s)\n", ip.SrcIP, ip.DstIP, ip.Protocol)
		Request.Data.IPv4SrcIP    = fmt.Sprintf("%v",ip.SrcIP)
		Request.Data.IPv4DstIP    = fmt.Sprintf("%v",ip.DstIP)
		Request.Data.IPv4Protocol = fmt.Sprintf("%v",ip.Protocol)
	}

	if tcpLayer != nil {
		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("[TCP] Ports from %d -> %d (Sequence: %d)\n", tcp.SrcPort, tcp.DstPort, tcp.Seq)
		Request.Data.TCPSrcPort    = fmt.Sprintf("%v",tcp.SrcPort)
		Request.Data.TCPDstPort    = fmt.Sprintf("%v",tcp.DstPort)
		Request.Data.TCPSeq        = fmt.Sprintf("%v",tcp.Seq)
	}

	if udpLayer != nil {
		// UDP layer variables: SrcPort, DstPort, Length, Checksum
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Printf("[UDP] Ports from %d -> %d (Length: %d)\n", udp.SrcPort, udp.DstPort, udp.Length)
		Request.Data.UDPSrcPort    = fmt.Sprintf("%v",udp.SrcPort)
		Request.Data.UDPDstPort    = fmt.Sprintf("%v",udp.DstPort)
		Request.Data.UDPLength     = fmt.Sprintf("%v",udp.Length)
	}

	if icmpLayer != nil {
		// ICMP layer variables: TypeCode, Checksum, Id, Seq
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		fmt.Printf("[ICMP] ICMP packet type %d Sequence %d (Checksum: %d)\n", int8(icmp.TypeCode), int8(icmp.Seq), uint8(icmp.Checksum))
		Request.Data.ICMPType				= fmt.Sprintf("%v",int8(icmp.TypeCode))
		Request.Data.ICMPSeq				= fmt.Sprintf("%v",int8(icmp.Seq))
		Request.Data.ICMPChecksum		= fmt.Sprintf("%v",uint8(icmp.Checksum))
	}

	if applicationLayer != nil {
		// fmt.Printf("[Payload] %s\n", applicationLayer.Payload())
		Request.Data.Payload     = fmt.Sprintf("%s",applicationLayer.Payload())
	}

	fmt.Println("---------------------\n ")
	jsonStr, _ := json.Marshal(Request)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
			// panic(err)
	}
	if resp !=nil{
		defer resp.Body.Close()
	}
	// fmt.Println("response Status:", resp.Status)
	// fmt.Println("response Headers:", resp.Header)
	// body, _ := ioutil.ReadAll(resp.Body)
	// fmt.Println("response Body:", string(body))
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
