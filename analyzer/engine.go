package analyzer

import (
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Engine struct {
	PcapPath string
	Limit    int
}

func NewEngine(pcapPath string, limit int) *Engine {
	return &Engine{
		PcapPath: pcapPath,
		Limit:    limit, // 一度にpcapから読むパケットの数
	}
}

func (e *Engine) Run() []Event {
	// 1. ファイルを開く
	// 2. pcapとして読む準備をする
	// 3. パケットを1つずつ取り出す
	// 4. 最大10個まで、packetToEventでEventに変換する
	// 5. Eventの配列としてmain.goに返す
	// 4.1 IPv4層を取り出す
	// 4.2 SrcIP, DstIP, ProtocolをEventに入れる
	// 4.3 TCP層があれば取り出す
	// 4.4 TCPのSrcPort, DstPortをEventに入れる
	// 4.5 TCPがなくてUDP層があれば取り出す
	// 4.6 UDPのSrcPort, DstPortをEventに入れる
	// 4.7 完成したEventを返す

	// Event, event, events について
	// event: 1パケット分のEventを入れる
	// events: 複数パケット分のEvent一覧 (必須ではないが、わかりやすくするために)

	file, err := os.Open(e.PcapPath)
	if err != nil {
		return []Event{
			{
				Type:  "pcap_open_failed",
				Error: err.Error(),
			},
		}
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return []Event{
			{
				Type:  "pcap_reader_failed",
				Error: err.Error(),
			},
		}
	}
	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	events := []Event{}

	for i := 0; i < e.Limit; i++ {
		packet, err := packetSource.NextPacket()
		if err != nil {
			break
		}
		event := packetToEvent(packet)
		events = append(events, event)
	}
	if len(events) == 0 {
		return []Event{
			{
				Type:    "no_packets_read",
				Message: "no packets were read from pcap",
			},
		}
	}
	return events
}

func dnsTypeName(t layers.DNSType) string {
	switch int(t) {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 33:
		return "SRV"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	default:
		return t.String()
	}
}

func packetToEvent(packet gopacket.Packet) Event {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return Event{
			Type:    "packet_observed",
			Message: "IPv4 layer not found",
		}
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return Event{
			Type:  "packet_parse_failed",
			Error: "failed to parse IPv4 layer",
		}
	}
	localIP, remoteIP := localRemoteIP(ip.SrcIP, ip.DstIP)
	event := Event{
		Type:      "packet_observed",
		SrcIP:     ip.SrcIP.String(),
		DstIP:     ip.DstIP.String(),
		Protocol:  ip.Protocol.String(),
		Layers:    []string{"IPv4"},
		Direction: detectDirection(ip.SrcIP, ip.DstIP),
		LocalIP:   localIP,
		RemoteIP:  remoteIP,
		Message:   packet.Metadata().Timestamp.String(),
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return Event{
				Type:  "packet_parse_failed",
				Error: "failed to parse TCP layer",
			}
		}
		flags := []string{}

		if tcp.SYN {
			flags = append(flags, "SYN")
		}
		if tcp.ACK {
			flags = append(flags, "ACK")
		}
		if tcp.FIN {
			flags = append(flags, "FIN")
		}
		if tcp.RST {
			flags = append(flags, "RST")
		}
		event.TCPFlags = strings.Join(flags, ", ") // スライドに対して、その合間に指定した文字を入れ込むことができる
		event.SrcPort = strconv.Itoa(int(tcp.SrcPort))
		event.DstPort = strconv.Itoa(int(tcp.DstPort))
		event.Layers = append(event.Layers, "TCP")
		payload := string(tcp.Payload)

		if strings.HasPrefix(payload, "GET ") ||
			strings.HasPrefix(payload, "POST ") ||
			strings.HasPrefix(payload, "PUT ") ||
			strings.HasPrefix(payload, "DELETE ") ||
			strings.HasPrefix(payload, "HEAD ") {
			event.Layers = append(event.Layers, "HTTP")
			event.Service = "http"
			event.Risk = append(event.Risk, "http_plaintext")

			firstLine := strings.SplitN(payload, "\r\n", 2)[0]
			// payloadの一行目の改行(\r\n)までと二行目以降で分けて、その一つ目(一行目の開業まで)を取得している
			parts := strings.Fields(firstLine)
			// 空白のトロこで細かく切り分けている GET /index.html HTTP/1.1だったら、「GET」, 「/index.html」, 「HTTP/1.1」で分かれる

			if len(parts) >= 2 {
				event.HTTPMethod = parts[0] // GETとかを入れる
				event.HTTPPath = parts[1]   // HTMLのpathを入れる
			}
			lines := strings.Split(payload, "\r\n")
			for _, line := range lines {
				lowerLine := strings.ToLower(line)

				if strings.HasPrefix(lowerLine, "host:") {
					event.HTTPHost = strings.TrimSpace(line[len("Host:"):])
				}
				if strings.HasPrefix(lowerLine, "user-agent:") {
					event.HTTPUserAgent = strings.TrimSpace(line[len("User-Agent:"):])
				}
				if strings.HasPrefix(lowerLine, "authorization:") {
					event.HTTPSensitiveHeaders = append(event.HTTPSensitiveHeaders, "Authorization")
				}
				if strings.HasPrefix(lowerLine, "cookie:") {
					event.HTTPSensitiveHeaders = append(event.HTTPSensitiveHeaders, "Cookie")
				}
				if strings.HasPrefix(lowerLine, "x-api-key:") {
					event.HTTPSensitiveHeaders = append(event.HTTPSensitiveHeaders, "X-API-Key")
				}
			}
			if len(event.HTTPSensitiveHeaders) > 0 {
				event.Risk = append(event.Risk, "http_sensitive_header")
			}
		}
		event.LocalPort, event.RemotePort = localRemotePort(event.Direction, event.SrcPort, event.DstPort)
	} else {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, ok := udpLayer.(*layers.UDP)
			if !ok {
				return Event{
					Type:  "packet_parse_failed",
					Error: "failed to parse UDP layer",
				}
			}
			event.SrcPort = strconv.Itoa(int(udp.SrcPort))
			event.DstPort = strconv.Itoa(int(udp.DstPort))
			event.Layers = append(event.Layers, "UDP")
			event.LocalPort, event.RemotePort = localRemotePort(event.Direction, event.SrcPort, event.DstPort)

			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer != nil {
				dns, ok := dnsLayer.(*layers.DNS)
				if !ok {
					return Event{
						Type:  "packet_parse_failed",
						Error: "failed to parse DNS layer",
					}
				}
				event.Layers = append(event.Layers, "DNS")
				event.DNSIsResponse = dns.QR // false: DNS query, true: DNS response　QRはquestion or response だね
				if len(dns.Questions) > 0 {
					event.DNSQuery = string(dns.Questions[0].Name)
					event.DNSQueryType = dnsTypeName(dns.Questions[0].Type)
					event.DNSQueryTypeCode = int(dns.Questions[0].Type)
				}
				if len(dns.Answers) > 0 {
					for _, answer := range dns.Answers {
						if answer.IP != nil {
							event.DNSAnswers = append(event.DNSAnswers, answer.IP.String())
						}
					}
				}
			}
		}
	}
	if event.Service == "" {
		event.Service = detectService(event.Protocol, event.LocalPort, event.RemotePort)
	}
	return event
}

func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return false
}

func detectDirection(srcIP net.IP, dstIP net.IP) string {
	if srcIP.IsLoopback() && dstIP.IsLoopback() {
		return "loopback"
	}
	srcPrivate := isPrivateIP(srcIP)
	dstPrivate := isPrivateIP(dstIP)

	if srcPrivate && !dstPrivate {
		return "outbound"
	}
	if !srcPrivate && dstPrivate {
		return "inbound"
	}
	if srcPrivate && dstPrivate {
		return "internal"
	}
	return "external"
}

func localRemoteIP(srcIP net.IP, dstIP net.IP) (string, string) {
	srcPrivate := isPrivateIP(srcIP)
	dstPrivate := isPrivateIP(dstIP)
	if srcIP.IsLoopback() && dstIP.IsLoopback() {
		return srcIP.String(), dstIP.String()
	}
	if srcPrivate && !dstPrivate {
		return srcIP.String(), dstIP.String()
	}
	if !srcPrivate && dstPrivate {
		return dstIP.String(), srcIP.String()
	}
	if srcPrivate && dstPrivate {
		return srcIP.String(), dstIP.String()
	}
	return "", ""
}

func localRemotePort(direction string, srcPort string, dstPort string) (string, string) {
	if direction == "outbound" || direction == "loopback" || direction == "internal" {
		return srcPort, dstPort
	}
	if direction == "inbound" {
		return dstPort, srcPort
	}
	return "", ""
}

func detectService(protocol string, localPort string, remotePort string) string {
	switch protocol {
	case "TCP":
		if remotePort == "80" || localPort == "80" {
			return "http"
		}
		if remotePort == "443" || localPort == "443" {
			return "https"
		}
		if remotePort == "22" || localPort == "22" {
			return "ssh"
		}
		if remotePort == "23" || localPort == "23" {
			return "telnet"
		}
		if remotePort == "8080" || localPort == "8080" {
			return "http-alt"
		}
	case "UDP":
		if remotePort == "53" || localPort == "53" {
			return "dns"
		}
		if remotePort == "123" || localPort == "123" {
			return "ntp"
		}
		if remotePort == "1900" || localPort == "1900" {
			return "ssdp"
		}

	}
	return ""
}

func Run() []Event {
	engine := NewEngine("sample/test.pcap", 10)
	return engine.Run()
}
