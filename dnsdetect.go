package main

import (
	"bytes"
	"container/list"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	gopacket "github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
	pcap "github.com/google/gopacket/pcap"
)

//strcut for queue
type qapacket struct {
	packettime time.Time
	qa         bool //false for ques and true for ans
	question   layers.DNSQuestion
	answers    []layers.DNSResourceRecord
	id         uint16
}

//hashmaps to maintain count of questions and answers
var questionmap = make(map[uint16]int)
var answermap = make(map[uint16]int)

//func to remove earlier timestamps to maintin 1 min packets
func removeEarlierTimestamps(que *list.List) {
	//get last element timestamp
	pack := que.Back().Value.(qapacket)
	ltime := pack.packettime
	added1 := ltime.Add(time.Second * 20)
	for e := que.Front(); e != nil; e = e.Next() {
		if e.Value.(qapacket).packettime.After(added1) {
			//reduce the count from hashmaps
			if pack.qa == false {
				questionmap[pack.id]--
			}
			if pack.qa == true {
				answermap[pack.id]--
			}
			que.Remove(e)
		}
	}
	//now que will be having only one packets with 1 min timeframe

}

// Execute function for read from pcap
func Execute_Read(fileI string, bpf string) {
	var protocol = ""
	var dstPort = ""
	var srcPort = ""
	var breakexec = false
	//create a queue for maintiaining packets which are in  1 min time frame
	packetq := list.New()

	if handle, err := pcap.OpenOffline(fileI); err != nil {
		fmt.Println("Cannot find the file mentioned")
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
				srcPort = re.FindString((udp.SrcPort).String())
				dstPort = re.FindString((udp.DstPort).String())
			}

			if (dstPort == "53" || srcPort == "53") && protocol == "UDP" {
				if dnslayer := packet.Layer(layers.LayerTypeDNS); dnslayer != nil {
					dns_l, _ := dnslayer.(*layers.DNS)
					//create a struct and store the packet data until that time frame then check and detect
					pack := qapacket{packettime: packet.Metadata().Timestamp,
						qa:       dns_l.QR,
						question: dns_l.Questions[0],
						answers:  dns_l.Answers,
						id:       dns_l.ID}
					//add to queue
					packetq.PushBack(pack)
					//add to hashmaps for maintaining counts of questions and answers
					if pack.qa == false {
						if _, exists := questionmap[pack.id]; exists {
							questionmap[pack.id]++
						} else {
							questionmap[pack.id] = 1
						}
					} else if pack.qa == true {
						if _, exists := answermap[pack.id]; exists {
							answermap[pack.id]++
						} else {
							answermap[pack.id] = 1
						}
					}

					//remove from queue and hashmaps which are not in timeframe
					removeEarlierTimestamps(packetq)

					//check in packets if there are two responses with same id and question
					for e := packetq.Front(); e.Next() != nil; e = e.Next() {
						if pack.id == e.Value.(qapacket).id {
							if pack.qa == true && e.Value.(qapacket).qa == true {
								if string(pack.question.Name) == string(e.Value.(qapacket).question.Name) {
									//count number of questions and answers
									if answermap[pack.id] > questionmap[pack.id] {
										//spoof is detected
										fmt.Println((pack.packettime).String() + "   DNS poisoning attempt")
										fmt.Print("TXID ")
										fmt.Println("0x" + strconv.FormatInt(int64(pack.id), 16))
										fmt.Println("Request  " + string(pack.question.Name))
										//make answer for ips
										answer1 := ""
										answer2 := ""
										for a := 0; a < len(pack.answers); a++ {
											if pack.answers[a].IP != nil {
												if a+1 == len(pack.answers) {
													answer1 = answer1 + (pack.answers[a].IP).String()
												} else {
													answer1 = answer1 + (pack.answers[a].IP).String() + " :: "
												}
											}

										}
										for b := 0; b < len(e.Value.(qapacket).answers); b++ {
											if e.Value.(qapacket).answers[b].IP != nil {
												if b+1 == len(e.Value.(qapacket).answers) {
													answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String()
												} else {
													answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String() + " :: "
												}
											}

										}
										fmt.Print("Answer1 ")
										fmt.Println(answer1)
										fmt.Print("Answer2 ")
										fmt.Println(answer2)
										fmt.Println("\n")
										//fmt.Println("question")
										//fmt.Println(questionmap[pack.id])
										//fmt.Println("answer")
										//fmt.Println(answermap[pack.id])
										break
									}
									if len(pack.answers) > 0 && len(e.Value.(qapacket).answers) > 0 {
										if len(pack.answers) != len(e.Value.(qapacket).answers) {
											fmt.Println((pack.packettime).String() + "   DNS poisoning attempt")
											fmt.Print("TXID ")
											fmt.Println("0x" + strconv.FormatInt(int64(pack.id), 16))
											fmt.Println("Request  " + string(pack.question.Name))
											//make answer for ips
											answer1 := ""
											answer2 := ""
											for a := 0; a < len(pack.answers); a++ {
												if pack.answers[a].IP != nil {
													if a+1 == len(pack.answers) {
														answer1 = answer1 + (pack.answers[a].IP).String()
													} else {
														answer1 = answer1 + (pack.answers[a].IP).String() + " :: "
													}
												}
											}
											for b := 0; b < len(e.Value.(qapacket).answers); b++ {
												if e.Value.(qapacket).answers[b].IP != nil {
													if b+1 == len(e.Value.(qapacket).answers) {
														answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String()
													} else {
														answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String() + " :: "
													}
												}
											}
											fmt.Print("Answer1 ")
											fmt.Println(answer1)
											fmt.Print("Answer2 ")
											fmt.Println(answer2)
											fmt.Println("\n")
											//fmt.Println("question")
											//fmt.Println(questionmap[pack.id])
											//fmt.Println("answer")
											//fmt.Println(answermap[pack.id])
											break
										} else {
											//for one answer comparision
											if len(pack.answers) == 1 && len(e.Value.(qapacket).answers) == 1 {
												if (bytes.Compare(pack.answers[0].Data, e.Value.(qapacket).answers[0].Data)) != 0 {
													fmt.Println((pack.packettime).String() + "   DNS poisoning attempt")
													fmt.Print("TXID ")
													fmt.Println("0x" + strconv.FormatInt(int64(pack.id), 16))
													fmt.Println("Request  " + string(pack.question.Name))
													//make answer for ips
													answer1 := ""
													answer2 := ""
													for a := 0; a < len(pack.answers); a++ {
														if pack.answers[a].IP != nil {
															if a+1 == len(pack.answers) {
																answer1 = answer1 + (pack.answers[a].IP).String()
															} else {
																answer1 = answer1 + (pack.answers[a].IP).String() + " :: "
															}
														}
													}
													for b := 0; b < len(e.Value.(qapacket).answers); b++ {
														if e.Value.(qapacket).answers[b].IP != nil {
															if b+1 == len(e.Value.(qapacket).answers) {
																answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String()
															} else {
																answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String() + " :: "
															}
														}
													}
													fmt.Print("Answer1 ")
													fmt.Println(answer1)
													fmt.Print("Answer2 ")
													fmt.Println(answer2)
													fmt.Println("\n")
													//fmt.Println("question")
													//fmt.Println(questionmap[pack.id])
													//fmt.Println("answer")
													//fmt.Println(answermap[pack.id])
													break
												}
											} else {
												//if lengths are equal and greater than 1
												//check if both the answers have the same ip addresses to not raise false positives
												//simple array serach will fal because the order of answers could be different
												for i := 0; i < len(pack.answers); i++ {
													for j := 0; j < len(e.Value.(qapacket).answers); j++ {
														if (bytes.Compare(pack.answers[i].Data, e.Value.(qapacket).answers[j].Data)) != 0 {
															if j+1 == len(e.Value.(qapacket).answers) {
																//could not fing the ip in second array.. so different answer so raise alert
																fmt.Println((pack.packettime).String() + "   DNS poisoning attempt")
																fmt.Print("TXID ")
																fmt.Println("0x" + strconv.FormatInt(int64(pack.id), 16))
																fmt.Println("Request  " + string(pack.question.Name))
																//make answer for ips
																answer1 := ""
																answer2 := ""
																for a := 0; a < len(pack.answers); a++ {
																	if pack.answers[a].IP != nil {
																		if a+1 == len(pack.answers) {
																			answer1 = answer1 + (pack.answers[a].IP).String()
																		} else {
																			answer1 = answer1 + (pack.answers[a].IP).String() + " :: "
																		}
																	}
																}
																for b := 0; b < len(e.Value.(qapacket).answers); b++ {
																	if e.Value.(qapacket).answers[b].IP != nil {
																		if b+1 == len(e.Value.(qapacket).answers) {
																			answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String()
																		} else {
																			answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String() + " :: "
																		}
																	}
																}
																fmt.Print("Answer1 ")
																fmt.Println(answer1)
																fmt.Print("Answer2 ")
																fmt.Println(answer2)
																fmt.Println("\n")
																//fmt.Println("question")
																//fmt.Println(questionmap[pack.id])
																//fmt.Println("answer")
																//fmt.Println(answermap[pack.id])
																breakexec = true
															}
														} else {
															continue
														}
													}
													if breakexec == true {
														break
													}
												}
											}
										}

									}

								}

							}
						}
						if breakexec == true {
							break
						}
					}

				}
			}
		}
	}
}

//Execute function for open live
func Execute_Live(interfaceI string, bpf string) {
	var protocol = ""
	var dstPort = ""
	var srcPort = ""
	var breakexec = false
	//create a queue for maintiaining packets which are in  1 min time frame
	packetq := list.New()

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
				srcPort = re.FindString((udp.SrcPort).String())
				dstPort = re.FindString((udp.DstPort).String())
			}

			if (dstPort == "53" || srcPort == "53") && protocol == "UDP" {
				if dnslayer := packet.Layer(layers.LayerTypeDNS); dnslayer != nil {
					dns_l, _ := dnslayer.(*layers.DNS)
					//create a struct and store the packet data until that time frame then check and detect
					pack := qapacket{packettime: packet.Metadata().Timestamp,
						qa:       dns_l.QR,
						question: dns_l.Questions[0],
						answers:  dns_l.Answers,
						id:       dns_l.ID}
					//add to queue
					packetq.PushBack(pack)
					//add to hashmaps for maintaining counts of questions and answers
					if pack.qa == false {
						if _, exists := questionmap[pack.id]; exists {
							questionmap[pack.id]++
						} else {
							questionmap[pack.id] = 1
						}
					} else if pack.qa == true {
						if _, exists := answermap[pack.id]; exists {
							answermap[pack.id]++
						} else {
							answermap[pack.id] = 1
						}
					}

					//remove from queue and hashmaps which are not in timeframe
					removeEarlierTimestamps(packetq)

					//check in packets if there are two responses with same id and question
					for e := packetq.Front(); e.Next() != nil; e = e.Next() {
						if pack.id == e.Value.(qapacket).id {
							if pack.qa == true && e.Value.(qapacket).qa == true {
								if string(pack.question.Name) == string(e.Value.(qapacket).question.Name) {
									//count number of questions and answers
									if answermap[pack.id] > questionmap[pack.id] {
										//spoof is detected
										fmt.Println((pack.packettime).String() + "   DNS poisoning attempt")
										fmt.Print("TXID ")
										fmt.Println("0x" + strconv.FormatInt(int64(pack.id), 16))
										fmt.Println("Request  " + string(pack.question.Name))
										//make answer for ips
										answer1 := ""
										answer2 := ""
										for a := 0; a < len(pack.answers); a++ {
											if pack.answers[a].IP != nil {
												if a+1 == len(pack.answers) {
													answer1 = answer1 + (pack.answers[a].IP).String()
												} else {
													answer1 = answer1 + (pack.answers[a].IP).String() + " :: "
												}
											}

										}
										for b := 0; b < len(e.Value.(qapacket).answers); b++ {
											if e.Value.(qapacket).answers[b].IP != nil {
												if b+1 == len(e.Value.(qapacket).answers) {
													answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String()
												} else {
													answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String() + " :: "
												}
											}

										}
										fmt.Print("Answer1 ")
										fmt.Println(answer1)
										fmt.Print("Answer2 ")
										fmt.Println(answer2)
										fmt.Println("\n")
										//fmt.Println("question")
										//fmt.Println(questionmap[pack.id])
										//fmt.Println("answer")
										//fmt.Println(answermap[pack.id])
										break
									}
									if len(pack.answers) > 0 && len(e.Value.(qapacket).answers) > 0 {
										if len(pack.answers) != len(e.Value.(qapacket).answers) {
											fmt.Println((pack.packettime).String() + "   DNS poisoning attempt")
											fmt.Print("TXID ")
											fmt.Println("0x" + strconv.FormatInt(int64(pack.id), 16))
											fmt.Println("Request  " + string(pack.question.Name))
											//make answer for ips
											answer1 := ""
											answer2 := ""
											for a := 0; a < len(pack.answers); a++ {
												if pack.answers[a].IP != nil {
													if a+1 == len(pack.answers) {
														answer1 = answer1 + (pack.answers[a].IP).String()
													} else {
														answer1 = answer1 + (pack.answers[a].IP).String() + " :: "
													}
												}
											}
											for b := 0; b < len(e.Value.(qapacket).answers); b++ {
												if e.Value.(qapacket).answers[b].IP != nil {
													if b+1 == len(e.Value.(qapacket).answers) {
														answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String()
													} else {
														answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String() + " :: "
													}
												}
											}
											fmt.Print("Answer1 ")
											fmt.Println(answer1)
											fmt.Print("Answer2 ")
											fmt.Println(answer2)
											fmt.Println("\n")
											//fmt.Println("question")
											//fmt.Println(questionmap[pack.id])
											//fmt.Println("answer")
											//fmt.Println(answermap[pack.id])
											break
										} else {
											//for one answer comparision
											if len(pack.answers) == 1 && len(e.Value.(qapacket).answers) == 1 {
												if (bytes.Compare(pack.answers[0].Data, e.Value.(qapacket).answers[0].Data)) != 0 {
													fmt.Println((pack.packettime).String() + "   DNS poisoning attempt")
													fmt.Print("TXID ")
													fmt.Println("0x" + strconv.FormatInt(int64(pack.id), 16))
													fmt.Println("Request  " + string(pack.question.Name))
													//make answer for ips
													answer1 := ""
													answer2 := ""
													for a := 0; a < len(pack.answers); a++ {
														if pack.answers[a].IP != nil {
															if a+1 == len(pack.answers) {
																answer1 = answer1 + (pack.answers[a].IP).String()
															} else {
																answer1 = answer1 + (pack.answers[a].IP).String() + " :: "
															}
														}
													}
													for b := 0; b < len(e.Value.(qapacket).answers); b++ {
														if e.Value.(qapacket).answers[b].IP != nil {
															if b+1 == len(e.Value.(qapacket).answers) {
																answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String()
															} else {
																answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String() + " :: "
															}
														}
													}
													fmt.Print("Answer1 ")
													fmt.Println(answer1)
													fmt.Print("Answer2 ")
													fmt.Println(answer2)
													fmt.Println("\n")
													//fmt.Println("question")
													//fmt.Println(questionmap[pack.id])
													//fmt.Println("answer")
													//fmt.Println(answermap[pack.id])
													break
												}
											} else {
												//if lengths are equal and greater than 1
												//check if both the answers have the same ip addresses to not raise false positives
												//simple array serach will fal because the order of answers could be different
												for i := 0; i < len(pack.answers); i++ {
													for j := 0; j < len(e.Value.(qapacket).answers); j++ {
														if (bytes.Compare(pack.answers[i].Data, e.Value.(qapacket).answers[j].Data)) != 0 {
															if j+1 == len(e.Value.(qapacket).answers) {
																//could not fing the ip in second array.. so different answer so raise alert
																fmt.Println((pack.packettime).String() + "   DNS poisoning attempt")
																fmt.Print("TXID ")
																fmt.Println("0x" + strconv.FormatInt(int64(pack.id), 16))
																fmt.Println("Request  " + string(pack.question.Name))
																//make answer for ips
																answer1 := ""
																answer2 := ""
																for a := 0; a < len(pack.answers); a++ {
																	if pack.answers[a].IP != nil {
																		if a+1 == len(pack.answers) {
																			answer1 = answer1 + (pack.answers[a].IP).String()
																		} else {
																			answer1 = answer1 + (pack.answers[a].IP).String() + " :: "
																		}
																	}
																}
																for b := 0; b < len(e.Value.(qapacket).answers); b++ {
																	if e.Value.(qapacket).answers[b].IP != nil {
																		if b+1 == len(e.Value.(qapacket).answers) {
																			answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String()
																		} else {
																			answer2 = answer2 + (e.Value.(qapacket).answers[b].IP).String() + " :: "
																		}
																	}
																}
																fmt.Print("Answer1 ")
																fmt.Println(answer1)
																fmt.Print("Answer2 ")
																fmt.Println(answer2)
																fmt.Println("\n")
																//fmt.Println("question")
																//fmt.Println(questionmap[pack.id])
																//fmt.Println("answer")
																//fmt.Println(answermap[pack.id])
																breakexec = true
															}
														} else {
															continue
														}
													}
													if breakexec == true {
														break
													}
												}
											}
										}

									}

								}

							}
						}
						if breakexec == true {
							break
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
	var fileI string
	var bpf string
	// flags declaration using flag package
	flag.StringVar(&interfaceI, "i", "None", "Specify interface. Default is eth0")
	flag.StringVar(&fileI, "r", "None", "Include -r flag only if input is from a file")
	flag.Parse()
	//fmt.Println(interfaceI)
	//fmt.Println(fileI)
	//fmt.Println(stringI)

	//getting bpf filter statement
	//if even number of args are present then the bpf filter is givesn if odd number of args are present then not
	if len(os.Args)%2 == 0 {
		bpf = os.Args[len(os.Args)-1]
	} else {
		bpf = "None"
	}

	//fmt.Println("BPF filter" + bpf)
	var defdev = ""
	//switch either to file reader or live packet capture and call respective functions
	if fileI == "None" {
		//fmt.Println("This is live capture")
		if interfaceI == "None" {
			//getting the interface
			device_list, err := pcap.FindAllDevs()
			if err != nil {
				panic(err)
				os.Exit(1)
			}
			for _, device := range device_list {
				defdev = device.Name
				break
			}
		} else {
			defdev = interfaceI
		}
		//fmt.Println(defdev)
		Execute_Live(defdev, strings.ToLower(bpf))
	} else {
		//fmt.Println("This is an input from a pcap file")
		Execute_Read(fileI, strings.ToLower(bpf))
	}
}
