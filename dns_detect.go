package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len int32 = 65535
	handle       *pcap.Handle
	timeout      time.Duration = -1 * time.Second
	err          error
	promiscous   bool = false
	strPattern   *string
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var interfaceName = devices[0].Name

	fileFlag := flag.String("r", "", "a string")
	interf := flag.String("i", interfaceName, "a string")
	strPattern = flag.String("s", "", "a string")

	flag.Parse()

	fmt.Println(*strPattern)

	var filter = flag.Arg(0)

	if *fileFlag != "" {
		// Opening pcap file
		if handle, err = pcap.OpenOffline(*fileFlag); err != nil {
			panic(err)
		}
	} else {
		// Opening device for Live Capture
		if handle, err = pcap.OpenLive(*interf, snapshot_len, promiscous, timeout); err != nil {
			panic(err)
		}
		fmt.Println("Reading from interface ", *interf)

	}

	if filter != "" {
		// Setting a BPF filter given by the user for capturing a subset of the traffic
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Only capturing packets with filter ", filter)
	}
	transaction_id_map := make(map[uint16]net.IP)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//Going through the packets one by one
	for Packet := range packetSource.Packets() {

		//Checking the DNS Layer of the packet
		dns_layer := Packet.Layer(layers.LayerTypeDNS)

		if dns_layer != nil {
			dns, _ := dns_layer.(*layers.DNS)

			if dns.QR == true {

				_, id := transaction_id_map[dns.ID]
				if id && dns.ANCount > 0 {
					if !reflect.DeepEqual(transaction_id_map[dns.ID], dns.Answers[0].IP) {

						fmt.Printf("DNS Poisoning Attempt for id %v and domain %s \n", dns.ID, dns.Questions[0].Name)

						fmt.Printf("Answer (1) : %v \n", transaction_id_map[dns.ID])

						fmt.Printf("Answer (2) : %v \n", dns.Answers[0].IP)
					}

				} else {
					for i := 0; i < int(dns.ANCount); i++ {
						transaction_id_map[dns.ID] = append(dns.Answers[i].IP)

					}

				}

			}

		}
	}
}
