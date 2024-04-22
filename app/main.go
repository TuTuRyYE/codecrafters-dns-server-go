package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/dns"
)

var resolver string

func main() {
	flag.StringVar(&resolver, "resolver", "", "")
	flag.Parse()

	if resolver != "" {
		fmt.Printf("Fetching to resolver: %s", resolver)
	}

	udpConn, err := openDNSSocket()
	if err != nil {
		fmt.Println("failed to open udp conn:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		message, err := dns.ParseMessage(buf[:size])
		if err != nil {
			fmt.Println("Error parsing message:", err)
			break
		}

		newMessage, err := message.ChallengeResolver(resolver)
		if err != nil {
			fmt.Println("Error parsing message:", err)
			break
		}

		nb, _ := newMessage.Binary()

		_, err = udpConn.WriteToUDP(nb, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

func openDNSSocket() (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen UDP address: %w", err)
	}

	return udpConn, nil
}
