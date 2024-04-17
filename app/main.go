package main

import (
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/dns"
)

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
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

		// Create an empty response
		message := dns.Message{
			Header: dns.Header{
				ID:      1234,
				QR:      true,
				QDCount: 1,
				ANCount: 1,
			},
			Question: dns.Question{
				Name: []dns.DomainLabel{
					{Length: 12, Content: []byte("codecrafters")},
					{Length: 2, Content: []byte("io")},
				},
				Type:  [2]byte{0, 1},
				Class: [2]byte{0, 1},
			},
			Answer: dns.Answer{
				Name: []dns.DomainLabel{
					{Length: 12, Content: []byte("codecrafters")},
					{Length: 2, Content: []byte("io")},
				},
				Type:     [2]byte{0, 1},
				Class:    [2]byte{0, 1},
				TTL:      [4]byte{0, 0, 0, 60},
				RDLength: [2]byte{0, 4},
				RData:    []byte{8, 8, 8, 8},
			},
		}

		b, _ := message.Binary()

		fmt.Printf("%o", b)

		_, err = udpConn.WriteToUDP(b, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
