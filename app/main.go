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

		receivedHeader, err := dns.ParseHeader(buf[:12])
		if err != nil {
			fmt.Println("Error parsing header:", err)
			break
		}

		questions, err := dns.ParseQuestions(int(receivedHeader.QDCount), buf[:size])
		if err != nil {
			fmt.Println("Error parsing domain labels:", err)
			break
		}

		answers := []dns.Answer{}
		for _, q := range questions {
			answers = append(answers, dns.Answer{
				Name:     q.Name,
				Class:    q.Class,
				Type:     q.Type,
				TTL:      [4]byte{0, 0, 0, 60},
				RDLength: 4,
				RData:    []byte{8, 8, 8, 8}})
		}

		// Create an empty response
		message := dns.Message{
			Header: dns.Header{
				ID:     receivedHeader.ID,
				QR:     true,
				OPCODE: receivedHeader.OPCODE,
				RD:     receivedHeader.RD,
				RCode: func() uint16 {
					if receivedHeader.OPCODE != 0 {
						return 4
					}
					return 0
				}(),
				QDCount: func() uint16 {
					if receivedHeader.QDCount == 0 {
						return 1
					}
					return receivedHeader.QDCount
				}(),
				ANCount: func() uint16 {
					if receivedHeader.QDCount == 0 {
						return 1
					}
					return receivedHeader.QDCount
				}(),
			},
			Questions: questions,
			Answers:   answers,
		}

		b, _ := message.Binary()

		_, err = udpConn.WriteToUDP(b, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
