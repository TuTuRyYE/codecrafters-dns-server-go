package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
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
		header := DNSHeader{
			ID: 1234,
		}

		b, _ := header.ToBinary()

		fmt.Printf("%b", b)

		_, err = udpConn.WriteToUDP(b, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

const Test = 0x101

type DNSMessage struct {
	Header [12]byte
}

type DNSHeader struct {
	ID      uint16
	QR      bool
	OPCODE  uint16
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint16
	RCode   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h *DNSHeader) FlagsToUint16() uint16 {
	return uint16(1 << 15)
}

func (h *DNSHeader) ToBinary() ([]byte, error) {
	values := []uint16{
		h.ID,
		h.FlagsToUint16(),
		h.QDCount,
		h.ANCount,
		h.NSCount,
		h.ARCount,
	}

	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.BigEndian, values)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
