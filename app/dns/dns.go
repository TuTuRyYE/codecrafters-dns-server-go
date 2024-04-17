package dns

import (
	"bytes"
	"encoding/binary"
)

type Message struct {
	Header   Header
	Question Question
}

func (m *Message) Binary() ([]byte, error) {
	b := []byte{}

	h, err := m.Header.Binary()
	if err != nil {
		return nil, err
	}

	q, err := m.Header.Binary()
	if err != nil {
		return nil, err
	}

	b = append(b, h...)
	b = append(b, q...)

	return b, nil
}

type Header struct {
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

func (h *Header) FlagsToUint16() uint16 {
	var flags uint16

	if h.QR {
		flags = flags | (1 << 15)
	}

	flags = flags | (h.OPCODE << 11)

	if h.AA {
		flags = flags | (1 << 10)
	}

	if h.TC {
		flags = flags | (1 << 9)
	}

	if h.RD {
		flags = flags | (1 << 8)
	}

	if h.RA {
		flags = flags | (1 << 7)
	}

	flags = flags | (h.Z << 4)

	flags = flags | h.RCode

	return flags
}

func (h *Header) Binary() ([]byte, error) {
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

type DomainLabel struct {
	Length  byte
	Content []byte
}

type Question struct {
	DomainLabels []DomainLabel
	Type         [2]byte
	Class        [2]byte
}

func (q *Question) Binary() ([]byte, error) {
	buf := new(bytes.Buffer)

	for _, v := range q.DomainLabels {
		buf.WriteByte(v.Length)
		buf.Write(v.Content)
	}

	binary.Write(buf, binary.BigEndian, q.Type)
	binary.Write(buf, binary.BigEndian, q.Class)

	return buf.Bytes(), nil
}
