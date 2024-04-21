package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type Message struct {
	Header    Header
	Questions []Question
	Answers   []Answer
}

func (m *Message) Binary() ([]byte, error) {
	b := []byte{}

	h, err := m.Header.Binary()
	if err != nil {
		return nil, err
	}

	b = append(b, h...)

	for _, q := range m.Questions {
		qb, err := q.Binary()
		if err != nil {
			return nil, err
		}

		b = append(b, qb...)
	}

	for _, a := range m.Answers {
		ab, err := a.Binary()
		if err != nil {
			return nil, err
		}

		b = append(b, ab...)
	}

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

func ParseHeader(b []byte) (*Header, error) {
	if len(b) != 12 {
		return nil, errors.New("headers are 12 bytes long")
	}

	header, err := parseHeaderFlags(b[2:4])
	if err != nil {
		return nil, err
	}

	header.ID = binary.BigEndian.Uint16(b[0:2])
	header.QDCount = binary.BigEndian.Uint16(b[4:6])
	header.ANCount = binary.BigEndian.Uint16(b[6:8])
	header.NSCount = binary.BigEndian.Uint16(b[8:10])
	header.ARCount = binary.BigEndian.Uint16(b[10:12])

	return header, nil
}

func parseHeaderFlags(b []byte) (*Header, error) {
	if len(b) != 2 {
		return nil, errors.New("header flags are encoded on 2 bytes")
	}

	flags := binary.BigEndian.Uint16(b)

	header := &Header{}

	qr := uint16(1 << 15)
	if (flags & qr) == qr {
		header.QR = true
	}

	header.OPCODE = flags & (15 << 11) >> 11

	aa := uint16(1 << 10)
	if (flags & aa) == aa {
		header.AA = true
	}

	tc := uint16(1 << 9)
	if (flags & tc) == tc {
		header.TC = true
	}

	rd := uint16(1 << 8)
	if (flags & rd) == rd {
		header.RD = true
	}

	ra := uint16(1 << 7)
	if (flags & ra) == ra {
		header.RA = true
	}

	header.Z = flags & (7 << 4) >> 4

	header.RCode = flags & 15

	return header, nil
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

func ParseDomainLabels(startIndex int, data []byte, domainLabels *[]DomainLabel) (nextQuestionIndex int, err error) {
	if len(data) < 3 || startIndex >= len(data) {
		return 0, errors.New("not enough data")
	}

	if data[startIndex]&0xC0 == 0xC0 {
		pointer := binary.BigEndian.Uint16(data[startIndex : startIndex+2])
		offset := int(pointer) & 0x3FFF //filtering offset value
		return ParseDomainLabels(offset, data, domainLabels)
	}

	if data[startIndex] == 0 {
		return startIndex + 5, nil
	}

	length := data[startIndex]
	*domainLabels = append(*domainLabels, DomainLabel{Length: length, Content: data[startIndex+1 : startIndex+int(length)+1]})

	return ParseDomainLabels(startIndex+int(length)+1, data, domainLabels)
}

func ParseQuestions(qdCount int, data []byte) (questions []Question, err error) {
	//data is expected to be complete payload, with header having a size of 12
	nextQuestionIndex := 12
	for i := 0; i < qdCount; i++ {
		domainLabels := []DomainLabel{}
		nextQuestionIndex, err = ParseDomainLabels(nextQuestionIndex, data, &domainLabels)
		if err != nil {
			return nil, err
		}
		questions = append(questions, Question{Name: domainLabels, Type: 1, Class: 1})
	}

	return
}

func (d *DomainLabel) Binary() ([]byte, error) {
	buf := new(bytes.Buffer)

	err := buf.WriteByte(d.Length)
	if err != nil {
		return nil, err
	}

	n, err := buf.Write(d.Content)
	if err != nil {
		return nil, err
	}

	if n != len(d.Content) {
		return nil, errors.New("should have written len of content into buf")
	}

	return buf.Bytes(), nil
}

type Question struct {
	Name  []DomainLabel
	Type  uint16
	Class uint16
}

func (q *Question) Binary() ([]byte, error) {
	buf := new(bytes.Buffer)

	for _, domainLabel := range q.Name {
		b, err := domainLabel.Binary()
		if err != nil {
			return nil, err
		}

		buf.Write(b)
	}

	buf.WriteByte(0)

	binary.Write(buf, binary.BigEndian, q.Type)
	binary.Write(buf, binary.BigEndian, q.Class)

	return buf.Bytes(), nil
}

type Answer struct {
	Name     []DomainLabel
	Type     uint16
	Class    uint16
	TTL      [4]byte
	RDLength uint16
	RData    []byte
}

func (a *Answer) Binary() ([]byte, error) {
	buf := new(bytes.Buffer)

	for _, domainLabel := range a.Name {
		b, err := domainLabel.Binary()
		if err != nil {
			return nil, err
		}

		buf.Write(b)
	}

	buf.WriteByte(0)

	binary.Write(buf, binary.BigEndian, a.Type)
	binary.Write(buf, binary.BigEndian, a.Class)
	binary.Write(buf, binary.BigEndian, a.TTL)
	binary.Write(buf, binary.BigEndian, a.RDLength)
	binary.Write(buf, binary.BigEndian,
		a.RData[:a.RDLength],
	)

	return buf.Bytes(), nil
}
