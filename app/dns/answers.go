package dns

import (
	"bytes"
	"encoding/binary"
)

type Answer struct {
	Name     []DomainLabel
	Type     uint16
	Class    uint16
	TTL      uint32
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

func ParseAnswers(anCount int, startIndex int, data []byte) (answers []Answer, nextSectionStartIndex int, err error) {
	for i := 0; i < anCount; i++ {
		domainLabels := []DomainLabel{}
		startIndex, err = ParseDomainLabels(startIndex, data, &domainLabels)
		if err != nil {
			return nil, 0, err
		}

		a := Answer{Name: domainLabels, Type: 1, Class: 1}

		a.TTL = binary.BigEndian.Uint32(data[startIndex : startIndex+4])
		a.RDLength = binary.BigEndian.Uint16(data[startIndex+4 : startIndex+6])
		a.RData = []byte{data[startIndex+6], data[startIndex+7], data[startIndex+8], data[startIndex+9]}

		startIndex = startIndex + 10

		answers = append(answers, a)
	}

	nextSectionStartIndex = startIndex

	return
}
