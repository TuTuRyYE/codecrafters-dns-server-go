package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type DomainLabel struct {
	Length  byte
	Content []byte
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
