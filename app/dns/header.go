package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
)

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
	if len(b) < 12 {
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



