package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDNS_parseHeaderFlags(t *testing.T) {
	tests := []struct {
		Name   string
		Input  []byte
		Output *Header
	}{
		{Name: "qr", Input: []byte{128, 0}, Output: &Header{QR: true}},
		{Name: "opcore", Input: []byte{72, 0}, Output: &Header{OPCODE: 9}},
		{Name: "aa", Input: []byte{4, 0}, Output: &Header{AA: true}},
		{Name: "tc", Input: []byte{2, 0}, Output: &Header{TC: true}},
		{Name: "rd & ra", Input: []byte{1, 128}, Output: &Header{RD: true, RA: true}},
		{Name: "z is 5 & rcode is 12", Input: []byte{0, (5 << 4) + 12}, Output: &Header{Z: 5, RCode: 12}},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			header, err := parseHeaderFlags(test.Input)
			assert.NoError(t, err)
			assert.Equal(t, test.Output, header)
		})
	}
}
