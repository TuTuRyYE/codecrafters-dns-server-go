package dns

import (
	"fmt"
	"net"
)

type Message struct {
	Header    Header
	Questions []Question
	Answers   []Answer
}

func ParseMessage(data []byte) (*Message, error) {
	m := &Message{}

	header, err := ParseHeader(data[:12])
	if err != nil {
		return nil, err
	}

	questions, nextSectionStartIndex, err := ParseQuestions(int(header.QDCount), data)
	if err != nil {
		return nil, err
	}

	answers, _, err := ParseAnswers(int(header.ANCount), nextSectionStartIndex, data)
	if err != nil {
		return nil, err
	}

	header.QR = true

	if header.OPCODE != 0 {
		header.RCode = 4
	} else {
		header.RCode = 0
	}

	m.Header = *header

	m.Questions = questions

	m.Answers = answers

	m.Header.ANCount = uint16(len(answers))
	m.Header.QDCount = uint16(len(questions))

	return m, nil
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

func (m *Message) ChallengeResolver(resolver string) (*Message, error) {
	conn, err := net.Dial("udp", resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	messageToReturn := &Message{
		Header:    m.Header,
		Answers:   []Answer{},
		Questions: []Question{},
	}

	for _, q := range m.Questions {
		m := &Message{
			Header:    Header{ID: m.Header.ID, QR: false, QDCount: 1},
			Questions: []Question{q},
		}

		b, err := m.Binary()
		if err != nil {
			return nil, err
		}

		_, err = conn.Write(b)
		if err != nil {
			return nil, err
		}

		buf := make([]byte, 512)

		newSize, err := conn.Read(buf)
		if err != nil {
			fmt.Println("failed to read to newbuf: ", err)
			break
		}

		responseMessage, err := ParseMessage(buf[:newSize])
		if err != nil {
			fmt.Println("Error parsing message:", err)
			break
		}

		messageToReturn.Answers = append(messageToReturn.Answers, responseMessage.Answers...)
		messageToReturn.Questions = append(messageToReturn.Questions, responseMessage.Questions...)
	}

	messageToReturn.Header.ANCount = uint16(len(messageToReturn.Answers))
	messageToReturn.Header.QDCount = uint16(len(messageToReturn.Questions))

	return messageToReturn, nil
}
