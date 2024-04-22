package dns

import (
	"bytes"
	"encoding/binary"
)

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

func ParseQuestions(qdCount int, data []byte) (questions []Question, nextSectionStartIndex int, err error) {
	//data is expected to be complete payload, with header having a size of 12
	nextQuestionIndex := 12
	for i := 0; i < qdCount; i++ {
		domainLabels := []DomainLabel{}
		nextQuestionIndex, err = ParseDomainLabels(nextQuestionIndex, data, &domainLabels)
		if err != nil {
			return nil, 0, err
		}
		questions = append(questions, Question{Name: domainLabels, Type: 1, Class: 1})
	}

	nextSectionStartIndex = nextQuestionIndex

	return
}
