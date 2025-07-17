package parser

import (
	"encoding/binary"
	"errors"
)

type MessageType int

const (
	Query MessageType = iota
	Response
)

type RCode uint8

const (
	NoError RCode = iota
	FormErr
	ServFail
	NXDomain
	NotImp
	Refused
)

type DNSHeader struct {
	ID      uint16
	flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type DNSQuestion struct {
	QName  string
	QType  uint16
	QClass uint16
}

type DNSResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

type DNSMessage struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSResourceRecord
	Authorities []DNSResourceRecord
	Additionals []DNSResourceRecord
}

type dnsReader struct {
	data []byte
	pos  int
}

func (h *DNSHeader) QR() bool {
	return h.flags&0x8000 != 0
}

func (h *DNSHeader) Opcode() uint8 {
	return uint8((h.flags & 0x7800) >> 11)
}

func (h *DNSHeader) AA() bool {
	return h.flags&0x0400 != 0
}

func (h *DNSHeader) TC() bool {
	return h.flags&0x0200 != 0
}

func (h *DNSHeader) RD() bool {
	return h.flags&0x0100 != 0
}

func (h *DNSHeader) RA() bool {
	return h.flags&0x0080 != 0
}

func (h *DNSHeader) Z() uint8 {
	return uint8((h.flags & 0x0070) >> 4)
}

func (h *DNSHeader) RCode() uint8 {
	return uint8(h.flags & 0x000F)
}

func (h *DNSHeader) validateHeader(mode MessageType) error {
	switch mode {
	case Query:
		if h.QR() {
			return errors.New("QR bit set in query")
		}
		if h.AA() {
			return errors.New("AA bit set in query")
		}
		if h.RA() {
			return errors.New("RA bit set in query")
		}
		if h.Z() > 0 {
			return errors.New("Z must be zero")
		}
		if h.RCode() > 0 {
			return errors.New("RCODE set in query")
		}
		if h.QDCount == 0 {
			return errors.New("QDCOUNT set to zero")
		}
		if h.ANCount > 0 {
			return errors.New("ANCOUNT set in query")
		}
		if h.NSCount > 0 {
			return errors.New("NSCOUNT set in query")
		}
		if h.ARCount > 0 {
			return errors.New("ARCOUNT set in query")
		}
	case Response:
		if !h.QR() {
			return errors.New("QR bit not set in response")
		}
		if h.QDCount == 0 {
			return errors.New("QCount not non-zero in response")
		}
	}
	return nil
}

func parseDNSHeader(r *dnsReader, mode MessageType) (DNSHeader, error) {
	h := DNSHeader{}
	var err error

	if h.ID, err = r.ReadUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.flags, err = r.ReadUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.QDCount, err = r.ReadUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.ANCount, err = r.ReadUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.NSCount, err = r.ReadUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.ARCount, err = r.ReadUint16(); err != nil {
		return DNSHeader{}, err
	}

	err = h.validateHeader(mode)
	if err != nil {
		return DNSHeader{}, err
	}
	return h, nil
}

func parseQName(r *dnsReader) (string, error) {
	result := ""
	for {
		length, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if length == 0 {
			break
		}
		token, err := r.ReadBytes(int(length))
		if err != nil {
			return "", errors.New("QName not long enough")
		}
		result += string(token) + "."
	}
	if result == "" {
		result = "."
	}
	return result, nil
}

func parseDNSQuestion(r *dnsReader, qdCount uint16) ([]DNSQuestion, error) {
	questions := make([]DNSQuestion, qdCount)
	var err error
	for i := 0; i < int(qdCount); i++ {
		q := DNSQuestion{}
		if q.QName, err = parseQName(r); err != nil {
			return nil, err
		}
		if q.QType, err = r.ReadUint16(); err != nil {
			return nil, err
		}
		if q.QClass, err = r.ReadUint16(); err != nil {
			return nil, err
		}
		questions[i] = q
	}
	return questions, nil
}

func (r *dnsReader) ReadUint16() (uint16, error) {
	if r.pos+2 > len(r.data) {
		return 0, errors.New("Out of bounds while reading uint16")
	}
	val := binary.BigEndian.Uint16(r.data[r.pos : r.pos+2])
	r.pos += 2
	return val, nil
}

func (r *dnsReader) ReadBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, errors.New("Out of bounds while reading bytes")
	}
	val := r.data[r.pos : r.pos+n]
	r.pos += n
	return val, nil
}

func (r *dnsReader) ReadByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("Out of bounds while reading byte")
	}
	val := r.data[r.pos]
	r.pos++
	return val, nil
}

func ParseDNSMessage(query []byte, mode MessageType) (DNSMessage, error) {
	m := DNSMessage{}
	var err error
	r := dnsReader{data: query}

	if m.Header, err = parseDNSHeader(&r, mode); err != nil {
		return DNSMessage{}, err
	}

	if m.Questions, err = parseDNSQuestion(&r, m.Header.QDCount); err != nil {
		return DNSMessage{}, err
	}
	return m, nil
}
