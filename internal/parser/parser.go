package parser

import (
	"encoding/binary"
	"errors"
	"net"
)

type MessageType int

const (
	Query MessageType = iota
	Response
)

type RecordType uint16

const (
	RTA     RecordType = 1
	RTNS    RecordType = 2
	RTMD    RecordType = 3
	RTMF    RecordType = 4
	RTCNAME RecordType = 5
	RTSOA   RecordType = 6
	RTMB    RecordType = 7
	RTMG    RecordType = 8
	RTMR    RecordType = 9
	RTNULL  RecordType = 10
	RTWKS   RecordType = 11
	RTPTR   RecordType = 12
	RTHINFO RecordType = 13
	RTMINFO RecordType = 14
	RTMX    RecordType = 15
	RTTXT   RecordType = 16

	RTAXFR  RecordType = 252
	RTMAILB RecordType = 253
	RTMAILA RecordType = 254
	RTSTAR  RecordType = 255
)

type RecordClass uint16

const (
	RCIN RecordClass = 1
	RCCS RecordClass = 2
	RCCH RecordClass = 3
	RCHS RecordClass = 4

	RCSTAR RecordClass = 255
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

type RData interface{}

type ARecord struct {
	IP net.IP
}

type NSRecord struct {
	Name string
}

type MDRecord struct {
	Name string
}

type MFRecord struct {
	Name string
}

type CNameRecord struct {
	Name string
}

type SOARecord struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Expire  uint32
	Minimum uint32
}

type MBRecord struct {
	Name string
}

type MGRecord struct {
	Name string
}

type MRRecord struct {
	Name string
}

type NullRecord struct {
	Anything []byte
}

type WKSRecord struct {
	Address  net.IP
	Protocol uint8
	Bitmap   []byte
}

type PTRRecord struct {
	Name string
}

type HInfoRecord struct {
	CPU string
	OS  string
}

type MInfoRecord struct {
	RMailBX string
	EMailBX string
}

type MXRecord struct {
	Preference uint16
	Exchange   string
}

type TXTRecord struct {
	Data []string
}

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
	QType  RecordType
	QClass RecordClass
}

type DNSResourceRecord struct {
	Name     string
	Type     RecordType
	Class    RecordClass
	TTL      uint32
	RDLength uint16
	RData    RData
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

func parseName(r *dnsReader) (string, error) {
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
			return "", errors.New("(Q)Name not long enough")
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
		if q.QName, err = parseName(r); err != nil {
			return nil, err
		}
		if t, err := r.ReadUint16(); err != nil {
			return nil, err
		} else {
			q.QType = RecordType(t)
		}
		if c, err := r.ReadUint16(); err != nil {
			return nil, err
		} else {
			q.QClass = RecordClass(c)
		}
		questions[i] = q
	}
	return questions, nil
}

func parseARecord(r *dnsReader) (ARecord, error) {
	return ARecord{}, nil
}

func parseNSRecord(r *dnsReader) (NSRecord, error) {
	return NSRecord{}, nil
}

func parseMDRecord(r *dnsReader) (MDRecord, error) {
	return MDRecord{}, nil
}

func parseMFRecord(r *dnsReader) (MFRecord, error) {
	return MFRecord{}, nil
}

func parseCNameRecord(r *dnsReader) (CNameRecord, error) {
	return CNameRecord{}, nil
}

func parseSOARecord(r *dnsReader) (SOARecord, error) {
	return SOARecord{}, nil
}

func parseMBRecord(r *dnsReader) (MBRecord, error) {
	return MBRecord{}, nil
}

func parseMGRecord(r *dnsReader) (MGRecord, error) {
	return MGRecord{}, nil
}

func parseMRRecord(r *dnsReader) (MRRecord, error) {
	return MRRecord{}, nil
}

func parseNullRecord(r *dnsReader) (NullRecord, error) {
	return NullRecord{}, nil
}

func parseWKSRecord(r *dnsReader) (WKSRecord, error) {
	return WKSRecord{}, nil
}

func parsePTRRecord(r *dnsReader) (PTRRecord, error) {
	return PTRRecord{}, nil
}

func parseHInfoRecord(r *dnsReader) (HInfoRecord, error) {
	return HInfoRecord{}, nil
}

func parseMInfoRecord(r *dnsReader) (MInfoRecord, error) {
	return MInfoRecord{}, nil
}

func parseMXRecord(r *dnsReader) (MXRecord, error) {
	return MXRecord{}, nil
}

func parseTXTRecord(r *dnsReader) (TXTRecord, error) {
	return TXTRecord{}, nil
}

func parseRData(r *dnsReader, rt RecordType, rc RecordClass) (RData, error) {
	switch rt {
	case RTA:
		return parseARecord(r)
	case RTNS:
		return parseNSRecord(r)
	case RTMD:
		return parseMDRecord(r)
	case RTMF:
		return parseMXRecord(r)
	case RTCNAME:
		return parseCNameRecord(r)
	case RTSOA:
		return parseSOARecord(r)
	case RTMB:
		return parseMBRecord(r)
	case RTMG:
		return parseMGRecord(r)
	case RTMR:
		return parseMRRecord(r)
	case RTNULL:
		return parseNullRecord(r)
	case RTWKS:
		return parseWKSRecord(r)
	case RTPTR:
		return parsePTRRecord(r)
	case RTHINFO:
		return parseHInfoRecord(r)
	case RTMINFO:
		return parseMInfoRecord(r)
	case RTMX:
		return parseMXRecord(r)
	case RTTXT:
		return parseTXTRecord(r)
	default:
		return "", errors.New("Unsupported TYPE")
	}
}

func parseDNSResourceRecord(r *dnsReader, count uint16) ([]DNSResourceRecord, error) {
	records := make([]DNSResourceRecord, count)
	var err error
	for i := 0; i < int(count); i++ {
		rr := DNSResourceRecord{}
		if rr.Name, err = parseName(r); err != nil {
			return nil, err
		}
		if t, err := r.ReadUint16(); err != nil {
			return nil, err
		} else {
			rr.Type = RecordType(t)
		}
		if c, err := r.ReadUint16(); err != nil {
			return nil, err
		} else {
			rr.Class = RecordClass(c)
		}
		if rr.TTL, err = r.ReadUint32(); err != nil {
			return nil, err
		}
		if rr.RDLength, err = r.ReadUint16(); err != nil {
			return nil, err
		}
		if rr.RData, err = parseRData(r, rr.Type, rr.Class); err != nil {
			return nil, err
		}
		records[i] = rr
	}
	return records, nil
}

func (r *dnsReader) ReadUint16() (uint16, error) {
	if r.pos+2 > len(r.data) {
		return 0, errors.New("Out of bounds while reading uint16")
	}
	val := binary.BigEndian.Uint16(r.data[r.pos : r.pos+2])
	r.pos += 2
	return val, nil
}

func (r *dnsReader) ReadUint32() (uint32, error) {
	if r.pos+4 > len(r.data) {
		return 0, errors.New("Out of bounds while reading uint32")
	}
	val := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4
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
	if mode == Query {
		return m, nil
	}
	return m, nil
}
