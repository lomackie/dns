package parser

import (
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"strings"
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

type parseStatus int

const (
	parsingHeader parseStatus = iota
	parsingQuestion
	parsingResourceRecords
)

type RData any

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
	Retry   uint32
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
	data        []byte
	pos         int
	parseStatus parseStatus
	offsetStack []uint16
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
	if r.parseStatus != parsingHeader {
		return DNSHeader{}, errors.New("Parser in incorrect state")
	}
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
	r.parseStatus = parsingQuestion
	return h, nil
}

func parseDNSQuestion(r *dnsReader, qdCount uint16) ([]DNSQuestion, error) {
	if r.parseStatus != parsingQuestion {
		return nil, errors.New("Parser in incorrect state")
	}
	questions := make([]DNSQuestion, qdCount)
	var err error
	for i := 0; i < int(qdCount); i++ {
		q := DNSQuestion{}
		if q.QName, err = r.ReadName(); err != nil {
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
	r.parseStatus = parsingResourceRecords
	return questions, nil
}

func parseARecord(r *dnsReader) (ARecord, error) {
	res := ARecord{}
	ipBytes, err := r.ReadBytes(4)
	if err != nil {
		return ARecord{}, err
	} else {
		res.IP = net.IP(ipBytes).To4()
	}
	return res, nil
}

func parseNSRecord(r *dnsReader) (NSRecord, error) {
	res := NSRecord{}
	var err error
	res.Name, err = r.ReadName()
	if err != nil {
		return NSRecord{}, err
	}
	return res, nil
}

func parseMDRecord(r *dnsReader) (MDRecord, error) {
	res := MDRecord{}
	var err error
	res.Name, err = r.ReadName()
	if err != nil {
		return MDRecord{}, err
	}
	return res, nil
}

func parseMFRecord(r *dnsReader) (MFRecord, error) {
	res := MFRecord{}
	var err error
	res.Name, err = r.ReadName()
	if err != nil {
		return MFRecord{}, err
	}
	return res, nil
}

func parseCNameRecord(r *dnsReader) (CNameRecord, error) {
	res := CNameRecord{}
	var err error
	res.Name, err = r.ReadName()
	if err != nil {
		return CNameRecord{}, err
	}
	return res, nil
}

func parseSOARecord(r *dnsReader) (SOARecord, error) {
	res := SOARecord{}
	var err error
	res.MName, err = r.ReadName()
	if err != nil {
		return SOARecord{}, err
	}
	res.RName, err = r.ReadName()
	if err != nil {
		return SOARecord{}, err
	}
	res.Serial, err = r.ReadUint32()
	if err != nil {
		return SOARecord{}, err
	}
	res.Refresh, err = r.ReadUint32()
	if err != nil {
		return SOARecord{}, err
	}
	res.Retry, err = r.ReadUint32()
	if err != nil {
		return SOARecord{}, err
	}
	res.Expire, err = r.ReadUint32()
	if err != nil {
		return SOARecord{}, err
	}
	res.Minimum, err = r.ReadUint32()
	if err != nil {
		return SOARecord{}, err
	}
	return res, nil
}

func parseMBRecord(r *dnsReader) (MBRecord, error) {
	res := MBRecord{}
	var err error
	res.Name, err = r.ReadName()
	if err != nil {
		return MBRecord{}, err
	}
	return res, nil
}

func parseMGRecord(r *dnsReader) (MGRecord, error) {
	res := MGRecord{}
	var err error
	res.Name, err = r.ReadName()
	if err != nil {
		return MGRecord{}, err
	}
	return res, nil
}

func parseMRRecord(r *dnsReader) (MRRecord, error) {
	res := MRRecord{}
	var err error
	res.Name, err = r.ReadName()
	if err != nil {
		return MRRecord{}, err
	}
	return res, nil
}

func parseNullRecord(r *dnsReader, length int) (NullRecord, error) {
	res := NullRecord{}
	var err error
	res.Anything, err = r.ReadBytes(length)
	if err != nil {
		return NullRecord{}, err
	}
	return res, nil
}

func parseWKSRecord(r *dnsReader, length int) (WKSRecord, error) {
	res := WKSRecord{}
	a, err := r.ReadBytes(4)
	if err != nil {
		return WKSRecord{}, err
	} else {
		res.Address = net.IP(a).To4()
	}
	res.Protocol, err = r.ReadUint8()
	if err != nil {
		return WKSRecord{}, err
	}
	res.Bitmap, err = r.ReadBytes(length - 5)
	if err != nil {
		return WKSRecord{}, err
	}
	return res, nil
}

func parsePTRRecord(r *dnsReader) (PTRRecord, error) {
	res := PTRRecord{}
	var err error
	res.Name, err = r.ReadName()
	if err != nil {
		return PTRRecord{}, err
	}
	return res, nil
}

func parseHInfoRecord(r *dnsReader) (HInfoRecord, error) {
	res := HInfoRecord{}
	var err error
	res.CPU, err = r.ReadString()
	if err != nil {
		return HInfoRecord{}, err
	}
	res.OS, err = r.ReadString()
	if err != nil {
		return HInfoRecord{}, err
	}
	return res, nil
}

func parseMInfoRecord(r *dnsReader) (MInfoRecord, error) {
	res := MInfoRecord{}
	var err error
	res.RMailBX, err = r.ReadName()
	if err != nil {
		return MInfoRecord{}, err
	}
	res.EMailBX, err = r.ReadName()
	if err != nil {
		return MInfoRecord{}, err
	}
	return res, nil
}

func parseMXRecord(r *dnsReader) (MXRecord, error) {
	res := MXRecord{}
	var err error
	res.Preference, err = r.ReadUint16()
	if err != nil {
		return MXRecord{}, err
	}
	res.Exchange, err = r.ReadName()
	if err != nil {
		return MXRecord{}, err
	}
	return res, nil
}

func parseTXTRecord(r *dnsReader, length int) (TXTRecord, error) {
	res := TXTRecord{}
	var recs []string
	startPos := r.pos
	for r.pos < startPos+length {
		rec, err := r.ReadString()
		if err != nil {
			return TXTRecord{}, err
		}
		recs = append(recs, rec)
	}
	res.Data = recs
	return res, nil
}

func parseRData(r *dnsReader, rt RecordType, rc RecordClass, length int) (RData, error) {
	var res RData
	var err error
	startPos := r.pos
	switch rt {
	case RTA:
		res, err = parseARecord(r)
	case RTNS:
		res, err = parseNSRecord(r)
	case RTMD:
		res, err = parseMDRecord(r)
	case RTMF:
		res, err = parseMFRecord(r)
	case RTCNAME:
		res, err = parseCNameRecord(r)
	case RTSOA:
		res, err = parseSOARecord(r)
	case RTMB:
		res, err = parseMBRecord(r)
	case RTMG:
		res, err = parseMGRecord(r)
	case RTMR:
		res, err = parseMRRecord(r)
	case RTNULL:
		res, err = parseNullRecord(r, length)
	case RTWKS:
		res, err = parseWKSRecord(r, length)
	case RTPTR:
		res, err = parsePTRRecord(r)
	case RTHINFO:
		res, err = parseHInfoRecord(r)
	case RTMINFO:
		res, err = parseMInfoRecord(r)
	case RTMX:
		res, err = parseMXRecord(r)
	case RTTXT:
		res, err = parseTXTRecord(r, length)
	default:
		return "", errors.New("Unsupported TYPE")
	}
	if err != nil {
		return nil, err
	}
	if r.pos-startPos != length {
		return nil, errors.New("RData not aligned with RLength")
	}
	return res, nil
}

func parseDNSResourceRecord(r *dnsReader, count uint16) ([]DNSResourceRecord, error) {
	records := make([]DNSResourceRecord, count)
	var err error
	for i := 0; i < int(count); i++ {
		rr := DNSResourceRecord{}
		if rr.Name, err = r.ReadName(); err != nil {
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
		if rr.RData, err = parseRData(r, rr.Type, rr.Class, int(rr.RDLength)); err != nil {
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
	if n <= 0 {
		return nil, errors.New("Cannot read non-positive number of bytes")
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

func (r *dnsReader) ReadUint8() (uint8, error) {
	val, err := r.ReadByte()
	if err != nil {
		return 0, errors.New("Out of bounds while reading uint8")
	}
	return uint8(val), nil
}

func (r *dnsReader) ReadString() (string, error) {
	length, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	val, err := r.ReadBytes(int(length))
	if err != nil {
		return "", err
	}
	return string(val), nil
}

func (r *dnsReader) ReadNameFromOffset(offset uint16) (string, error) {
	if slices.Contains(r.offsetStack, offset) {
		return "", errors.New("Cyclical offset detected")
	}
	r.offsetStack = append(r.offsetStack, offset)

	startPos := r.pos
	r.pos = int(offset)

	name, err := r.ReadName()
	if err != nil {
		return "", err
	}

	r.pos = startPos
	r.offsetStack = r.offsetStack[:len(r.offsetStack)-1]
	return name, nil
}

func (r *dnsReader) ReadName() (string, error) {
	tokens := make([]string, 0)
	for {
		lead, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if r.parseStatus == parsingResourceRecords && lead&0xC0 == 0xC0 {
			// Pointer
			off2, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			offset := uint16(lead&0x3F)<<8 | uint16(off2)
			token, err := r.ReadNameFromOffset(offset)
			if err != nil {
				return "", err
			}
			tokens = append(tokens, strings.TrimSuffix(token, "."))
			break
		} else if lead == 0 {
			// End of name
			break
		} else {
			// Label of length lead
			token, err := r.ReadBytes(int(lead))
			if err != nil {
				return "", errors.New("(Q)Name not long enough")
			}
			tokens = append(tokens, string(token))
		}
	}
	return strings.Join(tokens, ".") + ".", nil
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
	if m.Answers, err = parseDNSResourceRecord(&r, m.Header.ANCount); err != nil {
		return DNSMessage{}, err
	}
	return m, nil
}
