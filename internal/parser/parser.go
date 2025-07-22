package parser

import (
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"strings"
)

func (r *dnsReader) readUint16() (uint16, error) {
	if r.pos+2 > len(r.data) {
		return 0, errors.New("Out of bounds while reading uint16")
	}
	val := binary.BigEndian.Uint16(r.data[r.pos : r.pos+2])
	r.pos += 2
	return val, nil
}

func (r *dnsReader) readUint32() (uint32, error) {
	if r.pos+4 > len(r.data) {
		return 0, errors.New("Out of bounds while reading uint32")
	}
	val := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4
	return val, nil
}

func (r *dnsReader) readBytes(n int) ([]byte, error) {
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

func (r *dnsReader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("Out of bounds while reading byte")
	}
	val := r.data[r.pos]
	r.pos++
	return val, nil
}

func (r *dnsReader) readUint8() (uint8, error) {
	val, err := r.readByte()
	if err != nil {
		return 0, errors.New("Out of bounds while reading uint8")
	}
	return uint8(val), nil
}

func (r *dnsReader) readString() (string, error) {
	length, err := r.readByte()
	if err != nil {
		return "", err
	}
	val, err := r.readBytes(int(length))
	if err != nil {
		return "", err
	}
	return string(val), nil
}

func (r *dnsReader) readIP() (net.IP, error) {
	ipBytes, err := r.readBytes(4)
	if err != nil {
		return nil, err
	}
	val := net.IP(ipBytes).To4()
	return val, nil
}

func (r *dnsReader) readIPv6() (net.IP, error) {
	ipBytes, err := r.readBytes(16)
	if err != nil {
		return nil, err
	}
	val := net.IP(ipBytes).To16()
	return val, nil
}

func (r *dnsReader) readNameFromOffset(offset uint16) (string, error) {
	if slices.Contains(r.offsetStack, offset) {
		return "", errors.New("Cyclical offset detected")
	}
	r.offsetStack = append(r.offsetStack, offset)
	startPos := r.pos
	r.pos = int(offset)
	name, err := r.readName()
	if err != nil {
		return "", err
	}
	r.pos = startPos
	r.offsetStack = r.offsetStack[:len(r.offsetStack)-1]
	return name, nil
}

func (r *dnsReader) readName() (string, error) {
	tokens := make([]string, 0)
	for {
		lead, err := r.readByte()
		if err != nil {
			return "", err
		}
		if r.parseStatus == parsingResourceRecords && lead&PointerMask == PointerMask {
			// Pointer
			off2, err := r.readByte()
			if err != nil {
				return "", err
			}
			offset := uint16(lead&OffsetMask)<<8 | uint16(off2)
			token, err := r.readNameFromOffset(offset)
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
			token, err := r.readBytes(int(lead))
			if err != nil {
				return "", errors.New("(Q)Name not long enough")
			}
			tokens = append(tokens, string(token))
		}
	}
	return strings.Join(tokens, ".") + ".", nil
}

func (h *DNSHeader) GetQR() bool {
	return h.flags&QRMask != 0
}

func (h *DNSHeader) GetOpcode() uint8 {
	return uint8((h.flags & OpcodeMask) >> 11)
}

func (h *DNSHeader) GetAA() bool {
	return h.flags&AAMask != 0
}
func (h *DNSHeader) GetTC() bool {
	return h.flags&TCMask != 0
}

func (h *DNSHeader) GetRD() bool {
	return h.flags&RDMask != 0
}

func (h *DNSHeader) GetRA() bool {
	return h.flags&RAMask != 0
}

func (h *DNSHeader) GetZ() uint8 {
	return uint8((h.flags & ZMask) >> 4)
}

func (h *DNSHeader) GetRCode() uint8 {
	return uint8(h.flags & RCodeMask)
}

func (h *DNSHeader) validateHeader(mode MessageType) error {
	switch mode {
	case Query:
		if h.GetQR() {
			return errors.New("QR bit set in query")
		}
		if h.GetAA() {
			return errors.New("AA bit set in query")
		}
		if h.GetRA() {
			return errors.New("RA bit set in query")
		}
		if h.GetZ() > 0 {
			return errors.New("Z must be zero")
		}
		if h.GetRCode() > 0 {
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
		if !h.GetQR() {
			return errors.New("QR bit not set in response")
		}
	}
	return nil
}
func (r *dnsReader) parseARecord() (ARecord, error) {
	res := ARecord{}
	var err error
	res.IP, err = r.readIP()
	if err != nil {
		return ARecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseNSRecord() (NSRecord, error) {
	res := NSRecord{}
	var err error
	res.Name, err = r.readName()
	if err != nil {
		return NSRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseMDRecord() (MDRecord, error) {
	res := MDRecord{}
	var err error
	res.Name, err = r.readName()
	if err != nil {
		return MDRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseMFRecord() (MFRecord, error) {
	res := MFRecord{}
	var err error
	res.Name, err = r.readName()
	if err != nil {
		return MFRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseCNameRecord() (CNameRecord, error) {
	res := CNameRecord{}
	var err error
	res.Name, err = r.readName()
	if err != nil {
		return CNameRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseSOARecord() (SOARecord, error) {
	res := SOARecord{}
	var err error
	res.MName, err = r.readName()
	if err != nil {
		return SOARecord{}, err
	}
	res.RName, err = r.readName()
	if err != nil {
		return SOARecord{}, err
	}
	res.Serial, err = r.readUint32()
	if err != nil {
		return SOARecord{}, err
	}
	res.Refresh, err = r.readUint32()
	if err != nil {
		return SOARecord{}, err
	}
	res.Retry, err = r.readUint32()
	if err != nil {
		return SOARecord{}, err
	}
	res.Expire, err = r.readUint32()
	if err != nil {
		return SOARecord{}, err
	}
	res.Minimum, err = r.readUint32()
	if err != nil {
		return SOARecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseMBRecord() (MBRecord, error) {
	res := MBRecord{}
	var err error
	res.Name, err = r.readName()
	if err != nil {
		return MBRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseMGRecord() (MGRecord, error) {
	res := MGRecord{}
	var err error
	res.Name, err = r.readName()
	if err != nil {
		return MGRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseMRRecord() (MRRecord, error) {
	res := MRRecord{}
	var err error
	res.Name, err = r.readName()
	if err != nil {
		return MRRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseNullRecord(length int) (NullRecord, error) {
	res := NullRecord{}
	var err error
	res.Anything, err = r.readBytes(length)
	if err != nil {
		return NullRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseWKSRecord(length int) (WKSRecord, error) {
	res := WKSRecord{}
	var err error
	res.Address, err = r.readIP()
	if err != nil {
		return WKSRecord{}, err
	}
	res.Protocol, err = r.readUint8()
	if err != nil {
		return WKSRecord{}, err
	}
	res.Bitmap, err = r.readBytes(length - 5)
	if err != nil {
		return WKSRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parsePTRRecord() (PTRRecord, error) {
	res := PTRRecord{}
	var err error
	res.Name, err = r.readName()
	if err != nil {
		return PTRRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseHInfoRecord() (HInfoRecord, error) {
	res := HInfoRecord{}
	var err error
	res.CPU, err = r.readString()
	if err != nil {
		return HInfoRecord{}, err
	}
	res.OS, err = r.readString()
	if err != nil {
		return HInfoRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseMInfoRecord() (MInfoRecord, error) {
	res := MInfoRecord{}
	var err error
	res.RMailBX, err = r.readName()
	if err != nil {
		return MInfoRecord{}, err
	}
	res.EMailBX, err = r.readName()
	if err != nil {
		return MInfoRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseMXRecord() (MXRecord, error) {
	res := MXRecord{}
	var err error
	res.Preference, err = r.readUint16()
	if err != nil {
		return MXRecord{}, err
	}
	res.Exchange, err = r.readName()
	if err != nil {
		return MXRecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseTXTRecord(length int) (TXTRecord, error) {
	res := TXTRecord{}
	var recs []string
	startPos := r.pos
	for r.pos < startPos+length {
		rec, err := r.readString()
		if err != nil {
			return TXTRecord{}, err
		}
		recs = append(recs, rec)
	}
	res.Data = recs
	return res, nil
}

func (r *dnsReader) parseAAAARecord() (AAAARecord, error) {
	res := AAAARecord{}
	var err error
	res.IP, err = r.readIPv6()
	if err != nil {
		return AAAARecord{}, err
	}
	return res, nil
}

func (r *dnsReader) parseRData(rt RecordType, rc RecordClass, length int) (RData, error) {
	var res RData
	var err error
	startPos := r.pos
	switch rt {
	case RTA:
		res, err = r.parseARecord()
	case RTNS:
		res, err = r.parseNSRecord()
	case RTMD:
		res, err = r.parseMDRecord()
	case RTMF:
		res, err = r.parseMFRecord()
	case RTCNAME:
		res, err = r.parseCNameRecord()
	case RTSOA:
		res, err = r.parseSOARecord()
	case RTMB:
		res, err = r.parseMBRecord()
	case RTMG:
		res, err = r.parseMGRecord()
	case RTMR:
		res, err = r.parseMRRecord()
	case RTNULL:
		res, err = r.parseNullRecord(length)
	case RTWKS:
		res, err = r.parseWKSRecord(length)
	case RTPTR:
		res, err = r.parsePTRRecord()
	case RTHINFO:
		res, err = r.parseHInfoRecord()
	case RTMINFO:
		res, err = r.parseMInfoRecord()
	case RTMX:
		res, err = r.parseMXRecord()
	case RTTXT:
		res, err = r.parseTXTRecord(length)
	case RTAAAA:
		res, err = r.parseAAAARecord()
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

func (r *dnsReader) parseDNSResourceRecord(count uint16) ([]DNSResourceRecord, error) {
	records := make([]DNSResourceRecord, count)
	var err error
	for i := 0; i < int(count); i++ {
		rr := DNSResourceRecord{}
		if rr.Name, err = r.readName(); err != nil {
			return nil, err
		}
		if t, err := r.readUint16(); err != nil {
			return nil, err
		} else {
			rr.Type = RecordType(t)
		}
		if c, err := r.readUint16(); err != nil {
			return nil, err
		} else {
			rr.Class = RecordClass(c)
		}
		if rr.TTL, err = r.readUint32(); err != nil {
			return nil, err
		}
		if rr.RDLength, err = r.readUint16(); err != nil {
			return nil, err
		}
		if rr.RData, err = r.parseRData(rr.Type, rr.Class, int(rr.RDLength)); err != nil {
			return nil, err
		}
		records[i] = rr
	}
	return records, nil
}

func (r *dnsReader) parseDNSHeader(mode MessageType) (DNSHeader, error) {
	if r.parseStatus != parsingHeader {
		return DNSHeader{}, errors.New("Parser in incorrect state")
	}
	h := DNSHeader{}
	var err error
	if h.ID, err = r.readUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.flags, err = r.readUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.QDCount, err = r.readUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.ANCount, err = r.readUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.NSCount, err = r.readUint16(); err != nil {
		return DNSHeader{}, err
	}
	if h.ARCount, err = r.readUint16(); err != nil {
		return DNSHeader{}, err
	}
	err = h.validateHeader(mode)
	if err != nil {
		return DNSHeader{}, err
	}
	r.parseStatus = parsingQuestion
	return h, nil
}

func (r *dnsReader) parseDNSQuestion(qdCount uint16) ([]DNSQuestion, error) {
	if r.parseStatus != parsingQuestion {
		return nil, errors.New("Parser in incorrect state")
	}
	questions := make([]DNSQuestion, qdCount)
	var err error
	for i := 0; i < int(qdCount); i++ {
		q := DNSQuestion{}
		if q.QName, err = r.readName(); err != nil {
			return nil, err
		}
		if t, err := r.readUint16(); err != nil {
			return nil, err
		} else {
			q.QType = RecordType(t)
		}
		if c, err := r.readUint16(); err != nil {
			return nil, err
		} else {
			q.QClass = RecordClass(c)
		}
		questions[i] = q
	}
	r.parseStatus = parsingResourceRecords
	return questions, nil
}

func ParseDNSMessage(query []byte, mode MessageType) (DNSMessage, error) {
	m := DNSMessage{}
	var err error
	r := dnsReader{data: query}
	if m.Header, err = r.parseDNSHeader(mode); err != nil {
		return DNSMessage{}, err
	}
	if m.Questions, err = r.parseDNSQuestion(m.Header.QDCount); err != nil {
		return DNSMessage{}, err
	}
	if mode == Query {
		return m, nil
	}
	if m.Answers, err = r.parseDNSResourceRecord(m.Header.ANCount); err != nil {
		return DNSMessage{}, err
	}
	if m.Authorities, err = r.parseDNSResourceRecord(m.Header.NSCount); err != nil {
		return DNSMessage{}, err
	}
	if m.Additionals, err = r.parseDNSResourceRecord(m.Header.ARCount); err != nil {
		return DNSMessage{}, err
	}
	return m, nil
}
