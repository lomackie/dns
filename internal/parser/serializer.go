package parser

import (
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
)

func (s *dnsWriter) writeUint8(v uint8) {
	s.data = append(s.data, byte(v))
}

func (s *dnsWriter) writeUint16(v uint16) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	s.data = append(s.data, buf...)
}

func (s *dnsWriter) writeUint32(v uint32) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	s.data = append(s.data, buf...)
}

func (s *dnsWriter) writeByte(v byte) {
	s.data = append(s.data, v)
}

func (s *dnsWriter) writeBytes(v []byte) {
	s.data = append(s.data, v...)
}

func (s *dnsWriter) writeString(v string) {
	s.writeByte(byte(len(v)))
	s.writeBytes([]byte(v))
}

func (s *dnsWriter) writePointer(offset int) {
	s.writeUint16((uint16(PointerMask) << 8) | uint16(offset))
}

func (s *dnsWriter) writeName(v string) {
	tokens := strings.Split(v, ".")
	for i, token := range tokens {
		suffix := strings.Join(tokens[i:], ".")
		offset, ok := s.names[suffix]
		if ok {
			s.writePointer(offset)
			return
		} else if token != "" {
			s.names[suffix] = len(s.data)
		}
		s.writeString(token)
	}
	if !strings.HasSuffix(v, ".") {
		s.writeByte(0)
	}
}

func (s *dnsWriter) writeIP(v net.IP) {
	s.data = append(s.data, v.To4()...)
}

func (h *DNSHeader) setQR(b bool) {
	h.flags &^= QRMask
	if b {
		h.flags |= QRMask
	}
}

func (h *DNSHeader) setOpcode(opcode uint8) {
	h.flags &^= OpcodeMask
	h.flags |= (uint16(opcode) << 11) & OpcodeMask
}

func (h *DNSHeader) setAA(b bool) {
	h.flags &^= AAMask
	if b {
		h.flags |= AAMask
	}
}

func (h *DNSHeader) setTC(b bool) {
	h.flags &^= TCMask
	if b {
		h.flags |= TCMask
	}
}

func (h *DNSHeader) setRD(b bool) {
	h.flags &^= RDMask
	if b {
		h.flags |= RDMask
	}
}

func (h *DNSHeader) setRA(b bool) {
	h.flags &^= RAMask
	if b {
		h.flags |= RAMask
	}
}

func (h *DNSHeader) setZ(z uint8) {
	h.flags &^= ZMask
	h.flags |= (uint16(z) << 4) & ZMask
}

func (h *DNSHeader) setRCode(rcode uint8) {
	h.flags &^= RCodeMask
	h.flags |= uint16(rcode) & RCodeMask
}

func (s *dnsWriter) serializeARecord(r ARecord) {
	s.writeIP(r.IP)
}

func (s *dnsWriter) serializeNSRecord(r NSRecord) {
	s.writeName(r.Name)
}

func (s *dnsWriter) serializeMDRecord(r MDRecord) {
	s.writeName(r.Name)
}

func (s *dnsWriter) serializeMFRecord(r MFRecord) {
	s.writeName(r.Name)
}

func (s *dnsWriter) serializeCNameRecord(r CNameRecord) {
	s.writeName(r.Name)
}

func (s *dnsWriter) serializeSOARecord(r SOARecord) {
	s.writeName(r.MName)
	s.writeName(r.RName)
	s.writeUint32(r.Serial)
	s.writeUint32(r.Refresh)
	s.writeUint32(r.Retry)
	s.writeUint32(r.Expire)
	s.writeUint32(r.Minimum)
}

func (s *dnsWriter) serializeMBRecord(r MBRecord) {
	s.writeName(r.Name)
}

func (s *dnsWriter) serializeMGRecord(r MGRecord) {
	s.writeName(r.Name)
}

func (s *dnsWriter) serializeMRRecord(r MRRecord) {
	s.writeName(r.Name)
}

func (s *dnsWriter) serializeNullRecord(r NullRecord) {
	s.writeBytes(r.Anything)
}

func (s *dnsWriter) serializeWKSRecord(r WKSRecord) {
	s.writeIP(r.Address)
	s.writeUint8(r.Protocol)
	s.writeBytes(r.Bitmap)
}

func (s *dnsWriter) serializePTRRecord(r PTRRecord) {
	s.writeName(r.Name)
}

func (s *dnsWriter) serializeHInfoRecord(r HInfoRecord) {
	s.writeString(r.CPU)
	s.writeString(r.OS)
}

func (s *dnsWriter) serializeMInfoRecord(r MInfoRecord) {
	s.writeString(r.RMailBX)
	s.writeString(r.EMailBX)
}

func (s *dnsWriter) serializeMXRecord(r MXRecord) {
	s.writeUint16(r.Preference)
	s.writeString(r.Exchange)
}

func (s *dnsWriter) serializeTXTRecord(r TXTRecord) {
	for _, d := range r.Data {
		s.writeString(d)
	}
}

func (s *dnsWriter) writeRData(rdata RData) {
	switch rd := rdata.(type) {
	case ARecord:
		s.serializeARecord(rd)
	case NSRecord:
		s.serializeNSRecord(rd)
	case MDRecord:
		s.serializeMDRecord(rd)
	case MFRecord:
		s.serializeMFRecord(rd)
	case CNameRecord:
		s.serializeCNameRecord(rd)
	case SOARecord:
		s.serializeSOARecord(rd)
	case MBRecord:
		s.serializeMBRecord(rd)
	case MGRecord:
		s.serializeMGRecord(rd)
	case MRRecord:
		s.serializeMRRecord(rd)
	case NullRecord:
		s.serializeNullRecord(rd)
	case WKSRecord:
		s.serializeWKSRecord(rd)
	case PTRRecord:
		s.serializePTRRecord(rd)
	case HInfoRecord:
		s.serializeHInfoRecord(rd)
	case MInfoRecord:
		s.serializeMInfoRecord(rd)
	case MXRecord:
		s.serializeMXRecord(rd)
	case TXTRecord:
		s.serializeTXTRecord(rd)
	default:
		return
	}
}

func (s *dnsWriter) serializeDNSHeader(h DNSHeader) {
	s.writeUint16(h.ID)
	s.writeUint16(h.flags)
	s.writeUint16(h.QDCount)
	s.writeUint16(h.ANCount)
	s.writeUint16(h.NSCount)
	s.writeUint16(h.ARCount)
}

func (s *dnsWriter) serializeDNSQuestion(qs []DNSQuestion) {
	for _, q := range qs {
		s.writeName(q.QName)
		s.writeUint16(uint16(q.QType))
		s.writeUint16(uint16(q.QClass))
	}
}

func (s *dnsWriter) serializeDNSResourceRecord(rrs []DNSResourceRecord) {
	for _, rr := range rrs {
		s.writeName(rr.Name)
		s.writeUint16(uint16(rr.Type))
		s.writeUint16(uint16(rr.Class))
		s.writeUint32(rr.TTL)
		s.writeUint16(rr.RDLength)
		s.writeRData(rr.RData)
	}
}

func SerializeDNSMessage(m DNSMessage) []byte {
	s := dnsWriter{names: make(map[string]int)}
	s.serializeDNSHeader(m.Header)
	s.serializeDNSQuestion(m.Questions)
	s.serializeDNSResourceRecord(m.Answers)
	s.serializeDNSResourceRecord(m.Authorities)
	s.serializeDNSResourceRecord(m.Additionals)
	return s.data
}

func generateID() uint16 {
	return uint16(rand.Intn(1 << 16))
}

func CreateAnswerMessage(q DNSMessage, answers []DNSResourceRecord) DNSMessage {
	header := DNSHeader{
		ID:      q.Header.ID,
		QDCount: q.Header.QDCount,
		ANCount: uint16(len(answers)),
	}
	header.setQR(true)
	header.setRA(true)
	return DNSMessage{
		Header:    header,
		Questions: q.Questions,
		Answers:   answers,
	}
}

func CreateQuery(domain string, qtype RecordType, qclass RecordClass) []byte {
	return SerializeDNSMessage(DNSMessage{
		Header: DNSHeader{
			ID:      generateID(),
			QDCount: 1,
		},
		Questions: []DNSQuestion{
			{
				QName:  domain,
				QType:  qtype,
				QClass: qclass,
			},
		},
	})
}

func CreateErrorResponseMessage(err CustomError) DNSMessage {
	header := DNSHeader{
		ID: err.GetID(),
	}
	header.setQR(true)
	header.setRA(true)
	header.setRCode(uint8(FormErr))
	return DNSMessage{
		Header: header,
	}
}
