package parser

import (
	"fmt"
	"net"
	"strings"

	"go.uber.org/zap"
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

	RTAAAA RecordType = 28

	RTAXFR  RecordType = 252
	RTMAILB RecordType = 253
	RTMAILA RecordType = 254
	RTSTAR  RecordType = 255
)

func (rt RecordType) String() string {
	switch rt {
	case RTA:
		return "A"
	case RTNS:
		return "NS"
	case RTMD:
		return "MD"
	case RTMF:
		return "MF"
	case RTCNAME:
		return "CNAME"
	case RTSOA:
		return "SOA"
	case RTMB:
		return "MB"
	case RTMG:
		return "MG"
	case RTMR:
		return "MR"
	case RTNULL:
		return "NULL"
	case RTWKS:
		return "WKS"
	case RTPTR:
		return "PTR"
	case RTHINFO:
		return "HINFO"
	case RTMINFO:
		return "MINFO"
	case RTMX:
		return "MX"
	case RTTXT:
		return "TXT"
	case RTAXFR:
		return "AXFR"
	case RTMAILB:
		return "MAILB"
	case RTMAILA:
		return "MAILA"
	case RTSTAR:
		return "*"
	}
	return "?"
}

type RecordClass uint16

const (
	RCIN RecordClass = 1
	RCCS RecordClass = 2
	RCCH RecordClass = 3
	RCHS RecordClass = 4

	RCSTAR RecordClass = 255
)

func (rc RecordClass) String() string {
	switch rc {
	case RCIN:
		return "IN"
	case RCCS:
		return "CS"
	case RCCH:
		return "HS"
	case RCSTAR:
		return "*"
	}
	return "?"
}

type CustomError interface {
	Error() string
	Unwrap() error
	GetID() uint16
}

type FormError struct {
	Err error
	ID  uint16
}

func (e FormError) Error() string {
	return fmt.Sprintf("FORMERR(id=%d): %v", e.ID, e.Err)
}

func (e FormError) Unwrap() error {
	return e.Err
}

func (e FormError) GetID() uint16 {
	return e.ID
}

type ServFailError struct {
	Err error
	ID  uint16
}

func (e ServFailError) Error() string {
	return fmt.Sprintf("SERVFAIL(id=%d): %v", e.ID, e.Err)
}

func (e ServFailError) Unwrap() error {
	return e.Err
}

func (e ServFailError) GetID() uint16 {
	return e.ID
}

type NXDomainError struct {
	Err error
	ID  uint16
}

func (e NXDomainError) Error() string {
	return fmt.Sprintf("NXDOMAIN(id=%d): %v", e.ID, e.Err)
}

func (e NXDomainError) Unwrap() error {
	return e.Err
}

func (e NXDomainError) GetID() uint16 {
	return e.ID
}

type NotImpError struct {
	Err error
	ID  uint16
}

func (e NotImpError) Error() string {
	return fmt.Sprintf("NOTIMP(id=%d): %v", e.ID, e.Err)
}

func (e NotImpError) Unwrap() error {
	return e.Err
}

func (e NotImpError) GetID() uint16 {
	return e.ID
}

type RefusedError struct {
	Err error
	ID  uint16
}

func (e RefusedError) Error() string {
	return fmt.Sprintf("REFUSED(id=%d): %v", e.ID, e.Err)
}

func (e RefusedError) Unwrap() error {
	return e.Err
}

func (e RefusedError) GetID() uint16 {
	return e.ID
}

type OpCode uint8

const (
	OCQUERY OpCode = iota
	OCIQUERY
	OCSTATUS
)

func (oc OpCode) String() string {
	switch oc {
	case OCQUERY:
		return "QUERY"
	case OCIQUERY:
		return "IQUERY"
	case OCSTATUS:
		return "STATUS"
	}
	return "?"
}

type RCode uint8

const (
	NoError RCode = iota
	FormErr
	ServFail
	NXDomain
	NotImp
	Refused
)

func (rc RCode) String() string {
	switch rc {
	case NoError:
		return "NOERR"
	case FormErr:
		return "FORMERR"
	case ServFail:
		return "SERVFAIL"
	case NXDomain:
		return "NXDOMAIN"
	case NotImp:
		return "NOTIMP"
	case Refused:
		return "REFUSED"
	}
	return "?"
}

const (
	QRMask     = 0x8000
	OpcodeMask = 0x7800
	AAMask     = 0x0400
	TCMask     = 0x0200
	RDMask     = 0x0100
	RAMask     = 0x0080
	ZMask      = 0x0070
	RCodeMask  = 0x000F
)

const PointerMask = 0xC0
const OffsetMask = 0x3F

type parseStatus int

const (
	parsingHeader parseStatus = iota
	parsingQuestion
	parsingResourceRecords
)

type RData interface {
	String() string
}

type ARecord struct {
	IP net.IP
}

func (r ARecord) String() string {
	return r.IP.String()
}

type NSRecord struct {
	Name string
}

func (r NSRecord) String() string {
	return r.Name
}

type MDRecord struct {
	Name string
}

func (r MDRecord) String() string {
	return r.Name
}

type MFRecord struct {
	Name string
}

func (r MFRecord) String() string {
	return r.Name
}

type CNameRecord struct {
	Name string
}

func (r CNameRecord) String() string {
	return r.Name
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

func (r SOARecord) String() string {
	return fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%d\t%d", r.MName, r.RName, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum)
}

type MBRecord struct {
	Name string
}

func (r MBRecord) String() string {
	return r.Name
}

type MGRecord struct {
	Name string
}

func (r MGRecord) String() string {
	return r.Name
}

type MRRecord struct {
	Name string
}

func (r MRRecord) String() string {
	return r.Name
}

type NullRecord struct {
	Anything []byte
}

func (r NullRecord) String() string {
	return string(r.Anything)
}

type WKSRecord struct {
	Address  net.IP
	Protocol uint8
	Bitmap   []byte
}

func (r WKSRecord) String() string {
	return fmt.Sprintf("%v\t%d\t%v", r.Address, r.Protocol, r.Bitmap)
}

type PTRRecord struct {
	Name string
}

func (r PTRRecord) String() string {
	return r.Name
}

type HInfoRecord struct {
	CPU string
	OS  string
}

func (r HInfoRecord) String() string {
	return fmt.Sprintf("%s\t%s", r.CPU, r.OS)
}

type MInfoRecord struct {
	RMailBX string
	EMailBX string
}

func (r MInfoRecord) String() string {
	return fmt.Sprintf("%s\t%s", r.RMailBX, r.EMailBX)
}

type MXRecord struct {
	Preference uint16
	Exchange   string
}

func (r MXRecord) String() string {
	return fmt.Sprintf("%d\t%s", r.Preference, r.Exchange)
}

type TXTRecord struct {
	Data []string
}

func (r TXTRecord) String() string {
	res := ""
	for _, s := range r.Data {
		res += s + ";"
	}
	return res
}

type AAAARecord struct {
	IP net.IP
}

func (r AAAARecord) String() string {
	return r.IP.String()
}

type DNSHeader struct {
	ID      uint16
	flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h DNSHeader) String() string {
	flagsStr := ""
	if h.GetQR() {
		flagsStr += "qr "
	}
	if h.GetAA() {
		flagsStr += "aa "
	}
	if h.GetTC() {
		flagsStr += "tc "
	}
	if h.GetRD() {
		flagsStr += "rd "
	}
	if h.GetRA() {
		flagsStr += "ra "
	}
	flagsStr = strings.TrimSuffix(flagsStr, " ")
	return fmt.Sprintf("flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d", flagsStr, h.QDCount, h.ANCount, h.NSCount, h.ARCount)
}

type DNSQuestion struct {
	QName  string
	QType  RecordType
	QClass RecordClass
}

func (q DNSQuestion) String() string {
	return fmt.Sprintf("%s\t%v\t%v", q.QName, q.QClass, q.QType)
}

type DNSResourceRecord struct {
	Name     string
	Type     RecordType
	Class    RecordClass
	TTL      uint32
	RDLength uint16
	RData    RData
}

func (rr DNSResourceRecord) String() string {
	return fmt.Sprintf("%s\t%d\t%v\t%v\t%v", rr.Name, rr.TTL, rr.Class, rr.Type, rr.RData)
}

type DNSMessage struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSResourceRecord
	Authorities []DNSResourceRecord
	Additionals []DNSResourceRecord
}

func (m DNSMessage) String() string {
	qs := ""
	if len(m.Questions) > 0 {
		qs = "QUESTION SECTION:\n"
	}
	for _, q := range m.Questions {
		qs += q.String() + "\n"
	}
	ans := ""
	if len(m.Answers) > 0 {
		ans = "ANSWER SECTION:\n"
	}
	for _, a := range m.Answers {
		ans += a.String() + "\n"
	}
	auths := ""
	if len(m.Authorities) > 0 {
		auths = "AUTHORITY SECTION:\n"
	}
	for _, a := range m.Authorities {
		auths += a.String() + "\n"
	}
	adds := ""
	if len(m.Additionals) > 0 {
		adds = "ADDITIONALS SECTION:\n"
	}
	for _, a := range m.Additionals {
		adds += a.String() + "\n"
	}
	return fmt.Sprintf("->>HEADER<<- opcode: %v, status: %v, id: %d\n%v\n%s%s%s%s", m.Header.GetOpcode(), m.Header.GetRCode(), m.Header.ID, m.Header, qs, ans, auths, adds)
}

type dnsReader struct {
	id          uint16
	data        []byte
	pos         int
	parseStatus parseStatus
	offsetStack []uint16
	logger      *zap.Logger
}

type dnsWriter struct {
	data   []byte
	names  map[string]int
	logger *zap.Logger
}
