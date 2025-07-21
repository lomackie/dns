package parser

import "net"

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

type dnsSerializer struct {
	data  []byte
	names map[string]int
}
