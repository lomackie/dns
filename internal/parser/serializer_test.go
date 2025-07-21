package parser

import (
	"bytes"
	"testing"
)

func TestCreateQuery_SerializesToExpectedBytes(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		qtype        RecordType
		expectedWire []byte
	}{
		{
			name:   "valid A query for example.com",
			domain: "example.com.",
			qtype:  RTA,
			expectedWire: []byte{
				0x00, 0x00, 0x00, 0x00, // ID + flags
				0x00, 0x01, 0x00, 0x00, // QDCOUNT=1, ANCOUNT=0
				0x00, 0x00, 0x00, 0x00, // NSCOUNT=0, ARCOUNT=0
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
			},
		},
		{
			name:   "valid NS query for google.com",
			domain: "google.com.",
			qtype:  RTNS,
			expectedWire: []byte{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x06, 'g', 'o', 'o', 'g', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x02, // Type NS
				0x00, 0x01, // Class IN
			},
		},
		{
			name:   "valid MX query for test.org",
			domain: "test.org.",
			qtype:  RTMX,
			expectedWire: []byte{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x04, 't', 'e', 's', 't',
				0x03, 'o', 'r', 'g',
				0x00,
				0x00, 0x0f, // Type MX
				0x00, 0x01, // Class IN
			},
		},
		{
			name:   "valid PTR query for 4.3.2.1.in-addr.arpa",
			domain: "4.3.2.1.in-addr.arpa.",
			qtype:  RTPTR,
			expectedWire: []byte{
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x01, '4',
				0x01, '3',
				0x01, '2',
				0x01, '1',
				0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r',
				0x04, 'a', 'r', 'p', 'a',
				0x00,
				0x00, 0x0c, // Type PTR
				0x00, 0x01,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := CreateQuery(tt.domain, tt.qtype)
			if len(query) != len(tt.expectedWire) {
				t.Fatalf("length mismatch: got %d, want %d", len(query), len(tt.expectedWire))
			}
			if !bytes.Equal(query[2:], tt.expectedWire[2:]) {
				t.Errorf("byte mismatch (excluding ID):\ngot  %v\nwant %v", query[2:], tt.expectedWire[2:])
			}
		})
	}
}
