package parser

import (
	"net"
	"reflect"
	"testing"
)

func TestParseDNSMessageQuery(t *testing.T) {
	tests := []struct {
		name        string
		query       []byte
		expectError bool
		expectQName string
		expectQType RecordType
	}{
		{
			name: "valid A query for example.com",
			query: []byte{
				0x12, 0x34,
				0x01, 0x00,
				0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x00, 0x01,
				0x00, 0x01,
			},
			expectError: false,
			expectQName: "example.com.",
			expectQType: 1,
		},
		{
			name: "zero QDCOUNT (invalid)",
			query: []byte{
				0x12, 0x34,
				0x01, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
			expectError: true,
		},
		{
			name: "malformed QName (unterminated)",
			query: []byte{
				0x12, 0x34,
				0x01, 0x00,
				0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // no null terminator
				0x00, 0x01,
				0x00, 0x01,
			},
			expectError: true,
		},
		{
			name: "valid AAAA query for test.local",
			query: []byte{
				0xab, 0xcd,
				0x01, 0x00,
				0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x04, 't', 'e', 's', 't',
				0x05, 'l', 'o', 'c', 'a', 'l',
				0x00,
				0x00, 0x1c, // Type AAAA (28)
				0x00, 0x01,
			},
			expectError: false,
			expectQName: "test.local.",
			expectQType: 28,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseDNSMessage(tt.query, Query)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got none")
				}
				return
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
			}

			if tt.expectQName != "" {
				if len(msg.Questions) != 1 {
					t.Fatalf("expected 1 question, got %d", len(msg.Questions))
				}
				if msg.Questions[0].QName != tt.expectQName {
					t.Errorf("expected QName %s, got %s", tt.expectQName, msg.Questions[0].QName)
				}
				if msg.Questions[0].QType != tt.expectQType {
					t.Errorf("expected QType %d, got %d", tt.expectQType, msg.Questions[0].QType)
				}
			}
		})
	}
}

func TestParseDNSMessageResponse(t *testing.T) {
	tests := []struct {
		name          string
		query         []byte
		expectError   bool
		expectQName   string
		expectQType   RecordType
		expectANCount int

		// RData
		expectIP       net.IP
		expectTarget   string
		expectMXPref   uint16
		expectMXTarget string
		expectTXT      []string
	}{
		{
			name: "valid NS response",
			query: []byte{
				0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x02, 0x00, 0x01,
				0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x3c, 0x00, 0x0F,
				0x02, 'n', 's', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
			},
			expectError:   false,
			expectQName:   "google.com.",
			expectQType:   2,
			expectANCount: 1,
			expectTarget:  "ns.google.com.",
		},
		{
			name: "valid MX response",
			query: []byte{
				0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x0f, 0x00, 0x01,
				0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x3c, 0x00, 0x07,
				0x00, 0x0a, 0x02, 'm', 'x', 0xc0, 0x0c,
			},
			expectError:    false,
			expectQName:    "example.com.",
			expectQType:    15,
			expectANCount:  1,
			expectMXPref:   uint16(10),
			expectMXTarget: "mx.example.com.",
		},
		{
			name: "valid CNAME response",
			query: []byte{
				0xde, 0xad, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x05, 'a', 'l', 'i', 'a', 's', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x05, 0x00, 0x01,
				0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x3c, 0x00, 0x0c,
				0x06, 't', 'a', 'r', 'g', 'e', 't', 0x03, 'c', 'o', 'm', 0x00,
			},
			expectError:   false,
			expectQName:   "alias.com.",
			expectQType:   5,
			expectANCount: 1,
			expectTarget:  "target.com.",
		},
		{
			name: "valid PTR response",
			query: []byte{
				0xaa, 0xaa, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x01, '4', 0x01, '1', 0x01, '0', 0x01, 'i', 0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r', 0x04, 'a', 'r', 'p', 'a', 0x00,
				0x00, 0x0c, 0x00, 0x01,
				0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x3c, 0x00, 0x09,
				0x07, 'p', 't', 'r', 'n', 'a', 'm', 'e', 0x00,
			},
			expectError:   false,
			expectQName:   "4.1.0.i.in-addr.arpa.",
			expectQType:   12,
			expectANCount: 1,
			expectTarget:  "ptrname.",
		},
		{
			name: "valid TXT response",
			query: []byte{
				0xba, 0xad, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x07, 't', 'e', 's', 't', 'd', 'o', 'm', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x10, 0x00, 0x01,
				0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x3c, 0x00, 0x09,
				0x08, 't', 'e', 's', 't', ' ', 't', 'x', 't',
			},
			expectError:   false,
			expectQName:   "testdom.com.",
			expectQType:   16,
			expectANCount: 1,
			expectTXT:     []string{"test txt"},
		},
		{
			name: "valid multi-answer A response with compression",
			query: []byte{

				0x84, 0x76, 0x81, 0x80, 0x00, 0x01, 0x00, 0x06,
				0x00, 0x00, 0x00, 0x00,
				0x03, 'w', 'w', 'w', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x01, 0x00, 0x01,
				// Answer 1
				0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x01, 0x0b, 0x00, 0x04, 0x8e, 0xfa, 0x81, 0x6a,
				// Answer 2
				0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x01, 0x0b, 0x00, 0x04, 0x8e, 0xfa, 0x81, 0x63,
				// Answer 3
				0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x01, 0x0b, 0x00, 0x04, 0x8e, 0xfa, 0x81, 0x68,
				// Answer 4
				0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x01, 0x0b, 0x00, 0x04, 0x8e, 0xfa, 0x81, 0x93,
				// Answer 5
				0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x01, 0x0b, 0x00, 0x04, 0x8e, 0xfa, 0x81, 0x69,
				// Answer 6
				0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x01, 0x0b, 0x00, 0x04, 0x8e, 0xfa, 0x81, 0x67,
			},
			expectError:   false,
			expectQName:   "www.google.com.",
			expectQType:   1,
			expectANCount: 6,
			expectIP:      net.IPv4(142, 250, 129, 106),
		},
		{
			name: "invalid CNAME response with truncated RDATA",
			query: []byte{
				0xde, 0xad, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x05, 'a', 'l', 'i', 'a', 's', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x05, 0x00, 0x01,
				0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x3c, 0x00, 0x01, // RDLENGTH too short for QName
				0x03, 'b', 'a', 'd',
			},
			expectError: true,
		},
		{
			name: "invalid CNAME with bad compression offset",
			query: []byte{
				0xde, 0xaf, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x05, 'f', 'a', 'k', 'e', 's', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x05, 0x00, 0x01,
				0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x3c, 0x00, 0x02,
				0xc0, 0xff, // offset points out of bounds
			},
			expectError: true,
		},
		{
			name: "invalid CNAME with infinite pointer loop",
			query: []byte{
				0xbe, 0xef, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x05, 'l', 'o', 'o', 'p', 's', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x05, 0x00, 0x01,
				0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x3c, 0x00, 0x02,
				0xc0, 0x27, // points to itself repeatedly
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseDNSMessage(tt.query, Response)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if tt.expectQName != "" {
				if len(msg.Questions) != 1 {
					t.Fatalf("expected 1 question, got %d", len(msg.Questions))
				}
				if msg.Questions[0].QName != tt.expectQName {
					t.Errorf("expected QName %s, got %s", tt.expectQName, msg.Questions[0].QName)
				}
				if msg.Questions[0].QType != tt.expectQType {
					t.Errorf("expected QType %d, got %d", tt.expectQType, msg.Questions[0].QType)
				}
			}
			if len(msg.Answers) != tt.expectANCount {
				t.Errorf("expected %d answers, got %d", tt.expectANCount, len(msg.Answers))
			}
			switch v := msg.Answers[0].RData.(type) {
			case ARecord:
				if !v.IP.Equal(tt.expectIP) {
					t.Errorf("Expected IP %v, got %v", tt.expectIP, v.IP)
				}
			case NSRecord:
				if v.Name != tt.expectTarget {
					t.Errorf("Expected Name %v, got %v", tt.expectTarget, v.Name)
				}
			case CNameRecord:
				if v.Name != tt.expectTarget {
					t.Errorf("Expected Name %v, got %v", tt.expectTarget, v.Name)
				}
			case PTRRecord:
				if v.Name != tt.expectTarget {
					t.Errorf("Expected Name %v, got %v", tt.expectTarget, v.Name)
				}
			case MXRecord:
				if v.Preference != tt.expectMXPref {
					t.Errorf("Expected Name %v, got %v", tt.expectMXPref, v.Preference)
				}
				if v.Exchange != tt.expectMXTarget {
					t.Errorf("Expected Name %v, got %v", tt.expectMXTarget, v.Exchange)
				}
			case TXTRecord:
				if tt.expectTXT != nil && !reflect.DeepEqual(v.Data, tt.expectTXT) {
					t.Errorf("Expected TXT %v, got %v", tt.expectTXT, v.Data)
				}
			}
		})
	}
}
