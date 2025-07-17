package parser

import (
	"testing"
)

func TestParseDNSMessage(t *testing.T) {
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
