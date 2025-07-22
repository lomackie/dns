package resolver

import (
	"dns/internal/parser"
	"dns/internal/server"
	"errors"
	"fmt"
	"math/rand"
	"net"
)

var rootServers = []net.IP{
	net.IPv4(192, 41, 0, 4),
	net.IPv4(170, 247, 170, 2),
	net.IPv4(192, 33, 4, 12),
	net.IPv4(199, 7, 91, 13),
	net.IPv4(192, 203, 230, 10),
	net.IPv4(192, 5, 5, 251),
	net.IPv4(198, 97, 190, 53),
	net.IPv4(192, 36, 148, 17),
	net.IPv4(192, 58, 128, 30),
	net.IPv4(193, 0, 14, 129),
	net.IPv4(199, 7, 83, 43),
	net.IPv4(202, 12, 27, 33),
}

func getRootNameserver() net.IP {
	return rootServers[rand.Intn(len(rootServers))]
}

func getRecordIP(rr parser.DNSResourceRecord) net.IP {
	switch rd := rr.RData.(type) {
	case parser.ARecord:
		return rd.IP
	}
	return nil
}

func getAuthorities(msg parser.DNSMessage) map[string]net.IP {
	authorities := make(map[string]net.IP)
	for _, authority := range msg.Authorities {
		authorities[authority.Name] = nil
	}
	for _, additional := range msg.Additionals {
		ip := getRecordIP(additional)
		if ip != nil {
			authorities[additional.Name] = ip
		}
	}
	return authorities
}

func getAuthority(msg parser.DNSMessage) (net.IP, error) {
	authorities := getAuthorities(msg)
	for _, v := range authorities {
		if v != nil {
			return v, nil
		}
	}
	for k, _ := range authorities {
		msg, err := Resolve(k, parser.RTA)
		if err != nil {
			continue
		}
		ip := getRecordIP(msg.Answers[0])
		if ip != nil {
			return ip, nil
		}
	}
	return nil, errors.New("Could not resolve any authorities")
}

func resolveOnce(domain string, qtype parser.RecordType, ns net.IP, protocol server.Protocol) (parser.DNSMessage, error) {
	q := parser.CreateQuery(domain, qtype)
	fmt.Printf("Outgoing query: %v\n", q)
	res, err := server.SendMessage(q, ns, protocol)
	if err != nil {
		return parser.DNSMessage{}, err
	}
	msg, err := parser.ParseDNSMessage(res, parser.Response)
	if err != nil {
		return parser.DNSMessage{}, err
	}
	return msg, nil
}

func Resolve(domain string, qtype parser.RecordType) (parser.DNSMessage, error) {
	ns := getRootNameserver()
	for {
		msg, err := resolveOnce(domain, qtype, ns, server.UDP)
		if err != nil {
			return parser.DNSMessage{}, err
		}
		if msg.Header.GetTC() {
			msg, err = resolveOnce(domain, qtype, ns, server.TCP)
			if err != nil {
				return parser.DNSMessage{}, err
			}
		}
		if len(msg.Answers) > 0 {
			return msg, nil
		}
		ns, err = getAuthority(msg)
		if err != nil {
			return parser.DNSMessage{}, err
		}
	}
}
