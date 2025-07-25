package resolver

import (
	"dns/internal/parser"
	"dns/internal/server"
	"errors"
	"math/rand"
	"net"

	"go.uber.org/zap"
)

type Resolver struct {
	cache  *cache
	logger *zap.Logger
}

var rootServers = []net.IP{
	net.IPv4(170, 247, 170, 2),
	net.IPv4(192, 33, 4, 12),
	net.IPv4(199, 7, 91, 13),
	net.IPv4(192, 203, 230, 10),
	net.IPv4(192, 5, 5, 251),
	net.IPv4(198, 97, 190, 53),
	net.IPv4(192, 36, 148, 17),
	net.IPv4(193, 0, 14, 129),
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

func (r *Resolver) cacheMessage(domain string, msg parser.DNSMessage) {
	for _, record := range msg.Answers {
		r.cache.Add(domain, record)
	}
	for _, record := range msg.Authorities {
		r.cache.Add(domain, record)
	}
	for _, record := range msg.Additionals {
		r.cache.Add(domain, record)
	}
}

func (r *Resolver) getAuthority(msg parser.DNSMessage) (net.IP, error) {
	authorities := getAuthorities(msg)
	for _, v := range authorities {
		if v != nil {
			return v, nil
		}
	}
	for k, _ := range authorities {
		ans, err := r.Resolve(k, parser.RTA, parser.RCIN)
		if err != nil {
			continue
		}
		ip := getRecordIP(ans[rand.Intn(len(ans))])
		if ip != nil {
			return ip, nil
		}
	}
	return nil, errors.New("Could not resolve any authorities")
}

func (r *Resolver) resolveOnce(domain string, qtype parser.RecordType, qclass parser.RecordClass, ns net.IP, protocol server.Protocol) (parser.DNSMessage, error) {
	q := parser.CreateQuery(domain, qtype, qclass)
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

func (r *Resolver) Resolve(domain string, qtype parser.RecordType, qclass parser.RecordClass) ([]parser.DNSResourceRecord, error) {
	ck := cacheKey{domain, qtype, qclass}
	val, found := r.cache.Get(ck)
	if found {
		r.logger.Debug("Cache hit", zap.String("Key", ck.String()))
		return val, nil
	}
	ns := getRootNameserver()
	for {
		r.logger.Debug("Resolving", zap.String("Nameserver", ns.String()))
		msg, err := r.resolveOnce(domain, qtype, qclass, ns, server.UDP)
		if err != nil {
			return nil, err
		}
		r.logger.Debug("Intermediate response", zap.String("Message", msg.String()))
		if msg.Header.GetTC() {
			r.logger.Debug("Response was truncated, Retrying with TCP")
			msg, err = r.resolveOnce(domain, qtype, qclass, ns, server.TCP)
			r.logger.Debug("Intermediate response", zap.String("Message", msg.String()))
			if err != nil {
				return nil, err
			}
		}
		if msg.Header.ANCount > 0 {
			r.logger.Debug("Answer recieved")
			r.cacheMessage(domain, msg)
			return msg.Answers, nil
		}
		ns, err = r.getAuthority(msg)
		if err != nil {
			return nil, err
		}
	}
}

func (r *Resolver) ResolveQuery(q parser.DNSMessage) (parser.DNSMessage, error) {
	answers := make([]parser.DNSResourceRecord, 0)
	for _, question := range q.Questions {
		domain := question.QName
		qtype := question.QType
		qclass := question.QClass

		ans, err := r.Resolve(domain, qtype, qclass)
		if err != nil {
			return parser.DNSMessage{}, err
		}
		answers = append(answers, ans...)
	}
	return parser.CreateAnswerMessage(q, answers), nil
}

func NewResolver(logger *zap.Logger) Resolver {
	return Resolver{
		cache:  NewCache(logger),
		logger: logger,
	}
}
