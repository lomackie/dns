package resolver

import (
	"dns/internal/parser"
	"dns/internal/server"
	"errors"
	"math/rand"
	"net"
	"strings"

	"go.uber.org/zap"
)

type Resolver struct {
	cache  *cache
	logger *zap.Logger
}

var rootServers = []net.IP{
	net.IPv4(198, 41, 0, 4),
	net.IPv4(199, 9, 14, 201),
	net.IPv4(192, 33, 4, 12),
	net.IPv4(199, 7, 91, 13),
	net.IPv4(192, 5, 5, 241),
	net.IPv4(192, 203, 230, 10),
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
		if ns, ok := authority.RData.(parser.NSRecord); ok {
			authorities[ns.Name] = nil
		}
	}
	for _, additional := range msg.Additionals {
		if _, ok := authorities[additional.Name]; !ok {
			continue
		}
		ip := getRecordIP(additional)
		if ip != nil {
			authorities[additional.Name] = ip
		}
	}
	return authorities
}

func getZone(msg parser.DNSMessage) string {
	for _, record := range msg.Authorities {
		if record.Type == parser.RTNS {
			return record.Name
		}
	}
	return ""
}

func inZone(name, zone string) bool {
	return strings.HasSuffix(name, zone)
}

func (r *Resolver) cacheMessage(domain string, msg parser.DNSMessage) {
	// Cache all answers
	for _, record := range msg.Answers {
		r.cache.Add(record)
	}
	// Cache all NS authorities
	for _, record := range msg.Authorities {
		r.cache.Add(record)
	}
	// Cache in Zone additionals
	zone := getZone(msg)
	for _, record := range msg.Additionals {
		if record.Type == parser.RTA && inZone(record.Name, zone) {
			r.cache.Add(record)
		}
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

func (r *Resolver) resolveOnce(domain string, qtype parser.RecordType, qclass parser.RecordClass, ns net.IP) (parser.DNSMessage, error) {
	q := parser.CreateQuery(domain, qtype, qclass)
	res, err := server.SendMessage(q, ns, server.UDP)
	if err != nil {
		return parser.DNSMessage{}, err
	}
	msg, err := parser.ParseDNSMessage(res, parser.Response)
	if err != nil {
		return parser.DNSMessage{}, err
	}
	if msg.Header.GetTC() {
		r.logger.Debug("Response was truncated, Retrying with TCP")
		q = parser.CreateQuery(domain, qtype, qclass)
		res, err = server.SendMessage(q, ns, server.TCP)
		if err != nil {
			return parser.DNSMessage{}, err
		}
		msg, err = parser.ParseDNSMessage(res, parser.Response)
		if err != nil {
			return parser.DNSMessage{}, err
		}
	}
	r.logger.Debug("Intermediate response", zap.String("Message", msg.String()))
	return msg, nil
}

func hasResultRecord(domain string, qtype parser.RecordType, qclass parser.RecordClass, answers []parser.DNSResourceRecord) bool {
	for _, ans := range answers {
		if qtype == ans.Type && qclass == ans.Class {
			if ans.Name == domain {
				return true
			}
		}
	}
	return false
}

func getMatchingCNAME(domain string, qclass parser.RecordClass, answers []parser.DNSResourceRecord) *parser.DNSResourceRecord {
	for _, ans := range answers {
		if ans.Class == qclass && ans.Type == parser.RTCNAME && ans.Name == domain {
			return &ans
		}
	}
	return nil
}

func (r *Resolver) followCNAMEs(domain string, qtype parser.RecordType, qclass parser.RecordClass, answers []parser.DNSResourceRecord) ([]parser.DNSResourceRecord, error) {
	followedCNAMEs := make([]parser.DNSResourceRecord, 0)
	seen := make(map[string]int)
	resultAnswers := answers
	target := domain
	for {
		if hasResultRecord(target, qtype, qclass, resultAnswers) {
			resultAnswers = append(followedCNAMEs, resultAnswers...)
			return resultAnswers, nil
		}
		cn := getMatchingCNAME(target, qclass, resultAnswers)
		if cn == nil {
			return nil, errors.New("No matching result and no CNAME")
		}
		if _, ok := seen[cn.Name]; ok {
			return nil, errors.New("CNAME loop")
		}
		seen[cn.Name] = 1
		followedCNAMEs = append(followedCNAMEs, *cn)
		target = cn.RData.(parser.CNameRecord).Name
		result, err := r.Resolve(target, qtype, qclass)
		if err != nil {
			return nil, err
		}
		resultAnswers = result
	}
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
		msg, err := r.resolveOnce(domain, qtype, qclass, ns)
		r.cacheMessage(domain, msg)
		if err != nil {
			return nil, err
		}
		r.logger.Debug("Intermediate response", zap.String("Message", msg.String()))
		if msg.Header.ANCount > 0 {
			r.logger.Debug("Answer recieved, checking for CNAME")
			answers, err := r.followCNAMEs(domain, qtype, qclass, msg.Answers)
			if err != nil {
				return nil, err
			}
			return answers, nil
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
