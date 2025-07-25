package main

import (
	"dns/internal/parser"
	"dns/internal/resolver"
	"errors"
	"net"

	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	addr, _ := net.ResolveUDPAddr("udp", ":53")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	r := resolver.NewResolver(logger)
	logger.Info("Listening on :53")
	buf := make([]byte, 512)
	for {
		n, clientAddr, _ := conn.ReadFromUDP(buf)
		logger.Info("New connection", zap.String("IP", clientAddr.String()))
		m, err := parser.ParseDNSMessage(buf[:n], parser.Query)
		logger.Debug("Incoming Query", zap.String("Message", m.String()))
		if err != nil {
			logger.Error(err.Error())
			r := getErrorResponse(err)
			if r != nil {
				conn.WriteToUDP(r, clientAddr)
			}
			continue
		}
		ans, err := r.ResolveQuery(m)
		logger.Debug("Response to client", zap.String("Message", ans.String()))
		if err != nil {
			logger.Error(err.Error())
			r := getErrorResponse(err)
			if r != nil {
				conn.WriteToUDP(r, clientAddr)
			}
			continue
		}
		resp := parser.SerializeDNSMessage(ans)
		_, err = conn.WriteToUDP(resp, clientAddr)
		if err != nil {
			logger.Error(err.Error())
		}
	}
}

func getErrorResponse(err error) []byte {
	var ce parser.CustomError
	if errors.As(err, &ce) {
		return parser.SerializeDNSMessage(parser.CreateErrorResponseMessage(ce))
	}
	return nil
}
