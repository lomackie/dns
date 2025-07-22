package main

import (
	"dns/internal/parser"
	"dns/internal/resolver"
	"log"
	"net"
)

func main() {
	addr, _ := net.ResolveUDPAddr("udp", ":53")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	log.Println("Listening on :53")
	buf := make([]byte, 512)
	for {
		n, clientAddr, _ := conn.ReadFromUDP(buf)
		m, err := parser.ParseDNSMessage(buf[:n], parser.Query)
		if err != nil {
			log.Fatal(err)
		}
		ans, err := resolver.Resolve(m.Questions[0].QName, m.Questions[0].QType)
		ans.Header.ID = m.Header.ID
		resp := parser.SerializeDNSMessage(ans)
		conn.WriteToUDP(resp, clientAddr)
		if err != nil {
			log.Fatal(err)
		}
	}
}
