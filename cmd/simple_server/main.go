package main

import (
	"dns/internal/parser"
	"dns/internal/resolver"
	"fmt"
	"log"
	"net"
)

func main() {
	addr, _ := net.ResolveUDPAddr("udp", ":53")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	r := resolver.NewResolver()
	log.Println("Listening on :53")
	buf := make([]byte, 512)
	for {
		n, clientAddr, _ := conn.ReadFromUDP(buf)
		m, err := parser.ParseDNSMessage(buf[:n], parser.Query)
		if err != nil {
			log.Fatal(err)
		}
		ans, err := r.ResolveQuery(m)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Our resolution:%v\n", ans)
		resp := parser.SerializeDNSMessage(ans)
		fmt.Printf("Our response:%v\n", resp)
		conn.WriteToUDP(resp, clientAddr)
		if err != nil {
			log.Fatal(err)
		}
	}
}
