package main

import (
	"dns/internal/parser"
	"fmt"
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
		n, _, _ := conn.ReadFromUDP(buf)
		m, err := parser.ParseDNSMessage(buf[:n])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(m)
	}
}
