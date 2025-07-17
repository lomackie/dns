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
		n, clientAddr, _ := conn.ReadFromUDP(buf)
		m, err := parser.ParseDNSMessage(buf[:n], parser.Query)
		if err != nil {
			log.Fatal(err)
		}
		remoteAddr, _ := net.ResolveUDPAddr("udp", "1.1.1.1:53")
		remoteConn, _ := net.DialUDP("udp", nil, remoteAddr)
		remoteConn.Write(buf[:n])
		fmt.Println(m)

		resp := make([]byte, 512)
		rn, _, err := remoteConn.ReadFromUDP(resp)
		fmt.Println(resp[:rn])
		conn.WriteToUDP(resp[:rn], clientAddr)
		m2, err := parser.ParseDNSMessage(resp[:rn], parser.Response)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(m2)

	}
}
