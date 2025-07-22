package server

import (
	"errors"
	"fmt"
	"net"
)

type Protocol int

const (
	UDP Protocol = iota
	TCP
)

func SendMessage(data []byte, host net.IP, protocol Protocol) ([]byte, error) {
	switch protocol {
	case UDP:
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:53", host))
		if err != nil {
			return nil, err
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return nil, err
		}
		conn.Write(data)

		resp := make([]byte, 512)
		n, _, err := conn.ReadFromUDP(resp)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Response bytes: %v\n", resp[:n])
		return resp[:n], nil
	case TCP:
		addr, err := net.ResolveTCPAddr("udp", fmt.Sprintf("%v:53", host))
		if err != nil {
			return nil, err
		}
		conn, err := net.DialTCP("tcp", nil, addr)
		conn.Write(data)
		resp := make([]byte, 512)
		n, err := conn.Read(resp)
		fmt.Printf("Response bytes: %v\n", resp[:n])
		return resp[:n], nil
	default:
		return nil, errors.New("?")
	}
}
