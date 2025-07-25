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
		defer conn.Close()
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}

		resp := make([]byte, 512)
		n, _, err := conn.ReadFromUDP(resp)
		if err != nil {
			return nil, err
		}
		return resp[:n], nil
	case TCP:
		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%v:53", host))
		if err != nil {
			return nil, err
		}
		conn, err := net.DialTCP("tcp", nil, addr)
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		length := uint16(len(data))
		lengthBuf := []byte{byte(length >> 8), byte(length & 0xFF)}
		_, err = conn.Write(append(lengthBuf, data...))
		if err != nil {
			return nil, err
		}

		lengthPre := make([]byte, 2)
		_, err = conn.Read(lengthPre)
		if err != nil {
			return nil, err
		}
		respLength := int(lengthPre[0])<<8 | int(lengthPre[1])
		resp := make([]byte, respLength)
		_, err = conn.Read(resp)
		if err != nil {
			return nil, err
		}
		return resp, nil
	default:
		return nil, errors.New("?")
	}
}
