package main

import (
	"dns/internal/parser"
	"dns/internal/resolver"
	"fmt"
	"log"
)

func main() {
	msg, err := resolver.Resolve("google.com", parser.RTA)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", msg.Answers[0])
}
