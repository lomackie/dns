# Recursive DNS Resolver in Go

This project aims to be a simple recursive DNS resolver written in Go.
It aims to implement RFC 1034/1035.

AI was used to write tests, code is my own.

## Querying the DNS Resolver locally

If using `dig`, `+noadflag +nocdflag +noedns` should be set to conform to RFC 1035.
