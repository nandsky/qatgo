package main

import "testing"

func TestStartTlsServer(t *testing.T) {
	crt_file := "../tools/ssl/server_rsa.crt"
	key_file := "../tools/ssl/server_rsa.key"

	StartTlsServer(crt_file, key_file)
}
