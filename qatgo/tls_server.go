package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
)

func handler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	fmt.Fprintln(w, "Your conn state is: ", req.TLS)
	fmt.Fprintln(w, "Your client cert is: ", req.TLS.PeerCertificates)
}

func StartTlsServer(certFile string, keyFile string) {

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	tlscfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	srv := &http.Server{Addr: ":8443", Handler: nil}

	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatal(err)
	}
	tl := tls.NewListener(l, tlscfg)

	http.HandleFunc("/", handler)
	srv.Serve(tl)
}
