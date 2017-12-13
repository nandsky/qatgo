package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	pb "github.com/nandsky/qatgo/qatgo/server/job"
	"io/ioutil"
	"testing"
)

// RSA
func TestRsa(t *testing.T) {
	// 构建密文
	flag.Parse()
	crt_file := "../../tools/ssl/server_rsa.crt"

	pemPublicKey, err := ioutil.ReadFile(crt_file)
	if err != nil {
		t.Error(err)
		return
	}

	block, _ := pem.Decode([]byte(pemPublicKey))

	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPub := cert.PublicKey.(*rsa.PublicKey)
	plaintext := "helloworld!"

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
		return
	}

	qc, err := NewQatClient()
	if err != nil {
		t.Fatalf("create qat client failed: %s", err.Error())
		return
	}

	cipherText = make([]byte, 1024)
	// 调用RPC服务
	new_job := &pb.JobRequest{
		OpType:  1,
		Sni:     "test_rsa",
		Payload: cipherText,
	}

	if err != nil {
		panic(err)
	}
	t.Log("begin rpc call")
	response, err := qc.Run(new_job)
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
}

// ECDSA
func TestECDSA(t *testing.T) {
	qc, err := NewQatClient()
	if err != nil {
		t.Fatalf("create qat client failed: %s", err.Error())
		return
	}

	// 调用RPC服务
	new_job := &pb.JobRequest{
		OpType:  1,
		Sni:     "test_ecdsa",
		Payload: []byte("fssa"),
	}

	if err != nil {
		panic(err)
	}
	response, err := qc.Run(new_job)
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
}

func BenchmarkNewQatClient(t *testing.B) {
	// 构建密文
	flag.Parse()
	crt_file := "../ssl/server_rsa.crt"

	pemPublicKey, err := ioutil.ReadFile(crt_file)
	if err != nil {
		t.Error(err)
		return
	}

	block, _ := pem.Decode([]byte(pemPublicKey))

	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPub := cert.PublicKey.(*rsa.PublicKey)
	plaintext := "helloworld!"

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
		return
	}
	t.ResetTimer()

	for i := 0; i < t.N; i++ {
		go func() {
			qc, err := NewQatClient()
			if err != nil {
				t.Fatalf("create qat client failed: %s", err.Error())
				return
			}

			// 调用RPC服务
			new_job := &pb.JobRequest{
				OpType:  1,
				Sni:     "test",
				Payload: cipherText,
			}

			if err != nil {
				panic(err)
			}
			_, err = qc.Run(new_job)
			if err != nil {
				t.Error(err)
			}
		}()
		//t.Log(response)
	}
}
