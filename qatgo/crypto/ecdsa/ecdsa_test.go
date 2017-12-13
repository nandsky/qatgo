package ecdsa

import (
	go_ecdsa "crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	cy "github.com/nandsky/qatgo/qatgo/crypto"
	"testing"
)

func TestEcdsa(t *testing.T) {
	crt_file := "../../../tools/ssl/server_ecdsa.crt"
	key_file := "../../../tools/ssl/server_ecdsa.key"

	// 加载crt和key
	cert, err := tls.LoadX509KeyPair(crt_file, key_file)
	if err != nil {
		t.Error(err)
		return
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	pub := x509Cert.PublicKey.(*go_ecdsa.PublicKey)
	pk := cert.PrivateKey.(*go_ecdsa.PrivateKey)

	dumpHex(pub, pk, t)
	dumpInt(pub, pk, t)
}

func TestContext_SignAndVerify(t *testing.T) {
	crt_file := "../ssl/server_ecdsa.crt"
	key_file := "../ssl/server_ecdsa.key"

	_, err := cy.QatInit()
	if err != nil {
		t.Error(err)
		return
	}

	nc, err := NewContext(crt_file, key_file)
	if err != nil {
		t.Fatalf("create context failed: %s", err.Error())
	}
	//nc.SetAsyncMode(true)
	digest := []byte("afdada1")
	r, s, err := nc.Sign(digest)
	if err != nil {
		t.Fatalf("sign failed: %s", err.Error())
	}
	//t.Logf("r: %d, s: %d", len(r), len(s))

	result, err := nc.Verify(digest, r, s)

	t.Logf("finish: result: %s", result)
	cy.QatExit()
}

type PsudoRandReader struct {
}

func (r *PsudoRandReader) Read(p []byte) (n int, err error) {
	pLen := len(p)
	for i := 0; i < pLen; i++ {
		p[i] = 1
	}
	return pLen, nil
}

var cread1 PsudoRandReader

func TestContext_Sign2(t *testing.T) {
	crt_file := "../ssl/server_ecdsa.crt"
	key_file := "../ssl/server_ecdsa.key"

	cp, err := NewContextParam(crt_file, key_file)
	if err != nil {
		t.Fatal(err.Error())
	}
	hashD := []byte("afdada")
	r, s, err := go_ecdsa.Sign(&cread1, cp.PrivKey, hashD)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(hex.Dump(r.Bytes()))
	t.Log(hex.Dump(s.Bytes()))

	result := go_ecdsa.Verify(cp.PubKey, hashD, r, s)
	t.Log(result)
}

func dumpHex(pub *go_ecdsa.PublicKey, pk *go_ecdsa.PrivateKey, t *testing.T) {
	t.Logf("X: \n%s", hex.Dump(pub.X.Bytes()))
	t.Logf("Y: \n%s", hex.Dump(pub.Y.Bytes()))
	t.Logf("B: \n%s", hex.Dump(pub.Curve.Params().B.Bytes()))
	t.Logf("N: \n%s", hex.Dump(pub.Curve.Params().N.Bytes()))
	t.Logf("BitSize: %s", pub.Curve.Params().BitSize)
	t.Logf("Name: %s", pub.Curve.Params().Name)
	t.Logf("Gx: \n%s", hex.Dump(pub.Curve.Params().Gx.Bytes()))
	t.Logf("Gy: \n%s", hex.Dump(pub.Curve.Params().Gy.Bytes()))
	t.Logf("P: \n%s", hex.Dump(pub.Curve.Params().P.Bytes()))
	//t.Log(pub.Curve.Params().A)
	t.Logf("D: \n%s", hex.Dump(pk.D.Bytes()))
}

func dumpInt(pub *go_ecdsa.PublicKey, pk *go_ecdsa.PrivateKey, t *testing.T) {
	t.Logf("X: %s", pub.X)
	t.Logf("Y: %s", pub.Y)
	t.Logf("B: %s", pub.Curve.Params().B)
	t.Logf("N: %s", pub.Curve.Params().N)
	t.Logf("BitSize: %s", pub.Curve.Params().BitSize)
	t.Logf("Name: %s", pub.Curve.Params().Name)
	t.Logf("Gx: %s", pub.Curve.Params().Gx)
	t.Logf("Gy: %s", pub.Curve.Params().Gy)
	t.Logf("P: %s", pub.Curve.Params().P)
	//t.Log(pub.Curve.Params().A)
	t.Logf("D: %s", pk.D)
}
