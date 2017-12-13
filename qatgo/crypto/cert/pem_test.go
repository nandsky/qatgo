package cert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func Test_PemParse(t *testing.T) {
	PemParse()
}

func TestParseCert(t *testing.T) {
	//	filename := "../tools/ssl/server_ecdsa.crt"
	filename := "../tools/ssl/server_rsa.crt"
	cert := ParseCert(filename)

	t.Logf("public key type: %s", reflect.TypeOf(cert.PublicKey))
	switch pkType := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		rsa_pk := cert.PublicKey.(*rsa.PublicKey)
		t.Log(rsa_pk.E)
		t.Log(rsa_pk.N)
		t.Log(cert.PublicKeyAlgorithm)
		t.Log(cert.Subject)

	case *ecdsa.PublicKey:

		ecdsa_pk := cert.PublicKey.(*ecdsa.PublicKey)

		t.Log(ecdsa_pk.X)
		t.Log(ecdsa_pk.Y)
		t.Log(ecdsa_pk.Curve)
	default:
		t.Errorf("unknown type: %s", pkType)
	}
}

func TestParsePrivateKey(t *testing.T) {

	filename := "../tools/ssl/server_ecdsa.key"

	fi, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer fi.Close()

	rootPEM, err := ioutil.ReadAll(fi)
	//block, _ := pem.Decode([]byte(rootPEM))

	prk, err := x509.ParseECPrivateKey(rootPEM)
	if err != nil {
		t.Error(err)

	}
	t.Log(prk)
}

func TestX509KeyPair(t *testing.T) {
	crt_file := "../tools/ssl/server_rsa.crt"
	key_file := "../tools/ssl/server_rsa.key"
	// 加载crt和key
	cert, err := LoadX509KeyPair(crt_file, key_file)
	if err != nil {
		t.Error(err)
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	pub := x509Cert.PublicKey.(*rsa.PublicKey)
	pk := cert.PrivateKey.(*rsa.PrivateKey)

	t.Logf("module: %s", pub.N)          // n: modules
	t.Logf("public exponent: %d", pub.E) // e: publicExponent
	t.Logf("private exponent: %s", pk.D) // d: private exponent
	for idx, prime := range pk.Primes {
		t.Logf("primes %d: %s", idx, prime) // p, q: prime factors of N, has >= 2 elements

	}
	t.Logf("D mod (P-1): %s", pk.Precomputed.Dp)   // D mod (P-1)
	t.Logf("D mod (Q-1): %s", pk.Precomputed.Dq)   // D mod (Q-1)
	t.Logf("Q^-1 mod P: %s ", pk.Precomputed.Qinv) // Q^-1 mod P
}
