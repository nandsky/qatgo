package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"github.com/golang/glog"
	cy "github.com/nandsky/qatgo/qatgo/crypto"
	"testing"
	"time"
)

// 加密
func goRsaEncrypt(pub *rsa.PublicKey, origData []byte) []byte {
	encypt, err := rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
	if err != nil {
		panic(err)
	}
	return encypt //由于加密后是字节流，直接输出查看会乱码 用base64加密
}

// 解密
func goRsaDecrypt(priv *rsa.PrivateKey, ciphertext []byte) []byte {

	decypt, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)

	if err != nil {
		panic(err)
	}
	return decypt
}

func getPubAndPriv() (*rsa.PublicKey, *rsa.PrivateKey, error) {
	crt_file := "../../tools/ssl/server_rsa.crt"
	key_file := "../../tools/ssl/server_rsa.key"
	// 加载crt和key
	cert, err := tls.LoadX509KeyPair(crt_file, key_file)
	if err != nil {
		return nil, nil, err
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	pub := x509Cert.PublicKey.(*rsa.PublicKey)
	pk := cert.PrivateKey.(*rsa.PrivateKey)
	return pub, pk, nil
}

// RSA测试，GO加密，GO解密
func TestRsaEncryptDecrypt(t *testing.T) {
	pub, pk, err := getPubAndPriv()
	if err != nil {
		glog.Fatalf("read cert or key failed: %s", err.Error())
	}

	plaintext := "helloworld!"
	cipherdata := goRsaEncrypt(pub, []byte(plaintext))
	t.Log(cipherdata)
	txt := goRsaDecrypt(pk, cipherdata)
	t.Log(string(txt))
}

// RSA测试，GO加密，QAT解密
func TestNewQatRsa(t *testing.T) {
	crt_file := "../../tools/ssl/server_rsa.crt"
	key_file := "../../tools/ssl/server_rsa.key"
	pub, _, err := getPubAndPriv()
	if err != nil {
		glog.Fatalf("read cert or key failed: %s", err.Error())
	}

	plaintext := "helloworld!"
	cipherdata := goRsaEncrypt(pub, []byte(plaintext))

	ctxParam, err := NewContextParamFormFile(crt_file, key_file)
	if err != nil {
		t.Fatalf("创建上下文参数失败: %s", err.Error())
	}
	ctx, err := NewContext(ctxParam, false)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = cy.QatInit()
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(cipherdata)
	l := ctx.DecryptPKCS1(cipherdata)
	t.Log(l)

	cy.QatExit()
}

func TestRsaGoSignGoVerify(t *testing.T) {
	_, pk, err := getPubAndPriv()
	if err != nil {
		glog.Fatalf("read cert or key failed: %s", err.Error())
	}
	rng := rand.Reader
	message := []byte("message to be signed")

	hashed := sha256.Sum256(message)
	sign, err := rsa.SignPKCS1v15(rng, pk, crypto.SHA256, hashed[:])
	if err != nil {
		glog.Fatalf("sign failed, %s", err.Error())
	}
	t.Logf("\n%s", hex.Dump(sign))
	err = rsa.VerifyPKCS1v15(&pk.PublicKey, crypto.SHA256, hashed[:], sign)
	if err != nil {
		glog.Fatalf("Error from verification: %s\n", err)
	}
}

func TestRsaQatSignGoVerify(t *testing.T) {
	_, pk, err := getPubAndPriv()
	if err != nil {
		glog.Fatalf("read cert or key failed: %s", err.Error())
	}

	crt_file := "../../tools/ssl/server_rsa.crt"
	key_file := "../../tools/ssl/server_rsa.key"

	message := []byte("123456789 123456789 123456789 12a")
	//hashed := sha256.Sum256(message)

	_, err = cy.QatInit()
	if err != nil {
		t.Fatalf("QAT init failed: %s", err.Error())
		return
	}
	defer cy.QatExit()

	ctxParam, err := NewContextParamFormFile(crt_file, key_file)
	if err != nil {
		t.Fatalf("创建上下文参数失败: %s", err.Error())
	}
	ctx, err := NewContext(ctxParam, false)
	glog.Infof("hash len: %d", len(message))
	sign := ctx.SignPKCS1(message)
	glog.Errorf("sign content: \n%s", hex.Dump(sign))

	//verify := ctx.VerifyPKCS1(sign)
	//glog.Errorf("verify content: \n%s", hex.Dump(verify))
	err = rsa.VerifyPKCS1v15(&pk.PublicKey, 0, message, sign)
	if err != nil {
		glog.Fatalf("Error from verification: %s\n", err)
	} else {
		glog.Infof("verify success!")
	}
}

func TestRsaQatVerifyGoSign(t *testing.T) {
	_, pk, err := getPubAndPriv()
	if err != nil {
		glog.Fatalf("read cert or key failed: %s", err.Error())
	}

	crt_file := "../../tools/ssl/server_rsa.crt"
	key_file := "../../tools/ssl/server_rsa.key"

	message := []byte("message to be signed")
	hashed := sha256.Sum256(message)
	rng := rand.Reader

	sign, err := rsa.SignPKCS1v15(rng, pk, 0, hashed[:])
	glog.Infof("sign content: \n%s", hex.Dump(sign))
	_, err = cy.QatInit()
	if err != nil {
		t.Fatalf("QAT init failed: %s", err.Error())
		return
	}
	defer cy.QatExit()

	ctxParam, err := NewContextParamFormFile(crt_file, key_file)
	if err != nil {
		t.Fatalf("创建上下文参数失败: %s", err.Error())
	}
	ctx, err := NewContext(ctxParam, false)
	glog.Infof("hash len: %d", len(hashed[:]))

	verify := ctx.VerifyPKCS1(sign)
	glog.Infof("verify: \n%s", hex.Dump(verify))
}

func BenchmarkContext_SignPKCS1(b *testing.B) {
	crt_file := "../../tools/ssl/server_rsa.crt"
	key_file := "../../tools/ssl/server_rsa.key"
	message := []byte("message to be signed")
	_, err := cy.QatInit()
	if err != nil {
		b.Fatalf("QAT init failed: %s", err.Error())
		return
	}
	defer cy.QatExit()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ctxParam, err := NewContextParamFormFile(crt_file, key_file)
		if err != nil {
			b.Fatalf("创建上下文参数失败: %s", err.Error())
		}
		ctx, err := NewContext(ctxParam, false)
		//glog.Infof("hash len: %d", len(message))
		start := time.Now().UnixNano()
		ctx.SignPKCS1(message)
		end := time.Now().UnixNano()
		glog.Errorf("totol time: %d nsec, %f msec", end-start, (end-start)/1000000.0)

	}
}
