/*
RSA加解密接口
*/
package rsa

// #include <stdlib.h>
// #include <qat.h>
// #include <rsa.h>
// #cgo CFLAGS: -I../../../capi -I../../../lib/qat
// #cgo LDFLAGS: -L../../.. -L../../../output -licp_qa_al_s -lqatgo
import "C"

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/golang/glog"
	"github.com/nandsky/qatgo/qatgo/crypto"
	"math/big"
	"unsafe"
)

type ContextParam struct {
	CertFile string
	KeyFile  string

	// 公私钥形式
	pubKey  *rsa.PublicKey
	privKey *rsa.PrivateKey

	// 参数形式
	N    *big.Int
	E    *big.Int
	D    *big.Int
	P    *big.Int
	Q    *big.Int
	Dmp1 *big.Int
	Dmq1 *big.Int
	Iqmp *big.Int
}

// 支持同步操作和异步
// 在异步操作下，加解密操作直接等待释放锁
type Context struct {
	crypto.ContextCommon

	// Operation Content
	opCtx *C.struct__RSA_CTX
	param *ContextParam
}

// 从参数中加载
func newContextFromParam(param *ContextParam) (*Context, error) {
	// 创建UUID
	_uuid := crypto.GenerateUUID()
	cstring := C.CString(_uuid)
	defer C.free(unsafe.Pointer(cstring))

	var C_ctx *C.struct__RSA_CTX
	C_ctx = C.QAT_RSA_CTX_new(
		cstring,
		(*C.uchar)(unsafe.Pointer(&param.N.Bytes()[0])), C.int(len(param.N.Bytes())),
		(*C.uchar)(unsafe.Pointer(&param.E.Bytes()[0])), C.int(len(param.E.Bytes())),
		(*C.uchar)(unsafe.Pointer(&param.D.Bytes()[0])), C.int(len(param.D.Bytes())),
		(*C.uchar)(unsafe.Pointer(&param.P.Bytes()[0])), C.int(len(param.P.Bytes())),
		(*C.uchar)(unsafe.Pointer(&param.Q.Bytes()[0])), C.int(len(param.Q.Bytes())),
		(*C.uchar)(unsafe.Pointer(&param.Dmp1.Bytes()[0])), C.int(len(param.Dmp1.Bytes())),
		(*C.uchar)(unsafe.Pointer(&param.Dmq1.Bytes()[0])), C.int(len(param.Dmq1.Bytes())),
		(*C.uchar)(unsafe.Pointer(&param.Iqmp.Bytes()[0])), C.int(len(param.Iqmp.Bytes())),
	)

	ret := &Context{}
	ret.opCtx = C_ctx
	ret.param = param
	ret.UUID = _uuid
	ret.Async = false
	return ret, nil
}

// 从证书文件中产生参数
func NewContextParamFormFile(crtFile, keyFile string) (*ContextParam, error) {
	// 加载crt和key
	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil || cert.PrivateKey == nil {
		err = fmt.Errorf("Load file failed: %s", err.Error())
		return nil, err
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || x509Cert.PublicKey == nil {
		err = fmt.Errorf("parse cert failed: %s", err.Error())
		return nil, err
	}

	pub := x509Cert.PublicKey.(*rsa.PublicKey)
	pri_key := cert.PrivateKey.(*rsa.PrivateKey)

	ret, err := NewContextParam(
		pub.N, big.NewInt(int64(pub.E)), pri_key.D, pri_key.Primes[0], pri_key.Primes[1],
		pri_key.Precomputed.Dp, pri_key.Precomputed.Dq, pri_key.Precomputed.Qinv)

	if err != nil {
		return nil, err
	}

	ret.pubKey = x509Cert.PublicKey.(*rsa.PublicKey)
	ret.privKey = cert.PrivateKey.(*rsa.PrivateKey)
	ret.CertFile = crtFile
	ret.KeyFile = keyFile
	return ret, nil
}

func NewContextParam(n, e, d, p, q, dmp1, dmq1, iqmp *big.Int) (*ContextParam, error) {

	// 公约操作时，只需要使用 n, e
	// 私钥操作时，只需要使用 p, q, dmp1, dmq1, iqmp
	if nil == e {
		// todo: 临时填充方案
		e = big.NewInt(1)
	}
	if nil == d {
		d = big.NewInt(1)
	}
	ret := &ContextParam{
		N:    n,
		E:    e,
		D:    d,
		P:    p,
		Q:    q,
		Dmp1: dmp1,
		Dmq1: dmq1,
		Iqmp: iqmp,
	}
	return ret, nil
}

// 默认是同步调用
func NewContext(cp *ContextParam, async bool) (*Context, error) {
	if cp == nil {
		return nil, fmt.Errorf("%s", "ContextParam is empty!")
	}
	newContext, err := newContextFromParam(cp)
	if err != nil {
		return nil, err
	}
	newContext.setAsyncMode(async)
	return newContext, nil
}

func (ctx *Context) setAsyncMode(async bool) {
	if async {
		crypto.RegisteContext(ctx.UUID, ctx)
		ctx.Wg.Add(1)
	}
	ctx.Async = async
}

// 主动释放
func (ctx *Context) Free() {
	C.rsa_free(unsafe.Pointer(ctx.opCtx))
}

// 加密
func (ctx *Context) EncryptPKCS1(plaintext []byte) []byte {
	glog.Info("encrypto")
	to := make([]byte, 2048)

	glog.Infof("START rsa:")
	nlen := C.qat_rsa_encrypt(ctx.opCtx, (*C.uchar)(&plaintext[0]), (*C.uchar)(&to[0]), C.int(len(plaintext)))
	// 异步方式，等待异步完成
	if ctx.Async {
		ctx.Wg.Wait()
	}
	glog.Infof("END rsa")
	return to[:nlen] //由于加密后是字节流，直接输出查看会乱码 用base64加密
}

// 签名
func (ctx *Context) SignPKCS1(ciphertext []byte) []byte {
	to := make([]byte, 4000)
	nlen := C.qat_rsa_sign(ctx.opCtx, (*C.uchar)(&ciphertext[0]), (*C.uchar)(&to[0]), C.int(len(ciphertext)))
	if ctx.Async {
		ctx.Wg.Wait()
	}
	glog.Infof("sign return: %d", nlen)
	return to[:nlen]
}

// 解密
func (ctx *Context) DecryptPKCS1(ciphertext []byte) []byte {
	to := make([]byte, 4000)
	nlen := C.qat_rsa_decrypt(ctx.opCtx, (*C.uchar)(&ciphertext[0]), (*C.uchar)(&to[0]), C.int(len(ciphertext)))
	if ctx.Async {
		ctx.Wg.Wait()
	}
	return to[:nlen]
}

func (ctx *Context) VerifyPKCS1(hash []byte) []byte {
	to := make([]byte, 4000)
	nlen := C.qat_rsa_verify(ctx.opCtx, (*C.uchar)(&hash[0]), (*C.uchar)(&to[0]), C.int(len(hash)))
	if ctx.Async {
		ctx.Wg.Wait()
	}
	glog.Infof("verify return: %d", nlen)
	return to[:nlen]
}

func (ctx *Context) Final() error {
	ctx.Wg.Done()
	return nil
}
