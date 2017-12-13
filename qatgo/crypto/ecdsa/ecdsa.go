package ecdsa

// #include <stdlib.h>
// #include <qat.h>
// #include <ecdsa.h>
// #cgo CFLAGS: -I../../../capi -I../../../lib/qat
// #cgo LDFLAGS: -L../../.. -L../../../output -licp_qa_al_s -lqatgo
import "C"

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/nandsky/qatgo/qatgo/crypto"
	"math/big"
	"unsafe"
)

type ContextParam struct {
	CertFile string
	KeyFile  string

	PubKey  *ecdsa.PublicKey
	PrivKey *ecdsa.PrivateKey
}

type Context struct {
	crypto.ContextCommon
	Params *ContextParam
	opCtx  *C.struct__ECDSA_CTX
}

func NewContext(crtFile, keyFile string) (*Context, error) {
	// 加载crt和key
	contextParam, err := NewContextParam(crtFile, keyFile)
	if err != nil {
		return nil, err
	}
	return NewContextFromParam(contextParam)
}

func NewContextParam(crtFile, keyFile string) (*ContextParam, error) {

	// 加载crt和key
	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		err = fmt.Errorf("Load file failed: %s", err.Error())
		return nil, err
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		err = fmt.Errorf("parse cert failed: %s", err.Error())
		return nil, err
	}
	ret := &ContextParam{
		PubKey:   x509Cert.PublicKey.(*ecdsa.PublicKey),
		PrivKey:  cert.PrivateKey.(*ecdsa.PrivateKey),
		CertFile: crtFile,
		KeyFile:  keyFile,
	}
	return ret, nil
}

func NewContextFromParam(params *ContextParam) (*Context, error) {

	pub := params.PubKey
	pk := params.PrivKey
	// 创建UUID
	_uuid := crypto.GenerateUUID()
	cstring := C.CString(_uuid)
	defer C.free(unsafe.Pointer(cstring))

	curve_A := big.NewInt(-3)
	// 创建操作对象
	var C_ctx *C.struct__ECDSA_CTX
	C_ctx = C.QAT_ECDSA_CTX_new(
		cstring,
		(*C.uchar)(unsafe.Pointer(&curve_A.Bytes()[0])), C.int(len(curve_A.Bytes())), // A
		(*C.uchar)(unsafe.Pointer(&pk.Params().B.Bytes()[0])), C.int(len(pk.Params().B.Bytes())), // B
		(*C.uchar)(unsafe.Pointer(&pk.Params().P.Bytes()[0])), C.int(len(pk.Params().P.Bytes())), // P
		(*C.uchar)(unsafe.Pointer(&pk.Params().N.Bytes()[0])), C.int(len(pk.Params().N.Bytes())), // Order
		(*C.uchar)(unsafe.Pointer(&pub.X.Bytes()[0])), C.int(len(pub.X.Bytes())), // X
		(*C.uchar)(unsafe.Pointer(&pub.Y.Bytes()[0])), C.int(len(pub.Y.Bytes())), // Y
		(*C.uchar)(unsafe.Pointer(&pk.Params().Gx.Bytes()[0])), C.int(len(pk.Params().Gx.Bytes())), // Gx
		(*C.uchar)(unsafe.Pointer(&pk.Params().Gy.Bytes()[0])), C.int(len(pk.Params().Gy.Bytes())), // Gy
		(*C.uchar)(unsafe.Pointer(&pk.D.Bytes()[0])), C.int(len(pk.D.Bytes())), // PrivateKey
	)

	ret := &Context{}
	ret.opCtx = C_ctx
	ret.Params = params
	ret.Async = false
	ret.UUID = _uuid
	//
	return ret, nil
}

// 签名
func (c *Context) Sign(digest []byte) (r, s []byte, err error) {
	// 如果digest长度较长，需要裁剪
	truncateDigest := make([]byte, len(digest))
	copy(truncateDigest, digest)
	truncateDigest = hashToInt(truncateDigest, c.Params.PrivKey.Curve.Params().N.BitLen())
	// R和S的内存申请
	r_b := make([]byte, 64)
	s_b := make([]byte, 64)

	// 调用签名
	status := C.qat_ecdsa_do_sign_rs(
		c.opCtx,
		(*C.uchar)(&truncateDigest[0]), C.int(len(truncateDigest)),
		(*C.uchar)(&r_b[0]),
		(*C.uchar)(&s_b[0]))
	if status != 0 {
		err = fmt.Errorf("call qat_ecdsa_do_sign_rs failed: %d", status)
		return
	}

	// 异步使用
	if c.Async {
		c.Wg.Wait()
	}
	// TODO: 此处有BUG， 长度不是固定的
	return r_b[:48], s_b[:48], nil
}

// 验签
func (c *Context) Verify(digest, r, s []byte) (bool, error) {
	// 如果digest长度较长，需要裁剪
	truncateDigest := make([]byte, len(digest))
	copy(truncateDigest, digest)
	truncateDigest = hashToInt(truncateDigest, c.Params.PrivKey.Curve.Params().N.BitLen())

	success := make([]byte, 4)
	// 调用验证签名
	status := C.qat_ecdsa_do_verify(
		c.opCtx,
		(*C.uchar)(&truncateDigest[0]), C.int(len(truncateDigest)),
		(*C.uchar)(&r[0]), C.int(len(r)),
		(*C.uchar)(&s[0]), C.int(len(s)),
		(*C.uchar)(&success[0]),
	)
	if status != 0 {
		return false, fmt.Errorf("call verify failed: %d", status)
	}
	// 异步使用
	if c.Async {
		c.Wg.Wait()
	}
	fmt.Printf("%s", hex.Dump(success))
	return true, nil
}

// TODO: 是否可以优化
func (ctx *Context) setAsyncMode(async bool) {
	if async {
		crypto.RegisteContext(ctx.UUID, ctx)
		ctx.Wg.Add(1)
	}
	ctx.Async = async
}

// 辅助digest转为符合要求的disgest
func hashToInt(hash []byte, orderBits int) []byte {
	orderBytes := (orderBits + 7) / 8

	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret.Bytes()
}

func (ctx *Context) Final() error {
	ctx.Wg.Done()
	return nil
}
