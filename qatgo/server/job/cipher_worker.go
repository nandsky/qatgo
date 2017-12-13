/*

 */

package job

import (
	"fmt"
	"github.com/golang/glog"
	cy "github.com/nandsky/qatgo/qatgo/crypto"
	qatEcdsa "github.com/nandsky/qatgo/qatgo/crypto/ecdsa"
	qatRsa "github.com/nandsky/qatgo/qatgo/crypto/rsa"
	"github.com/nandsky/qatgo/qatgo/server/keystore"
)

// Op describing operation to be performed OR operation status.
type Op int

const (
	OpRSADecrypt Op = 1
)

var GContextTemplate map[string]interface{}

//
func CipherWorkerInit() error {

	// 初始化密钥管理系统
	GContextTemplate = make(map[string]interface{})
	for sni, _ := range keystore.GKeyStore {
		kp := keystore.GetKeyPair(sni)
		rsaCtxParam, err := qatRsa.NewContextParamFormFile(kp.CertFile, kp.KeyFile)
		if err != nil {
			return err
		}
		GContextTemplate[sni] = rsaCtxParam
	}
	// QAT初始化
	_, err := cy.QatInit()
	if err != nil {
		glog.Error(err)
		return err
	}
	// 完成队列
	//cq := qat.CompletionPortService.CompletionQueue
	//go JobDone(cq)

	return nil
}

func CipherWorkerClose() {
	cy.QatExit()
}

func DoCrypt(job *CyRequest) *CyResponse {
	//
	switch job.OpType {
	case 1:
		response, err := RsaDecrypt(job)
		if err != nil {
			makeErrResponse(job, err.Error())
		}
		return response
	case 3:
		return EcdsaSignOrVerify(job)
	default:
		return makeErrResponse(job, "unknow optype")
	}

	return makeNullResponse(job)
}

// 将job提交进行RSA解密
func RsaDecrypt(job *CyRequest) (*CyResponse, error) {
	ret := &CyResponse{}

	var rsaCtxParam *qatRsa.ContextParam = nil
	if job.RequestType == 0 {
		if _, found := GContextTemplate[job.Sni]; !found {
			return nil, fmt.Errorf("can not find sni: %s", job.Sni)
		}
		rsaCtxParam = GContextTemplate[job.Sni].(*qatRsa.ContextParam)
	} else {
		rsaParam, err := qatRsa.NewContextParam(
			job.N, nil, nil, job.P, job.Q, job.Dmp1, job.Dmq1, job.Iqmp)
		if err != nil {
			return nil, fmt.Errorf("%s", "create rsa ctx params failed")
		}
		rsaCtxParam = rsaParam
	}
	rsaCtx, err := qatRsa.NewContext(rsaCtxParam, false)
	if err != nil {
		err = fmt.Errorf("create ctx failed: %s", err.Error())
		glog.Error(err)
		return nil, err
	}

	plaintext := rsaCtx.SignPKCS1(job.Payload)
	ret.Msg = string(plaintext)
	ret.Status = 0
	return ret, nil
}

// 将job提交进行RSA解密
func EcdsaSignOrVerify(job *CyRequest) *CyResponse {
	ret := &CyResponse{}

	ecdsaCtxParam := GContextTemplate[job.Sni].(qatEcdsa.ContextParam)
	ecdsaCtx, err := qatEcdsa.NewContextFromParam(&ecdsaCtxParam)
	if err != nil {
		glog.Error("create ctx failed!")
		return nil
	}
	// 异步
	//ecdsaCtx.setAsyncMode(true)

	r, _, _ := ecdsaCtx.Sign(job.Payload)
	//	plaintext := rsaCtx.DecryptPKCS1(job.Payload)
	ret.Msg = string(r)
	ret.Status = 0
	return ret
}

func JobDone(finishQueue chan cy.AbstractContext) {
	// todo: finishQueue需要超时机制吗？
	select {
	case ctx := <-finishQueue:
		ctx.Final()

		fmt.Print("sdfa")
	}
}

func makeErrResponse(job *CyRequest, reason string) *CyResponse {
	resp := &CyResponse{
		Status: 11,
		Msg:    reason,
	}
	return resp
}

func makeNullResponse(job *CyRequest) *CyResponse {
	resp := &CyResponse{
		Status: 11,
		Msg:    "NULL RESPONSE",
	}
	return resp
}
