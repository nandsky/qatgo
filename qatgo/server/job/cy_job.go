package job

import (
	"math/big"
)

type CyRequest struct {
	// 0为sni模式，其实为直接参数形式
	RequestType int
	OpType      int32
	CySniRequest
	CyRsaRequest
	Payload []byte
}

type CyRsaRequest struct {
	N    *big.Int
	P    *big.Int
	Q    *big.Int
	Dmp1 *big.Int
	Dmq1 *big.Int
	Iqmp *big.Int
}

type CySniRequest struct {
	Sni string
}
type CyResponse struct {
	Status int32
	Msg    string
}
