/*
操作上下文，真正的RSA操作，ECDSA操作等均继承于该基本类
*/
package crypto

import "sync"

// 用于异步操作
type ContextCommon struct {
	UUID string
	// 用于异步
	Async      bool
	Wg         sync.WaitGroup
	NotifyChan *chan int
	Qat        *Qat

	//
	err error
}

type AbstractContext interface {
	Final() error
}

// 通用生成操作UUID
func GenerateUUID() string {
	return "abc"
}
