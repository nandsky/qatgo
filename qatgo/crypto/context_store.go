/*
上下文管理，更多是为了用于异步服务
*/
package crypto

import (
	"fmt"
	"sync"
	"time"
)

type ContextStoreService struct {
	// 存储实体
	Store *(map[string]AbstractContext)
	// 锁
	wrlocker sync.RWMutex
	Qat      *Qat
}

var GContextStore *ContextStoreService

func InitContextStore(q* Qat) *ContextStoreService {
	cs := make(map[string]AbstractContext)
	GContextStore = &ContextStoreService{
		Store: &cs,
		Qat: q,
	}
	go timeoutProcesser()
	return GContextStore
}

func GetContext(uuid string) AbstractContext {
	GContextStore.wrlocker.Lock()
	con := (*GContextStore.Store)[uuid]
	GContextStore.wrlocker.Unlock()
	return con
}

func RegisteContext(uuid string, context AbstractContext) {
	GContextStore.wrlocker.Lock()
	defer GContextStore.wrlocker.Unlock()
	(*GContextStore.Store)[uuid] = context
}

func timeoutProcesser() {
	time.Sleep(time.Minute * 1)
	fmt.Print("循环执行，清除已经异常的上下文")
}
