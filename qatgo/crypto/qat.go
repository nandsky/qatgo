/*
QAT密码服务Instance管理
*/

package crypto

// #include <stdlib.h>
// #include <qat.h>
// #include <rsa.h>
// #cgo CFLAGS: -I/mnt/hgfs/qatgo/capi/ -I/mnt/hgfs/qatgo/lib/qat -I../../../src -I../lib/qat -I../../../lib/qat
// #cgo LDFLAGS: -L/mnt/hgfs/qatgo/lib/qat -L/mnt/hgfs/qatgo/output -L../../.. -L../../../output -licp_qa_al_s -lqatgo
import "C"

import (
	"fmt"
	"github.com/golang/glog"
)

type Qat struct {
	Initialized bool
	InstanceNum int

	ContextStoreService   *ContextStoreService
	CompletionPortService *CompletionPortService
}

var gQat *Qat

// qat初始化
func QatInit() (*Qat, error) {
	if gQat != nil && gQat.Initialized {
		return gQat, nil
	}
	if gQat == nil {
		gQat = &Qat{
			Initialized: false,
			InstanceNum: 0,
		}
	}
	err := gQat.init()
	if err != nil {
		glog.Fatalf("qat crypto init failed: %s", err.Error())
		return nil, err
	}

	gQat.Initialized = true
	gQat.InstanceNum = 1
	glog.Info("Qat Initial success!")
	return gQat, nil
}

// qat退出
func QatExit() {
	gQat.exit()
}

func (q *Qat) init() error {
	// 初始化上下文参考
	css := InitContextStore(q)
	q.ContextStoreService = css

	// 初始化完成端口
	cps, err := InitCompletionPort(q)
	if err != nil {
		return fmt.Errorf("create completion routine failed: %s", err.Error())
	}
	q.CompletionPortService = cps

	// 初始化QAT引擎
	result := C.qat_init()
	if result != 0 {
		return fmt.Errorf("%s", "qat init failed")
	}
	return nil
}

func (q *Qat) exit() {
	C.qat_exit()
}

func InstanceNum() int {
	if gQat != nil {
		return gQat.InstanceNum
	}
	return 0
}
