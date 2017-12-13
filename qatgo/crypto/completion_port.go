package crypto

import (
	"github.com/golang/glog"
	"log"
	"net"
	"os"
)

const (
	com_port = ":50052"
)

type CompletionPortService struct {
	ComPort         int
	Qat             *Qat
	CompletionQueue chan AbstractContext
}

func InitCompletionPort(q *Qat) (*CompletionPortService, error) {
	cps := &CompletionPortService{
		ComPort: 50052,
		Qat:     q,
	}

	cq := make(chan AbstractContext)
	cps.CompletionQueue = cq

	// 有两种方案用于完成通知，1. unix socket 2. tcp socket
	err := cps.startTcpServer()
	//return startUnixServer()
	// 等待端口打开
	//startGrpc()

	if err != nil {
		return nil, err
	}
	return cps, nil
}

func (cps *CompletionPortService) completionNotify(conn net.Conn) {
finish_read:
	for {
		buf := make([]byte, 512)
		nLen, err := conn.Read(buf)
		if err != nil {
			glog.Errorf("recv failed: %s", err)
			break finish_read
		} else {
			// 收到通知就调用qat的函数
			_uuid := string(buf[:nLen])
			glog.Infof("get one notify: %s!\n", _uuid)
			cs := GetContext(_uuid)
			if cs != nil {
				glog.Info("found one context!")
				cps.CompletionQueue <- cs
				cs.Final()
			}

		}
	}
	glog.Info("lost connection from: %s", conn.RemoteAddr())
}

func (cps *CompletionPortService) startUnixServer() error {
	sockFile := "/var/run/cipherComm"
	listener, err := net.ListenUnix("unix", &net.UnixAddr{sockFile, "unix"})
	if err != nil {
		return err
	}
	// 死循环，监听新的连接
	go func() {
		defer os.Remove(sockFile)
		for {
			fd, err := listener.Accept()
			if err != nil {
				log.Fatal("Accept error: ", err)
			}
			glog.Info("got new connect from: %s", fd.RemoteAddr())
			// 处理新的连接
			go cps.completionNotify(fd)
		}
	}()

	return nil
}

func (cps *CompletionPortService) startTcpServer() error {
	listener, err := net.Listen("tcp", com_port)
	if err != nil {
		return err
	}
	go func() {
		for {
			fd, err := listener.Accept()
			if err != nil {
				log.Fatal("Accept error: ", err)
			}
			glog.Info("got new connect from: %s", fd.RemoteAddr())
			// 处理新的连接, 只会有1个连接
			go cps.completionNotify(fd)
		}
	}()
	return nil
}
