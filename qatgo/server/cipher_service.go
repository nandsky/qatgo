/*
RPC服务，接受客户的加解密(Operation)，返回处理结果
*/

package server

import (
	"fmt"
	"github.com/golang/glog"
	cy "github.com/nandsky/qatgo/qatgo/crypto"
	"github.com/nandsky/qatgo/qatgo/server/job"
	"github.com/nandsky/qatgo/qatgo/server/keystore"
	"github.com/nandsky/qatgo/qatgo/server/rpc"
	"github.com/nandsky/qatgo/qatgo/server/tcp"
	"net"
)

const (
	tcp_port = ":50051"
	rpc_port = ":50053"
)

func StartCyService() (err error) {

	// KeyStore
	_, err = keystore.LoadKeyStore("./conf/key_store1.ini")
	if err != nil {
		glog.Fatal(err)
		return
	}

	// ci workers
	err = job.CipherWorkerInit()
	if err != nil {
		glog.Fatalf("init cipher worker failed: %s", err.Error())
	}
	defer job.CipherWorkerClose()

	go func() {
		err := StartTcpServer()
		if err != nil {
			glog.Fatalf("start tcp server failed: %s", err)
		}
	}()
	go func() {
		err := StartRpcServer()
		if err != nil {
			glog.Fatalf("start rpc server failed: %s", err)
		}
	}()
	select {}
	return
}

func StartTcpServer() error {
	// TCP 监听
	listener, err := net.Listen("tcp", tcp_port)
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
		cy.QatExit()
		return fmt.Errorf("tcp server failed: %s", err.Error())
	}
	defer listener.Close()
	glog.Infof("start TcpServer, port: %d", tcp_port)

	err = tcp.EnableTcpServer(listener)
	if err != nil {
		glog.Fatal("开启服务失败: %s", err.Error())
	}
	return nil
}

func StartRpcServer() error {
	// TCP 监听
	listener, err := net.Listen("tcp", rpc_port)
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
		cy.QatExit()
		return fmt.Errorf("rpc server failed: %s", err.Error())
	}
	defer listener.Close()
	glog.Infof("start RpcServer, port: %d", rpc_port)

	err = rpc.EnableRpcServer(listener)
	if err != nil {
		glog.Fatal("开启服务失败: %s", err.Error())
	}
	return nil
}
