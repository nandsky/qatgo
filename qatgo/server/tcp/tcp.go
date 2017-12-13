package tcp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/golang/glog"
	"github.com/nandsky/qatgo/qatgo/server/job"
	"math/big"
	"net"
)

func EnableTcpServer(listener net.Listener) error {
	for {
		c, err := listener.Accept()
		if err != nil {
			fmt.Println("accept error:", err)
			return err
		}
		// start a new goroutine to handle
		// the new connection.
		go handleConn(c)
	}
	return nil
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	var buf = make([]byte, 4000)
	n, err := conn.Read(buf)
	if err != nil {
		glog.Warningf("recv failed: %s", err.Error())
		return
	}
	glog.Infof("GET buff: %d", n)

	rsar := &job.CyRequest{}

	var where uint32 = 0
	clen := binary.LittleEndian.Uint32(buf[0:4])
	rsar.N = &big.Int{}
	rsar.N.SetBytes(buf[where+4 : where+4+clen])
	glog.Infof("n: %d, content: \n%s", clen, hex.Dump(buf[where+4:where+4+clen]))

	where = where + 4 + clen
	clen = binary.LittleEndian.Uint32(buf[where : where+4])
	rsar.P = &big.Int{}
	rsar.P.SetBytes(buf[where+4 : where+4+clen])
	glog.Infof("p: %d, content: \n%s", clen, hex.Dump(buf[where+4:where+4+clen]))

	where = where + 4 + clen
	clen = binary.LittleEndian.Uint32(buf[where : where+4])
	rsar.Q = &big.Int{}
	rsar.Q.SetBytes(buf[where+4 : where+4+clen])
	glog.Infof("q: %d, content: \n%s", clen, hex.Dump(buf[where+4:where+4+clen]))

	where = where + 4 + clen
	clen = binary.LittleEndian.Uint32(buf[where : where+4])
	rsar.Dmp1 = &big.Int{}
	rsar.Dmp1.SetBytes(buf[where+4 : where+4+clen])
	glog.Infof("dmp1: %d, content: \n%s", clen, hex.Dump(buf[where+4:where+4+clen]))

	where = where + 4 + clen
	clen = binary.LittleEndian.Uint32(buf[where : where+4])
	rsar.Dmq1 = &big.Int{}
	rsar.Dmq1.SetBytes(buf[where+4 : where+4+clen])
	glog.Infof("dmq1: %d, content: \n%s", clen, hex.Dump(buf[where+4:where+4+clen]))

	where = where + 4 + clen
	clen = binary.LittleEndian.Uint32(buf[where : where+4])
	rsar.Iqmp = &big.Int{}
	rsar.Iqmp.SetBytes(buf[where+4 : where+4+clen])
	glog.Infof("iqmp: %d, content: \n%s", clen, hex.Dump(buf[where+4:where+4+clen]))

	where = where + 4 + clen
	clen = binary.LittleEndian.Uint32(buf[where : where+4])
	rsar.Payload = buf[where+4 : where+4+clen]
	glog.Infof("payload: %d, content: \n%s", clen, hex.Dump(buf[where+4:where+4+clen]))

	rsar.RequestType = 1
	// todo: we do not need this!
	rsar.OpType = 1
	response := job.DoCrypt(rsar)

	glog.Infof(". status: %d, content: \n%s",
		response.Status, hex.Dump([]byte(response.Msg)))
	if response.Status != 0 {
		glog.Warningf("操作错误！")
		return
	}

	n, err = conn.Write([]byte(response.Msg))
	if err != nil {
		glog.Warningf("send error: %s", err.Error())
	} else {
		glog.Infof("send %d data", n)
	}
	return
	//req := &job.CyRequest{
	//	OpType:  1,
	//	Sni:     "test_rsa",
	//	Payload: []byte("ewewe"),
	//}
	//response := job.DoCrypt(req)
	//glog.Info(response)
}
