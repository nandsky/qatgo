package client

import (
	"fmt"
	"github.com/golang/glog"
	pb "github.com/nandsky/qatgo/qatgo/server/job"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"gopkg.in/ini.v1"
	"net"
	"strconv"
)

const (
	address = "localhost:50051"
)

type Config struct {
	Addr string
	Port int
}

type QatClient struct {
	Addr string
	Port int
	// todo，该变量conn需要特意维护吗？
	conn *grpc.ClientConn
	cli  pb.JobServerClient
}

func loadConfig(confFile string) (*Config, error) {
	file, err := ini.InsensitiveLoad(confFile)
	if err != nil {
		return nil, err
	}
	sec, err := file.GetSection("server")
	if err != nil {
		return nil, err
	}
	addr := sec.Key("addr").String()
	if ip := net.ParseIP(addr); ip == nil {
		return nil, err
	}

	port, err := sec.Key("port").Int()
	if err != nil {
		return nil, err
	}

	cf := &Config{
		Addr: addr,
		Port: port,
	}
	return cf, nil
}

func NewQatClient() (*QatClient, error) {
	confFile := "client.ini"
	conf, err := loadConfig(confFile)
	if err != nil {
		return nil, fmt.Errorf("load config file: %s failed", confFile)
	}

	addr := conf.Addr + ":" + strconv.Itoa(conf.Port)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		glog.Fatalf("did not connect: %v", err)
		return nil, fmt.Errorf("connect to %s failed :%s", addr, err.Error())
	}
	c := pb.NewJobServerClient(conn)

	qc := &QatClient{
		Addr: conf.Addr,
		Port: conf.Port,
		conn: conn,
		cli:  c,
	}
	return qc, nil
}

// 请求一个加解密操作
func (q *QatClient) Run(newJob *pb.JobRequest) (*pb.JobReply, error) {

	r, err := q.cli.SayHello(context.Background(), newJob)
	if err != nil {
		glog.Fatalf("could not greet: %v", err)
	}
	glog.Infof("result: %d, %s\n", r.Status, r.Msg)

	return r, nil
}

func (q *QatClient) Close() {
	// 需要特意维护conn，并释放吗？
	if q.conn != nil {
		q.conn.Close()
	}
}
