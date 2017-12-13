package rpc

import (
	"github.com/golang/glog"
	worker "github.com/nandsky/qatgo/qatgo/server/job"
	pb "github.com/nandsky/qatgo/qatgo/server/rpc/job"
	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/reflection"
	"net"
	"net/http"
)

type CyHandler struct {
}

func (s *CyHandler) SayHello(ctx context.Context, in *pb.JobRequest) (*pb.JobReply, error) {
	glog.Errorf("sdfasfasfa")
	//replay := DoCrypt(in)
	replay := &pb.JobReply{
		Status: 121,
		Msg:    "dsfafa",
	}
	return replay, nil
}

func EnableRpcServer(listener net.Listener) error {
	grpc.EnableTracing = true
	s := grpc.NewServer()
	pb.RegisterJobServerServer(s, &CyHandler{})
	// Register reflection query_service on gRPC server.
	reflection.Register(s)
	// 开启trace
	grpc.EnableTracing = true
	go startTrace()
	if err := s.Serve(listener); err != nil {
		glog.Fatalf("failed to serve: %v", err)
		return err
	}
	return nil
}

func startTrace() {
	trace.AuthRequest = func(req *http.Request) (any, sensitive bool) {
		return true, true
	}
	go http.ListenAndServe(":50052", nil)
	grpclog.Println("Trace listen on 50052")
}

func DoCrypt(new_job *pb.JobRequest) *pb.JobReply {

	ret := &pb.JobReply{}

	cyJob := &worker.CyRequest{
		RequestType: 0,
		Payload:     new_job.Payload,
	}
	cyJob.OpType = new_job.OpType
	cyJob.Sni = new_job.Sni

	cyResponse := worker.DoCrypt(cyJob)
	ret.Status = cyResponse.Status
	ret.Msg = cyResponse.Msg
	return ret
}
