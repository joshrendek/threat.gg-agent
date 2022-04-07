// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// GreeterClient is the client API for Greeter service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type GreeterClient interface {
	// Sends a greeting
	SayHello(ctx context.Context, in *HelloRequest, opts ...grpc.CallOption) (*HelloReply, error)
}

type greeterClient struct {
	cc grpc.ClientConnInterface
}

func NewGreeterClient(cc grpc.ClientConnInterface) GreeterClient {
	return &greeterClient{cc}
}

func (c *greeterClient) SayHello(ctx context.Context, in *HelloRequest, opts ...grpc.CallOption) (*HelloReply, error) {
	out := new(HelloReply)
	err := c.cc.Invoke(ctx, "/honeypot.Greeter/SayHello", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GreeterServer is the server API for Greeter service.
// All implementations must embed UnimplementedGreeterServer
// for forward compatibility
type GreeterServer interface {
	// Sends a greeting
	SayHello(context.Context, *HelloRequest) (*HelloReply, error)
	mustEmbedUnimplementedGreeterServer()
}

// UnimplementedGreeterServer must be embedded to have forward compatible implementations.
type UnimplementedGreeterServer struct {
}

func (UnimplementedGreeterServer) SayHello(context.Context, *HelloRequest) (*HelloReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SayHello not implemented")
}
func (UnimplementedGreeterServer) mustEmbedUnimplementedGreeterServer() {}

// UnsafeGreeterServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to GreeterServer will
// result in compilation errors.
type UnsafeGreeterServer interface {
	mustEmbedUnimplementedGreeterServer()
}

func RegisterGreeterServer(s grpc.ServiceRegistrar, srv GreeterServer) {
	s.RegisterService(&Greeter_ServiceDesc, srv)
}

func _Greeter_SayHello_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HelloRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GreeterServer).SayHello(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/honeypot.Greeter/SayHello",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GreeterServer).SayHello(ctx, req.(*HelloRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Greeter_ServiceDesc is the grpc.ServiceDesc for Greeter service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Greeter_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "honeypot.Greeter",
	HandlerType: (*GreeterServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SayHello",
			Handler:    _Greeter_SayHello_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "honeypot.proto",
}

// HoneypotClient is the client API for Honeypot service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type HoneypotClient interface {
	Connect(ctx context.Context, in *ConnectRequest, opts ...grpc.CallOption) (*ConnectReply, error)
	SaveFtpLogin(ctx context.Context, in *FtpRequest, opts ...grpc.CallOption) (*SaveReply, error)
	SaveElasticsearch(ctx context.Context, in *ElasticsearchRequest, opts ...grpc.CallOption) (*SaveReply, error)
	SaveHttp(ctx context.Context, in *HttpRequest, opts ...grpc.CallOption) (*SaveReply, error)
	SaveSshLogin(ctx context.Context, in *SshLoginRequest, opts ...grpc.CallOption) (*SaveReply, error)
	SaveHttpHeaders(ctx context.Context, in *HttpHeaderRequest, opts ...grpc.CallOption) (*SaveReply, error)
	SaveShellCommand(ctx context.Context, in *ShellCommandRequest, opts ...grpc.CallOption) (*SaveReply, error)
	GetCommandResponse(ctx context.Context, in *CommandRequest, opts ...grpc.CallOption) (*CommandResponse, error)
}

type honeypotClient struct {
	cc grpc.ClientConnInterface
}

func NewHoneypotClient(cc grpc.ClientConnInterface) HoneypotClient {
	return &honeypotClient{cc}
}

func (c *honeypotClient) Connect(ctx context.Context, in *ConnectRequest, opts ...grpc.CallOption) (*ConnectReply, error) {
	out := new(ConnectReply)
	err := c.cc.Invoke(ctx, "/honeypot.Honeypot/Connect", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *honeypotClient) SaveFtpLogin(ctx context.Context, in *FtpRequest, opts ...grpc.CallOption) (*SaveReply, error) {
	out := new(SaveReply)
	err := c.cc.Invoke(ctx, "/honeypot.Honeypot/SaveFtpLogin", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *honeypotClient) SaveElasticsearch(ctx context.Context, in *ElasticsearchRequest, opts ...grpc.CallOption) (*SaveReply, error) {
	out := new(SaveReply)
	err := c.cc.Invoke(ctx, "/honeypot.Honeypot/SaveElasticsearch", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *honeypotClient) SaveHttp(ctx context.Context, in *HttpRequest, opts ...grpc.CallOption) (*SaveReply, error) {
	out := new(SaveReply)
	err := c.cc.Invoke(ctx, "/honeypot.Honeypot/SaveHttp", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *honeypotClient) SaveSshLogin(ctx context.Context, in *SshLoginRequest, opts ...grpc.CallOption) (*SaveReply, error) {
	out := new(SaveReply)
	err := c.cc.Invoke(ctx, "/honeypot.Honeypot/SaveSshLogin", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *honeypotClient) SaveHttpHeaders(ctx context.Context, in *HttpHeaderRequest, opts ...grpc.CallOption) (*SaveReply, error) {
	out := new(SaveReply)
	err := c.cc.Invoke(ctx, "/honeypot.Honeypot/SaveHttpHeaders", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *honeypotClient) SaveShellCommand(ctx context.Context, in *ShellCommandRequest, opts ...grpc.CallOption) (*SaveReply, error) {
	out := new(SaveReply)
	err := c.cc.Invoke(ctx, "/honeypot.Honeypot/SaveShellCommand", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *honeypotClient) GetCommandResponse(ctx context.Context, in *CommandRequest, opts ...grpc.CallOption) (*CommandResponse, error) {
	out := new(CommandResponse)
	err := c.cc.Invoke(ctx, "/honeypot.Honeypot/GetCommandResponse", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HoneypotServer is the server API for Honeypot service.
// All implementations must embed UnimplementedHoneypotServer
// for forward compatibility
type HoneypotServer interface {
	Connect(context.Context, *ConnectRequest) (*ConnectReply, error)
	SaveFtpLogin(context.Context, *FtpRequest) (*SaveReply, error)
	SaveElasticsearch(context.Context, *ElasticsearchRequest) (*SaveReply, error)
	SaveHttp(context.Context, *HttpRequest) (*SaveReply, error)
	SaveSshLogin(context.Context, *SshLoginRequest) (*SaveReply, error)
	SaveHttpHeaders(context.Context, *HttpHeaderRequest) (*SaveReply, error)
	SaveShellCommand(context.Context, *ShellCommandRequest) (*SaveReply, error)
	GetCommandResponse(context.Context, *CommandRequest) (*CommandResponse, error)
	mustEmbedUnimplementedHoneypotServer()
}

// UnimplementedHoneypotServer must be embedded to have forward compatible implementations.
type UnimplementedHoneypotServer struct {
}

func (UnimplementedHoneypotServer) Connect(context.Context, *ConnectRequest) (*ConnectReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Connect not implemented")
}
func (UnimplementedHoneypotServer) SaveFtpLogin(context.Context, *FtpRequest) (*SaveReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SaveFtpLogin not implemented")
}
func (UnimplementedHoneypotServer) SaveElasticsearch(context.Context, *ElasticsearchRequest) (*SaveReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SaveElasticsearch not implemented")
}
func (UnimplementedHoneypotServer) SaveHttp(context.Context, *HttpRequest) (*SaveReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SaveHttp not implemented")
}
func (UnimplementedHoneypotServer) SaveSshLogin(context.Context, *SshLoginRequest) (*SaveReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SaveSshLogin not implemented")
}
func (UnimplementedHoneypotServer) SaveHttpHeaders(context.Context, *HttpHeaderRequest) (*SaveReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SaveHttpHeaders not implemented")
}
func (UnimplementedHoneypotServer) SaveShellCommand(context.Context, *ShellCommandRequest) (*SaveReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SaveShellCommand not implemented")
}
func (UnimplementedHoneypotServer) GetCommandResponse(context.Context, *CommandRequest) (*CommandResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCommandResponse not implemented")
}
func (UnimplementedHoneypotServer) mustEmbedUnimplementedHoneypotServer() {}

// UnsafeHoneypotServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to HoneypotServer will
// result in compilation errors.
type UnsafeHoneypotServer interface {
	mustEmbedUnimplementedHoneypotServer()
}

func RegisterHoneypotServer(s grpc.ServiceRegistrar, srv HoneypotServer) {
	s.RegisterService(&Honeypot_ServiceDesc, srv)
}

func _Honeypot_Connect_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ConnectRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HoneypotServer).Connect(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/honeypot.Honeypot/Connect",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HoneypotServer).Connect(ctx, req.(*ConnectRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Honeypot_SaveFtpLogin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FtpRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HoneypotServer).SaveFtpLogin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/honeypot.Honeypot/SaveFtpLogin",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HoneypotServer).SaveFtpLogin(ctx, req.(*FtpRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Honeypot_SaveElasticsearch_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ElasticsearchRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HoneypotServer).SaveElasticsearch(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/honeypot.Honeypot/SaveElasticsearch",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HoneypotServer).SaveElasticsearch(ctx, req.(*ElasticsearchRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Honeypot_SaveHttp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HttpRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HoneypotServer).SaveHttp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/honeypot.Honeypot/SaveHttp",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HoneypotServer).SaveHttp(ctx, req.(*HttpRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Honeypot_SaveSshLogin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SshLoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HoneypotServer).SaveSshLogin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/honeypot.Honeypot/SaveSshLogin",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HoneypotServer).SaveSshLogin(ctx, req.(*SshLoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Honeypot_SaveHttpHeaders_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HttpHeaderRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HoneypotServer).SaveHttpHeaders(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/honeypot.Honeypot/SaveHttpHeaders",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HoneypotServer).SaveHttpHeaders(ctx, req.(*HttpHeaderRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Honeypot_SaveShellCommand_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ShellCommandRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HoneypotServer).SaveShellCommand(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/honeypot.Honeypot/SaveShellCommand",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HoneypotServer).SaveShellCommand(ctx, req.(*ShellCommandRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Honeypot_GetCommandResponse_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CommandRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HoneypotServer).GetCommandResponse(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/honeypot.Honeypot/GetCommandResponse",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HoneypotServer).GetCommandResponse(ctx, req.(*CommandRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Honeypot_ServiceDesc is the grpc.ServiceDesc for Honeypot service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Honeypot_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "honeypot.Honeypot",
	HandlerType: (*HoneypotServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Connect",
			Handler:    _Honeypot_Connect_Handler,
		},
		{
			MethodName: "SaveFtpLogin",
			Handler:    _Honeypot_SaveFtpLogin_Handler,
		},
		{
			MethodName: "SaveElasticsearch",
			Handler:    _Honeypot_SaveElasticsearch_Handler,
		},
		{
			MethodName: "SaveHttp",
			Handler:    _Honeypot_SaveHttp_Handler,
		},
		{
			MethodName: "SaveSshLogin",
			Handler:    _Honeypot_SaveSshLogin_Handler,
		},
		{
			MethodName: "SaveHttpHeaders",
			Handler:    _Honeypot_SaveHttpHeaders_Handler,
		},
		{
			MethodName: "SaveShellCommand",
			Handler:    _Honeypot_SaveShellCommand_Handler,
		},
		{
			MethodName: "GetCommandResponse",
			Handler:    _Honeypot_GetCommandResponse_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "honeypot.proto",
}
