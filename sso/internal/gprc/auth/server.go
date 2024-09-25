package auth

import (
	ssov1 "awesomeProject/protos/gen/go/sso"
	"context"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(ctx context.Context, appID int, email, password string) (token string, err error)
	RegisterNewUser(ctx context.Context, email, password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type ServerAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &ServerAPI{auth: auth})
}

const (
	emptyValue = 0
)

func (s *ServerAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	// email validation
	if err := validation.Validate(
		req.GetEmail(), validation.Required, validation.Length(12, 100), is.Email,
	); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// password validation
	if err := validation.Validate(
		req.GetPassword(), validation.Required, validation.Length(8, 100),
	); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// validation app_id
	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "app_id is empty value")
	}

	token, err := s.auth.Login(ctx, int(req.GetAppId()), req.GetEmail(), req.GetPassword())
	if err != nil {
		// TODO: ...
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{Token: token}, nil
}

func (s *ServerAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	// email validation
	if err := validation.Validate(
		req.GetEmail(), validation.Required, validation.Length(12, 100), is.Email,
	); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// password validation
	if err := validation.Validate(
		req.GetPassword(), validation.Required, validation.Length(8, 100),
	); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	userID, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		// TODO: ...
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{UserId: userID}, nil
}

func (s *ServerAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	// validation app_id
	if req.GetUserId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "app_id is empty value")
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		// TODO: ...
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}
