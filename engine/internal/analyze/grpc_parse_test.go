package analyze

import "testing"

func TestParseProtoGRPCEndpoints(t *testing.T) {
	t.Parallel()
	src := []byte(`syntax = "proto3";
service KeyManagementService {
  rpc CreateKey(CreateKeyRequest) returns (CreateKeyResponse);
  rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
}`)
	eps := parseProtoGRPCEndpoints("proto/kms/v1/kms.proto", src)
	if len(eps) != 2 {
		t.Fatalf("got %d endpoints", len(eps))
	}
	if eps[0].Service != "KeyManagementService" {
		t.Fatalf("service: %s", eps[0].Service)
	}
}

func TestParseGeneratedGRPCEndpoints(t *testing.T) {
	t.Parallel()
	src := []byte(`
var _KeyManagementService_CreateKey_Handler = ...
var _KeyManagementService_ListKeys_Handler = ...
`)
	eps := parseGeneratedGRPCEndpoints("proto/kms/v1/kms_grpc.pb.go", src)
	if len(eps) != 2 {
		t.Fatalf("got %d endpoints", len(eps))
	}
	if eps[0].Service == "" || eps[0].Method == "" {
		t.Fatal("expected non-empty service/method")
	}
}

