/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/endpoint"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// Creates a connection to the given Yandex.Cloud API endpoint.
func NewGrpcConnection(
	ctx context.Context,
	apiEndpoint string,
	apiEndpointID string, // an ID from https://api.cloud.yandex.net/endpoints
	caCertificate []byte,
) (*grpc.ClientConn, error) {
	conn, err := createGrpcConnection(apiEndpoint, caCertificate)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	serviceAPIEndpoint, err := endpoint.NewApiEndpointServiceClient(conn).Get(ctx, &endpoint.GetApiEndpointRequest{
		ApiEndpointId: apiEndpointID,
	})
	if err != nil {
		return nil, err
	}

	return createGrpcConnection(serviceAPIEndpoint.Address, caCertificate)
}

func createGrpcConnection(apiEndpoint string, caCertificate []byte) (*grpc.ClientConn, error) {
	tlsConfig, err := TlsConfig(caCertificate)
	if err != nil {
		return nil, err
	}

	// Until gRPC proposal A61 is implemented in grpc-go, default gRPC name resolver (dns)
	// is incompatible with dualstack backends, and YC API backends are dualstack.
	// However, if passthrough resolver is used instead, grpc-go won't do any name resolution
	// and will pass the endpoint to net. Dial as-is, which would utilize happy-eyeballs
	// support in Go's net package.
	// So we explicitly set gRPC resolver to `passthrough` to match `ycsdk`s behavior,
	// which uses `passthrough` resolver implicitly by using deprecated grpc.DialContext
	// instead of grpc.NewClient used here
	target := "passthrough:///" + apiEndpoint
	return grpc.NewClient(target,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Second * 30,
			Timeout:             time.Second * 10,
			PermitWithoutStream: false,
		}),
		grpc.WithUserAgent("external-secrets"),
	)
}

type PerRPCCredentials struct {
	IamToken string
}

func (t PerRPCCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"Authorization": "Bearer " + t.IamToken}, nil
}

func (PerRPCCredentials) RequireTransportSecurity() bool {
	return true
}

func BuildSDK(ctx context.Context, apiEndpoint string, creds ycsdk.Credentials, caCertificate []byte) (*ycsdk.SDK, error) {
	tlsConfig, err := TlsConfig(caCertificate)
	if err != nil {
		return nil, err
	}

	sdk, err := ycsdk.Build(ctx, ycsdk.Config{
		Credentials: creds,
		Endpoint:    apiEndpoint,
		TLSConfig:   tlsConfig,
	})
	if err != nil {
		return nil, err
	}

	return sdk, nil
}

func CloseSDK(ctx context.Context, sdk *ycsdk.SDK) error {
	return sdk.Shutdown(ctx)
}

func TlsConfig(caCertificate []byte) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caCertificate != nil {
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCertificate)
		if !ok {
			return nil, errors.New("unable to read trusted CA certificates")
		}
		tlsConfig.RootCAs = caCertPool
	}
	return tlsConfig, nil
}
