package sdk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	ycsdk "github.com/yandex-cloud/go-sdk"
)

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
