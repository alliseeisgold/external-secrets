package iamtoken

import (
	"context"
	"time"
)

type IamTokenCreator interface {
	Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error)
	BuildIamTokenCacheKey() CacheKey
	CheckAccess(ctxt context.Context) error
}

type IamToken struct {
	Token     string
	ExpiresAt time.Time
}
