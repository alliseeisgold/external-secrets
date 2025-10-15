package iamtoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/yandex-cloud/go-sdk/iamkey"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	clock2 "github.com/external-secrets/external-secrets/pkg/provider/yandex/common/clock"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"

	"k8s.io/client-go/kubernetes"
	ctrlcfg "sigs.k8s.io/controller-runtime/pkg/client/config"
)

type IamTokenCreator interface {
	Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error)
	BuildIamTokenCacheKey() any
}

type IamToken struct {
	Token     string
	ExpiresAt time.Time
}

func InitializeIamTokenCreator(
	ctx context.Context,
	kube kclient.Client,
	store esv1.GenericStore,
	namespace string,
	auth *esv1.YandexAuth,
	logger logr.Logger,
	clock clock2.Clock) (IamTokenCreator, error) {
	var iamTokenCreator IamTokenCreator
	switch {
	case auth.AuthorizedKey != nil:
		key, err := resolvers.SecretKeyRef(
			ctx,
			kube,
			store.GetKind(),
			namespace,
			auth.AuthorizedKey,
		)
		if err != nil {
			return nil, err
		}

		authorizedKey := &iamkey.Key{}
		err = json.Unmarshal([]byte(key), authorizedKey)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal authorized key: %w", err)
		}

		iamTokenCreator = &AuthorizedKeyIamTokenProvider{
			AuthorizedKey: authorizedKey,
		}
	case auth.JwtAuth.YandexIamServiceAccountID != "" && auth.JwtAuth.ServiceAccountRef.Name != "":
		config, err := ctrlcfg.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to get any Kubernetes config: %w", err)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, err
		}

		ns := &namespace
		// https://github.com/alliseeisgold/external-secrets/blob/b5c68bc46b74f30e61a834b8be249a93560e573c/pkg/provider/gcp/secretmanager/workload_identity.go#L153-L156
		// only ClusterStore is allowed to set namespace (and then it's required)
		if store.GetKind() == esv1.ClusterSecretStoreKind && auth.JwtAuth.ServiceAccountRef.Namespace != nil {
			ns = auth.JwtAuth.ServiceAccountRef.Namespace
		}

		iamTokenCreator = &JwtAuthIamTokenProvider{
			YandexIamServiceAccountID: auth.JwtAuth.YandexIamServiceAccountID,
			ServiceAccountName:        auth.JwtAuth.ServiceAccountRef.Name,
			Namespace:                 ns,
			Audiences:                 auth.JwtAuth.ServiceAccountRef.Audiences,
			Clock:                     clock,
			Logger:                    logger,
			Corev1:                    clientset.CoreV1(),
		}
	// добавить еще проверку на InstanceServiceAccount??
	default:
		return nil, errors.New("invalid Yandex Lockbox or Certificate Manager SecretStore")
	}
	return iamTokenCreator, nil
}
