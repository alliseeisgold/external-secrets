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

package lockbox

import (
	"context"
	"errors"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/provider/yandex/common"
	"github.com/external-secrets/external-secrets/pkg/provider/yandex/common/clock"
	"github.com/external-secrets/external-secrets/pkg/provider/yandex/lockbox/client"
)

var log = ctrl.Log.WithName("provider").WithName("yandex").WithName("lockbox")

func adaptInput(store esv1.GenericStore) (*common.YandexCloudProviderInput, error) {
	storeSpec := store.GetSpec()
	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.YandexLockbox == nil {
		return nil, errors.New("received invalid Yandex Lockbox SecretStore resource")
	}
	storeSpecYandexLockbox := storeSpec.Provider.YandexLockbox

	return &common.YandexCloudProviderInput{
		APIEndpoint:    storeSpecYandexLockbox.APIEndpoint,
		Auth:           &storeSpecYandexLockbox.Auth,
		CAProvider:     storeSpecYandexLockbox.CAProvider,
		FetchingPolicy: storeSpecYandexLockbox.FetchingPolicy,
	}, nil
}

func newSecretGetter(ctx context.Context, apiEndpoint string, caCertificate []byte) (common.SecretGetter, error) {
	lockboxClient, err := client.NewGrpcLockboxClient(ctx, apiEndpoint, caCertificate)
	if err != nil {
		return nil, err
	}
	return newLockboxSecretGetter(lockboxClient)
}

func init() {
	provider := common.InitYandexCloudProvider(
		log,
		clock.NewRealClock(),
		adaptInput,
		newSecretGetter,
		common.NewIamTokenCreator,
		time.Hour,
	)

	esv1.Register(
		provider,
		&esv1.SecretStoreProvider{
			YandexLockbox: &esv1.YandexLockboxProvider{},
		},
		esv1.MaintenanceStatusMaintained,
	)
}
