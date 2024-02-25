package passbolt

import (
	"context"

	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/passbolt/go-passbolt/api"

	corev1 "k8s.io/api/core/v1"
	//	"github.com/passbolt/go-passbolt/helper"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type ProviderPassbolt struct {
	client api.Client
}

func (provider *ProviderPassbolt) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadOnly
}

func (provider *ProviderPassbolt) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube kclient.Client, namespace string) (esv1beta1.SecretsClient, error) {
	config := store.GetSpec().Provider.Passbolt

	client, err := api.NewClient(nil, "", config.ConnectHost, config.Auth.PrivateKey, config.Auth.Password)
	if err != nil {
		return nil, err
	}
	provider.client = *client
	return provider, nil
}

func (provider *ProviderPassbolt) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	return nil, nil

}

func (provider *ProviderPassbolt) PushSecret(ctx context.Context, secret *corev1.Secret, data v1beta1.PushSecretData) error {
	return nil
}

func (provider *ProviderPassbolt) DeleteSecret(ctx context.Context, remoteRef v1beta1.PushSecretRemoteRef) error {
	return nil
}

func (provider *ProviderPassbolt) Validate() (v1beta1.ValidationResult, error) {
	var res v1beta1.ValidationResult
	return res, nil
}

func (provider *ProviderPassbolt) GetSecretMap(ctx context.Context, ref v1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	var res map[string][]byte
	return res, nil
}

func (provider *ProviderPassbolt) GetAllSecrets(ctx context.Context, ref v1beta1.ExternalSecretFind) (map[string][]byte, error) {
	var res map[string][]byte
	return res, nil
}

func (provider *ProviderPassbolt) Close(ctx context.Context) error {
	return nil
}
