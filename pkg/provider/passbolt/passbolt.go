package passbolt

import (
	"context"
	"encoding/json"

	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/passbolt/go-passbolt/api"

	"github.com/passbolt/go-passbolt/helper"
	corev1 "k8s.io/api/core/v1"
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

type PassboltSecret struct {
	Id             string `json:"id"`
	FolderParentId string `json:"folderParentId"`
	Name           string `json:"name"`
	Username       string `json:"username"`
	Uri            string `json:"uri"`
	Password       string `json:"password"`
	Description    string `json:"description"`
}

func (provider *ProviderPassbolt) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	folderParentID, name, username, uri, password, description, err := helper.GetResource(ctx, &provider.client, ref.Key)
	if err != nil {
		return nil, err
	}

	return []byte(password), nil
}

func (provider *ProviderPassbolt) PushSecret(ctx context.Context, secret *corev1.Secret, data v1beta1.PushSecretData) error {
	return nil
}

func (provider *ProviderPassbolt) DeleteSecret(ctx context.Context, remoteRef v1beta1.PushSecretRemoteRef) error {
	return nil
}

func (provider *ProviderPassbolt) Validate() (v1beta1.ValidationResult, error) {
	return v1beta1.ValidationResultUnknown, nil
}

func (provider *ProviderPassbolt) GetSecretMap(ctx context.Context, ref v1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	var res map[string][]byte

	folderParentID, name, username, uri, password, description, err := helper.GetResource(ctx, &provider.client, ref.Key)

	if err != nil {
		return res, nil
	}

	res["folderParentId"] = []byte(folderParentID)
	res["name"] = []byte(name)
	res["username"] = []byte(username)
	res["description"] = []byte(description)
	res["uri"] = []byte(uri)
	res["password"] = []byte(password)

	return res, nil
}

func (provider *ProviderPassbolt) GetAllSecrets(ctx context.Context, ref v1beta1.ExternalSecretFind) (map[string][]byte, error) {
	var res map[string][]byte
	return res, nil
}

func (provider *ProviderPassbolt) Close(ctx context.Context) error {
	return nil
}
