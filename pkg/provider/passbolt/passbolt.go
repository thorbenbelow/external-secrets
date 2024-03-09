package passbolt

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"regexp"

	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/passbolt/go-passbolt/api"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

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

	log.Println("PassboltClientCreate")

	client, err := api.NewClient(nil, "", config.Host, config.Auth.PrivateKey, config.Auth.Password)
	if err != nil {
		return nil, err
	}
	provider.client = *client
	return provider, nil
}
func assureLoggedIn(ctx context.Context, client *api.Client) error {
	if !client.CheckSession(ctx) {
		log.Println("PassboltClientLogin")
		return client.Login(ctx)
	}
	return nil
}

func (provider *ProviderPassbolt) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	log.Println("PassboltProviderGetSecret")

	if err := assureLoggedIn(ctx, &provider.client); err != nil {
		return nil, err
	}

	prop := "password"
	if ref.Property != "" {
		prop = ref.Property
	}

	res, err := provider.GetSecretMap(ctx, ref)
	if err != nil {
		return nil, err
	}

	return res[prop], nil
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
	log.Println("PassboltProviderGetSecretMap")
	res := make(map[string][]byte)
	if err := assureLoggedIn(ctx, &provider.client); err != nil {
		return res, err
	}

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

type PassboltSecret struct {
	Name        string `json:"name"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	URI         string `json:"uri"`
	Description string `json:"description"`
}

func getPassboltSecret(ctx context.Context, client *api.Client, id string) (*PassboltSecret, error) {
	_, name, username, uri, password, description, err := helper.GetResource(ctx, client, id)
	if err != nil {
		return nil, err
	}
	return &PassboltSecret{Name: name, Username: username, URI: uri, Password: password, Description: description}, nil
}

func (provider *ProviderPassbolt) GetAllSecrets(ctx context.Context, ref v1beta1.ExternalSecretFind) (map[string][]byte, error) {
	log.Println("PassboltProviderGetAllSecrets")
	res := make(map[string][]byte)

	if ref.Name.RegExp == "" {
		return res, nil
	}

	if err := assureLoggedIn(ctx, &provider.client); err != nil {
		return nil, err
	}

	resources, err := provider.client.GetResources(ctx, &api.GetResourcesOptions{})
	if err != nil {
		return nil, err
	}

	for _, resource := range resources {
		isMatch, err := regexp.Match(ref.Name.RegExp, []byte(resource.Name))
		if err != nil {
			return nil, err
		}
		if isMatch {
			secret, err := getPassboltSecret(ctx, &provider.client, resource.ID)
			if err != nil {
				return nil, err
			}
			marshaled, err := json.Marshal(secret)
			if err != nil {
				return nil, err
			}
			res[resource.ID] = marshaled
		}
	}

	return res, nil
}

func (provider *ProviderPassbolt) Close(ctx context.Context) error {
	slog.InfoContext(ctx, "PassboltProviderClose")
	return provider.client.Logout(ctx)
}

func init() {
	esv1beta1.Register(&ProviderPassbolt{}, &esv1beta1.SecretStoreProvider{
		Passbolt: &esv1beta1.PassboltProvider{},
	})
}

// ValidateStore checks if the provided store is valid.
func (provider *ProviderPassbolt) ValidateStore(store esv1beta1.GenericStore) (admission.Warnings, error) {
	return nil, nil
}
