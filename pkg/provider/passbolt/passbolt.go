package passbolt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/url"
	"regexp"

	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/passbolt/go-passbolt/api"
	corev1 "k8s.io/api/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type ProviderPassbolt struct {
	client Client
}

func (provider *ProviderPassbolt) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadOnly
}

type Client interface {
	CheckSession(ctx context.Context) bool
	Login(ctx context.Context) error
	Logout(ctx context.Context) error
	GetResource(ctx context.Context, resourceID string) (*api.Resource, error)
	GetResources(ctx context.Context, opts *api.GetResourcesOptions) ([]api.Resource, error)
	GetResourceType(ctx context.Context, typeID string) (*api.ResourceType, error)
	DecryptMessage(message string) (string, error)
	GetSecret(ctx context.Context, resourceID string) (*api.Secret, error)
}

func (provider *ProviderPassbolt) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube kclient.Client, namespace string) (esv1beta1.SecretsClient, error) {
	config := store.GetSpec().Provider.Passbolt
	log.Println("PassboltClientCreate")

	client, err := api.NewClient(nil, "", config.Host, config.Auth.PrivateKey, config.Auth.Password)
	if err != nil {
		return nil, err
	}

	provider.client = client
	return provider, nil
}

func (provider *ProviderPassbolt) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	log.Println("PassboltProviderGetSecret")

	if err := assureLoggedIn(ctx, provider.client); err != nil {
		return nil, err
	}

	secret, err := getPassboltSecret(ctx, provider.client, ref.Key)
	if err != nil {
		return nil, err
	}

	if ref.Property == "" {
		return json.Marshal(secret)
	}

	return secret.GetProp(ref.Property)
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
	return nil, nil
}

func (provider *ProviderPassbolt) GetAllSecrets(ctx context.Context, ref v1beta1.ExternalSecretFind) (map[string][]byte, error) {
	log.Println("PassboltProviderGetAllSecrets")
	res := make(map[string][]byte)

	if ref.Name.RegExp == "" {
		return res, nil
	}

	if err := assureLoggedIn(ctx, provider.client); err != nil {
		return nil, err
	}

	resources, err := provider.client.GetResources(ctx, &api.GetResourcesOptions{})
	if err != nil {
		return nil, err
	}

	nameRegexp, err := regexp.Compile(ref.Name.RegExp)
	if err != nil {
		return nil, err
	}

	for _, resource := range resources {
		if !nameRegexp.MatchString(resource.Name) {
			continue
		}

		secret, err := getPassboltSecret(ctx, provider.client, resource.ID)
		if err != nil {
			return nil, err
		}
		marshaled, err := json.Marshal(secret)
		if err != nil {
			return nil, err
		}
		res[resource.ID] = marshaled
	}

	return res, nil
}

func (provider *ProviderPassbolt) Close(ctx context.Context) error {
	slog.InfoContext(ctx, "PassboltProviderClose")
	return provider.client.Logout(ctx)
}

func (provider *ProviderPassbolt) ValidateStore(store esv1beta1.GenericStore) (admission.Warnings, error) {
	config := store.GetSpec().Provider.Passbolt
	if config == nil {
		return nil, errors.New("PassboltProviderMissing")
	}

	if config.Auth == nil {
		return nil, errors.New("PassboltAuthMissing")
	}

	if config.Auth.Password == "" {
		return nil, errors.New("PassboltAuthPasswordMissing")
	}

	if config.Auth.PrivateKey == "" {
		return nil, errors.New("PassboltAuthPrivateKeyMissing")
	}

	host, err := url.Parse(config.Host)
	if err != nil {
		return nil, errors.New("PassboltHostMalformedURL")
	}

	if host.Scheme != "https" {
		return nil, errors.New("PassboltHostSchemeNotHttps")
	}

	return nil, nil
}

func init() {
	esv1beta1.Register(&ProviderPassbolt{}, &esv1beta1.SecretStoreProvider{
		Passbolt: &esv1beta1.PassboltProvider{},
	})
}

type PassboltSecret struct {
	Name        string `json:"name"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	URI         string `json:"uri"`
	Description string `json:"description"`
}

func (ps PassboltSecret) GetProp(key string) ([]byte, error) {
	switch key {
	case "name":
		return []byte(ps.Name), nil
	case "username":
		return []byte(ps.Username), nil
	case "uri":
		return []byte(ps.URI), nil
	default:
		return nil, errors.New("Property must be one of username, etc.")
	}
}

func getPassboltSecret(ctx context.Context, client Client, id string) (*PassboltSecret, error) {
	resource, err := client.GetResource(ctx, id)
	if err != nil {
		return nil, err
	}

	resourceType, err := client.GetResourceType(ctx, resource.ResourceTypeID)
	if err != nil {
		return nil, err
	}

	secret, err := client.GetSecret(ctx, resource.ID)
	if err != nil {
		return nil, err
	}
	res := PassboltSecret{
		Name:        resource.Name,
		Username:    resource.Username,
		URI:         resource.URI,
		Description: resource.Description,
	}

	raw, err := client.DecryptMessage(secret.Data)
	if err != nil {
		return nil, err
	}

	switch resourceType.Slug {
	case "password-string":
		res.Password = raw
	case "password-and-description", "password-description-totp":
		var pwAndDesc api.SecretDataTypePasswordAndDescription
		if err := json.Unmarshal([]byte(raw), &pwAndDesc); err != nil {
			return nil, err
		}
		res.Password = pwAndDesc.Password
		res.Description = pwAndDesc.Description
	case "totp":
	default:
		return nil, errors.New(fmt.Sprintf("UnknownPassboltResourceType: %v", resourceType))

	}

	return &res, nil
}

func assureLoggedIn(ctx context.Context, client Client) error {
	if client.CheckSession(ctx) {
		return nil
	}

	return client.Login(ctx)
}
