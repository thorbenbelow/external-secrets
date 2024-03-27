package passbolt

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/onsi/gomega"
	"github.com/passbolt/go-passbolt/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
)

func TestNewClient(t *testing.T) {

}

var clientMock = PassboltClientMock{&api.Client{}}

func TestValidateStore(t *testing.T) {
	p := &ProviderPassbolt{client: clientMock}

	gomega.RegisterTestingT(t)
	store := &esv1beta1.SecretStore{
		Spec: esv1beta1.SecretStoreSpec{
			Provider: &esv1beta1.SecretStoreProvider{
				Passbolt: &esv1beta1.PassboltProvider{},
			},
		},
	}

	// missing auth
	_, err := p.ValidateStore(store)
	gomega.Expect(err).To(gomega.BeEquivalentTo(fmt.Errorf("MissingAuth")))

	// TODO: missing password
	// TODO: missing privateKey

	auth := &esv1beta1.PassboltAuth{
		Password:   "password",
		PrivateKey: "privatekey",
	}
	store.Spec.Provider.Passbolt.Auth = auth

	// missing host
	_, err = p.ValidateStore(store)
	gomega.Expect(err).To(gomega.BeEquivalentTo(fmt.Errorf("MissingHost")))

	// TODO: malformed url

	// TODO: not https

	// spec ok
	store.Spec.Provider.Passbolt.Host = "https://passbolt.invalid"
	_, err = p.ValidateStore(store)
	gomega.Expect(err).To(gomega.BeNil())
}

func TestClose(t *testing.T) {
	// TODO: Logout called
	p := &ProviderPassbolt{}
	gomega.RegisterTestingT(t)
	err := p.Close(context.TODO())
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
}

type testCase struct {
	name     string
	input    []esv1beta1.FakeProviderData
	request  esv1beta1.ExternalSecretDataRemoteRef
	expValue string
	expErr   string
}

func TestGetAllSecrets(t *testing.T) {
	cases := []struct {
		desc        string
		data        []esv1beta1.FakeProviderData
		ref         esv1beta1.ExternalSecretFind
		expected    map[string][]byte
		expectedErr string
	}{
		{
			desc: "no matches",
			data: []esv1beta1.FakeProviderData{},
			ref: esv1beta1.ExternalSecretFind{
				Name: &esv1beta1.FindName{
					RegExp: "some-key",
				},
			},
			expected: map[string][]byte{},
		},
		{
			desc: "matches",
			data: []esv1beta1.FakeProviderData{
				{
					Key:   "some-key1",
					Value: "some-value1",
				},
				{
					Key:   "some-key2",
					Value: "some-value2",
				},
				{
					Key:   "another-key1",
					Value: "another-value1",
				},
			},
			ref: esv1beta1.ExternalSecretFind{
				Name: &esv1beta1.FindName{
					RegExp: "some-key.*",
				},
			},
			expected: map[string][]byte{
				"some-key1": []byte("some-value1"),
				"some-key2": []byte("some-value2"),
			},
		},
		{
			desc: "unsupported operator",
			data: []esv1beta1.FakeProviderData{},
			ref: esv1beta1.ExternalSecretFind{
				Path: ptr.To("some-path"),
			},
			expectedErr: "unsupported find operator",
		},
	}

	for i, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()
			p := ProviderPassbolt{}

			client, err := p.NewClient(ctx, &esv1beta1.SecretStore{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("secret-store-%v", i),
				},
				Spec: esv1beta1.SecretStoreSpec{
					Provider: &esv1beta1.SecretStoreProvider{
						Fake: &esv1beta1.FakeProvider{
							Data: tc.data,
						},
					},
				},
			}, nil, "")
			if err != nil {
				t.Fatalf("failed to create a client: %v", err)
			}

			got, err := client.GetAllSecrets(ctx, tc.ref)
			if err != nil {
				if tc.expectedErr == "" {
					t.Fatalf("failed to call GetAllSecrets: %v", err)
				}

				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Fatalf("%q expected to contain substring %q", err.Error(), tc.expectedErr)
				}

				return
			}

			if tc.expectedErr != "" {
				t.Fatal("expected to receive an error but got nil")
			}

			if diff := cmp.Diff(tc.expected, got); diff != "" {
				t.Fatalf("(-got, +want)\n%s", diff)
			}
		})
	}
}

func TestGetSecret(t *testing.T) {
	gomega.RegisterTestingT(t)
	p := &ProviderPassbolt{}
	tbl := []testCase{
		{
			name:  "return err when not found",
			input: []esv1beta1.FakeProviderData{},
			request: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     "/foo",
				Version: "v2",
			},
			expErr: esv1beta1.NoSecretErr.Error(),
		},
		{
			name: "get correct value from multiple versions",
			input: []esv1beta1.FakeProviderData{
				{
					Key:     "/foo",
					Value:   "bar2",
					Version: "v2",
				},
				{
					Key:   "junk",
					Value: "xxxxx",
				},
				{
					Key:     "/foo",
					Value:   "bar1",
					Version: "v1",
				},
			},
			request: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     "/foo",
				Version: "v2",
			},
			expValue: "bar2",
		},
		{
			name: "get correct value from multiple properties",
			input: []esv1beta1.FakeProviderData{
				{
					Key:   "junk",
					Value: "xxxxx",
				},
				{
					Key:   "/foo",
					Value: `{"p1":"bar","p2":"bar2"}`,
				},
			},
			request: esv1beta1.ExternalSecretDataRemoteRef{
				Key:      "/foo",
				Property: "p2",
			},
			expValue: "bar2",
		},
	}

	for i, row := range tbl {
		t.Run(row.name, func(t *testing.T) {
			cl, err := p.NewClient(context.Background(), &esv1beta1.SecretStore{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("secret-store-%v", i),
				},
				Spec: esv1beta1.SecretStoreSpec{
					Provider: &esv1beta1.SecretStoreProvider{
						Fake: &esv1beta1.FakeProvider{
							Data: row.input,
						},
					},
				},
			}, nil, "")
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
			out, err := cl.GetSecret(context.Background(), row.request)
			if row.expErr != "" {
				gomega.Expect(err).To(gomega.MatchError(row.expErr))
			} else {
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
			}
			gomega.Expect(string(out)).To(gomega.Equal(row.expValue))
		})
	}
}
