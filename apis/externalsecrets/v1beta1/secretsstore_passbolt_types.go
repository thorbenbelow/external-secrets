package v1beta1

type PassboltAuth struct {
	Password   string `json:"password"`
	PrivateKey string `json:"privateKey"`
}

type PassboltProvider struct {
	// Auth defines the information necessary to authenticate against Passbolt Server
	Auth *PassboltAuth `json:"auth"`
	// Host defines the Passbolt Server to connect to
	Host string `json:"host"`
}
