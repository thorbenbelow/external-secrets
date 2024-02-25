package v1beta1

type PassboltAuth struct {
	Password   string `json:"userPassword"`
	PrivateKey string `json:"userPrivateKey"`
}

type PassboltProvider struct {
	// Auth defines the information necessary to authenticate against Passbolt Server
	Auth *PassboltAuth `json:"auth"`
	// ConnectHost defines the Passbolt Server to connect to
	ConnectHost string `json:"connectHost"`
}
