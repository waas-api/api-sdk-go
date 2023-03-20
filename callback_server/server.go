package callback_server

type ServerConfig struct {
	PrivateKey        string `json:"private_key" yaml:"private_key"`                 // required, RSA private key value for generate request signature. Create RSA key pair options，length=2048，format=PKCS#8
	PlatformPublicKey string `json:"platform_public_key" yaml:"platform_public_key"` // required, RSA public key value for verify API response，provided by platform
}
