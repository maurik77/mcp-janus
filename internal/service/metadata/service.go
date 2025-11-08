package metadata

type Service interface {
	OpenIDConfiguration() any
	ProtectedResourceMetadata() any
	WWWAuthenticateHeader() string
}
