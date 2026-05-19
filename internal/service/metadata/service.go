package metadata

type Service interface {
	OpenIDConfiguration() any
	AuthorizationServerMetadata() any
	ProtectedResourceMetadata() any
	WWWAuthenticateHeader() string
}
