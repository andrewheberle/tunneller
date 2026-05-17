package tunneller

// SSHEndpoint holds everything needed to establish an SSH tunnel to an endpoint.
type SSHEndpoint struct {
	// Host is the SSH server address (host:port)
	Host string
	// User is the SSH username
	User string
	// EndpointScheme sets the scheme explicitly
	EndpointScheme string
	// EndpointAddr is the endpoint address as seen from the SSH server (host:port)
	EndpointAddr string
}
