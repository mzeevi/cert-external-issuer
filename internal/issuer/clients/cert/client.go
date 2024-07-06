package cert

import (
	"time"

	httpClient "github.com/dana-team/cert-external-issuer/internal/issuer/clients/http"
	"github.com/dana-team/certificate-operator/api/v1alpha1"
	"github.com/go-logr/logr"
)

type ClientBuilder func(logr.Logger, *v1alpha1.CertificateConfig, map[string][]byte) (Client, error)

// Client is the interface to interact with Cert API service.
type Client interface {
}

type client struct {
	localHttpClient  httpClient.Client
	timeout          time.Duration
	apiEndpoint      string
	downloadEndpoint string
	token            string
}

// NewClient returns a new client.
func NewClient(log logr.Logger, options ...func(*client)) Client {
	cl := &client{}
	cl.localHttpClient = httpClient.NewClient(log)
	for _, o := range options {
		o(cl)
	}

	return cl
}

// WithAPIEndpoint returns a client with the API Endpoint field populated.
func WithAPIEndpoint(apiEndpoint string) func(*client) {
	return func(c *client) {
		c.apiEndpoint = apiEndpoint
	}
}

// WithDownloadEndpoint returns a client with the Download Endpoint field populated.
func WithDownloadEndpoint(downloadEndpoint string) func(*client) {
	return func(c *client) {
		c.downloadEndpoint = downloadEndpoint
	}
}

// WithToken returns a client with the Token field populated.
func WithToken(token string) func(*client) {
	return func(c *client) {
		c.token = token
	}
}

// WithTimeout returns a client with the Timeout field populated.
func WithTimeout(timeout time.Duration) func(*client) {
	return func(c *client) {
		c.timeout = timeout
	}
}
