package signer

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/dana-team/cert-external-issuer/internal/issuer/validate"

	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
	"github.com/dana-team/cert-external-issuer/internal/issuer/clients/cert"
	"github.com/go-logr/logr"
	kube "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultWaitTimeout           = 5 * time.Minute
	authorizationHeaderSecretKey = "token"
)

type certSigner struct {
	certClient   cert.Client
	restrictions certv1alpha1.Restrictions
}

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*certv1alpha1.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign(ctx context.Context, csrBytes []byte) ([]byte, []byte, error)
}

type SignerBuilder func(logr.Logger, *certv1alpha1.IssuerSpec, map[string][]byte, kube.Client) (Signer, error)

func CertSignerHealthCheckerFromIssuerAndSecretData(*certv1alpha1.IssuerSpec, map[string][]byte) (HealthChecker, error) {
	return &certSigner{}, nil
}

// CertSignerFromIssuerAndSecretData is a wrapper for certSignerFromIssuerAndSecretData that returns a Signer interface.
func CertSignerFromIssuerAndSecretData(log logr.Logger, issuerSpec *certv1alpha1.IssuerSpec, secretData map[string][]byte, kubeClient kube.Client) (Signer, error) {
	return certSignerFromIssuerAndSecretData(log, issuerSpec, secretData, kubeClient)
}

// certSignerFromIssuerAndSecretData creates a new Signer instance using the provided issuer spec and secret data.
func certSignerFromIssuerAndSecretData(log logr.Logger, issuerSpec *certv1alpha1.IssuerSpec, secretData map[string][]byte, kubeClient kube.Client) (Signer, error) {
	tokenData := string(secretData[authorizationHeaderSecretKey])
	if tokenData == "" {
		return nil, fmt.Errorf("missing token data in secret")
	}

	apiEndpoint := issuerSpec.APIEndpoint
	if apiEndpoint == "" {
		return nil, fmt.Errorf("missing api endpoint")
	}

	if kubeClient == nil {
		return nil, fmt.Errorf("missing kube client")
	}

	waitTimeout := issuerSpec.WaitTimeout
	timeout := defaultWaitTimeout
	if waitTimeout != nil {
		timeout = waitTimeout.Duration
	}

	restrictions := issuerSpec.CertificateRestrictions

	return &certSigner{
		certClient: cert.NewClient(
			log,
			cert.WithToken(tokenData),
			cert.WithAPIEndpoint(apiEndpoint),
			cert.WithTimeout(timeout),
		),
		restrictions: restrictions,
	}, nil

}

func (cs *certSigner) Check() error {
	return nil
}

func (cs *certSigner) Sign(ctx context.Context, csrBytes []byte) ([]byte, []byte, error) {
	csr, err := parseCSR(csrBytes)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	if err := validate.EnsureCSR(csr, cs.restrictions); err != nil {
		return []byte{}, []byte{}, fmt.Errorf("failed to validate CSR: %v", err)
	}

	// TODO: replace this with CSR signature
	return []byte{}, []byte{}, nil
}

// parseCSR extracts PEM from request object.
func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block type must be CERTIFICATE REQUEST, actual: %q", block)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
