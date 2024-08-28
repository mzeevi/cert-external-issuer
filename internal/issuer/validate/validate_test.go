package validate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"testing"

	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certv1alpha1 "github.com/dana-team/cert-external-issuer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
)

const (
	keySize    = 4096
	testName   = "test"
	dnsName    = "testName"
	ipAddress  = "1.1.1.1"
	scheme     = "HTTPS"
	notAllowed = "NotAllowedValue"
	allowed    = "Allowed"
)

func TestEnsureCSR(t *testing.T) {
	type params struct {
		algorithm              cmapi.PrivateKeyAlgorithm
		keySize                int
		allowedPrivateKeySizes []int
		altNames               []string
		subject                pkix.Name
		usages                 cmapi.KeyUsage
		restrictions           certv1alpha1.Restrictions
	}

	type want struct {
		result string
	}
	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSucceedWithoutRestrictions": {
			params: params{
				algorithm:              cmapi.RSAKeyAlgorithm,
				keySize:                keySize,
				allowedPrivateKeySizes: []int{},
				altNames:               []string{},
				subject:                pkix.Name{},
				usages:                 cmapi.UsageAny,
				restrictions:           certv1alpha1.Restrictions{},
			},
			want: want{
				result: "",
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			csr, err := generateMockCSR(tc.params.algorithm, tc.params.keySize)
			csr.DNSNames = tc.params.altNames
			csr.Subject = tc.params.subject
			assert.NoError(t, err)
			err = EnsureCSR(csr, tc.params.restrictions)
			if err != nil || tc.want.result != "" {
				assert.EqualError(t, err, tc.want.result)
			}
		})
	}
}

func TestValidateKey(t *testing.T) {
	type params struct {
		algorithm              cmapi.PrivateKeyAlgorithm
		keySize                int
		allowedPrivateKeySizes []int
		restrictions           certv1alpha1.PrivateKeyRestrictions
	}
	type want struct {
		errorMsg string
	}
	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldFailWithUnallowedAlgorithm": {
			params: params{
				algorithm:              cmapi.RSAKeyAlgorithm,
				keySize:                keySize,
				allowedPrivateKeySizes: []int{},

				restrictions: certv1alpha1.PrivateKeyRestrictions{
					AllowedPrivateKeyAlgorithms: []cmapi.PrivateKeyAlgorithm{cmapi.Ed25519KeyAlgorithm},
				},
			},
			want: want{
				errorMsg: fmt.Sprintf(errValidationFailedMsg, "type", fmt.Sprintf(errAllowedValuesStringMsg, ".spec.privateKey.algorithm", []cmapi.PrivateKeyAlgorithm{cmapi.Ed25519KeyAlgorithm})),
			},
		},
		"ShouldFailWithUnallowedSize": {
			params: params{
				algorithm:              cmapi.RSAKeyAlgorithm,
				keySize:                keySize,
				allowedPrivateKeySizes: []int{keySize},

				restrictions: certv1alpha1.PrivateKeyRestrictions{
					AllowedPrivateKeySizes:      []int{keySize * 2},
					AllowedPrivateKeyAlgorithms: []cmapi.PrivateKeyAlgorithm{cmapi.RSAKeyAlgorithm},
				},
			},
			want: want{
				errorMsg: fmt.Sprintf(errValidationFailedMsg, "size", fmt.Sprintf(errAllowedValuesIntMsg, ".spec.privateKey.size", []int{keySize * 2})),
			},
		},
		"ShouldPassWithNoRestrictions": {
			params: params{
				algorithm:              cmapi.RSAKeyAlgorithm,
				keySize:                keySize,
				allowedPrivateKeySizes: []int{},

				restrictions: certv1alpha1.PrivateKeyRestrictions{},
			},
			want: want{
				errorMsg: "",
			},
		},
		"ShouldPassWithValidKeyAndKeySize": {
			params: params{
				algorithm:              cmapi.RSAKeyAlgorithm,
				keySize:                keySize,
				allowedPrivateKeySizes: []int{},

				restrictions: certv1alpha1.PrivateKeyRestrictions{
					AllowedPrivateKeyAlgorithms: []cmapi.PrivateKeyAlgorithm{cmapi.RSAKeyAlgorithm},
					AllowedPrivateKeySizes:      []int{keySize},
				},
			},
			want: want{
				errorMsg: "",
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			csr, err := generateMockCSR(tc.params.algorithm, tc.params.keySize)
			assert.NoError(t, err)
			err = validateKey(csr, tc.params.restrictions)
			if err != nil || tc.want.errorMsg != "" {
				assert.EqualError(t, err, tc.want.errorMsg)
			}
		})
	}
}

func TestValidateSubjectAltName(t *testing.T) {
	type params struct {
		dnsNames       []string
		ipAddresses    []net.IP
		URLs           []*url.URL
		emailAddresses []string
		restrictions   certv1alpha1.SubjectAltNamesRestrictions
	}

	type want struct {
		errorMsg string
	}
	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldFailWithNoRestrictions": {
			params: params{
				dnsNames:       []string{dnsName},
				ipAddresses:    []net.IP{net.IP(ipAddress)},
				URLs:           []*url.URL{{Host: dnsName, Scheme: scheme}},
				emailAddresses: []string{dnsName + "@test.com"},
				restrictions:   certv1alpha1.SubjectAltNamesRestrictions{},
			},
			want: want{
				errorMsg: fmt.Sprintf(errValidationFailedMsg, "dnsName", fmt.Sprintf(errNotAllowedMsg, ".spec.dnsNames")),
			},
		},
		"ShouldPassWithAllTypesAllowed": {
			params: params{
				dnsNames:       []string{dnsName},
				ipAddresses:    []net.IP{net.IP(ipAddress)},
				URLs:           []*url.URL{{Host: dnsName, Scheme: "HTTPS"}},
				emailAddresses: []string{dnsName + "@test.com"},
				restrictions: certv1alpha1.SubjectAltNamesRestrictions{
					AllowDNSNames:    true,
					AllowIPAddresses: true,
					AllowURISANs:     true,
					AllowEmailSANs:   true,
				},
			},
			want: want{
				errorMsg: "",
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			csr := &x509.CertificateRequest{
				DNSNames:       tc.params.dnsNames,
				IPAddresses:    tc.params.ipAddresses,
				URIs:           tc.params.URLs,
				EmailAddresses: tc.params.emailAddresses,
			}
			err := validateSubjectAltName(csr, tc.params.restrictions)
			if err != nil || tc.want.errorMsg != "" {
				assert.EqualError(t, err, tc.want.errorMsg)
			}
		})
	}
}

func TestValidateSubject(t *testing.T) {
	type params struct {
		organizations       []string
		countries           []string
		organizationalUnits []string
		localities          []string
		provinces           []string
		streetAddresses     []string
		postalCodes         []string
		serialNumber        string
		restrictions        certv1alpha1.SubjectRestrictions
	}

	type want struct {
		errorMsg string
	}
	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldPassWithNoRestrictions": {
			params: params{
				organizations:       []string{testName},
				countries:           []string{testName},
				organizationalUnits: []string{testName},
				localities:          []string{testName},
				provinces:           []string{testName},
				streetAddresses:     []string{testName},
				postalCodes:         []string{testName},
				serialNumber:        testName,
				restrictions:        certv1alpha1.SubjectRestrictions{},
			},
			want: want{
				errorMsg: "",
			},
		},
		"ShouldFailWhenGivenSubjectIsNotInAllowedList": {
			params: params{
				organizations:       []string{testName},
				countries:           []string{testName},
				organizationalUnits: []string{testName},
				localities:          []string{testName},
				provinces:           []string{testName},
				streetAddresses:     []string{testName},
				postalCodes:         []string{notAllowed},
				serialNumber:        testName,
				restrictions: certv1alpha1.SubjectRestrictions{
					AllowedPostalCodes: []string{allowed},
				},
			},
			want: want{
				errorMsg: fmt.Sprintf(errValidationFailedMsg, "postal code", fmt.Sprintf(errAllowedValuesStringMsg, ".spec.subject.postalCodes", []string{allowed})),
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Organization:       tc.params.organizations,
					Country:            tc.params.countries,
					OrganizationalUnit: tc.params.organizationalUnits,
					Locality:           tc.params.localities,
					Province:           tc.params.provinces,
					StreetAddress:      tc.params.streetAddresses,
					PostalCode:         tc.params.postalCodes,
					SerialNumber:       tc.params.serialNumber,
				},
			}
			err := validateSubject(csr, tc.params.restrictions)
			if err != nil || tc.want.errorMsg != "" {
				assert.EqualError(t, err, tc.want.errorMsg)
			}
		})
	}
}

func TestValidateUsages(t *testing.T) {
	type params struct {
		extensions   []x509.KeyUsage
		restrictions certv1alpha1.UsageRestrictions
	}

	type want struct {
		errorMsg string
	}
	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldPassWithNoUsages": {
			params: params{
				extensions: []x509.KeyUsage{},
				restrictions: certv1alpha1.UsageRestrictions{
					AllowedUsages: []cmapi.KeyUsage{cmapi.UsageAny},
				},
			},
			want: want{
				errorMsg: "",
			},
		},
		"ShouldPassWithNoRestrictions": {
			params: params{
				extensions: []x509.KeyUsage{
					x509.KeyUsageContentCommitment,
				},
				restrictions: certv1alpha1.UsageRestrictions{},
			},

			want: want{
				errorMsg: "",
			},
		},
		"ShouldFailWithInvalidUsage": {
			params: params{
				extensions: []x509.KeyUsage{
					x509.KeyUsageDigitalSignature,
				},
				restrictions: certv1alpha1.UsageRestrictions{
					AllowedUsages: []cmapi.KeyUsage{cmapi.UsageCertSign},
				},
			},

			want: want{
				errorMsg: fmt.Sprintf(errValidationFailedMsg, "key usages", fmt.Sprintf(errAllowedValuesStringMsg, ".spec.usages", []cmapi.KeyUsage{cmapi.UsageCertSign})),
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			extensions := make([]pkix.Extension, len(tc.params.extensions))
			for i, usage := range tc.params.extensions {
				ext, err := cmpki.MarshalKeyUsage(usage)
				assert.NoError(t, err)
				extensions[i] = ext
			}
			csr := &x509.CertificateRequest{
				Extensions: extensions,
			}
			err := validateUsages(csr, tc.params.restrictions)
			if err != nil || tc.want.errorMsg != "" {
				assert.EqualError(t, err, tc.want.errorMsg)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	type params struct {
		commonName   string
		dnsNames     []string
		restrictions certv1alpha1.DomainRestrictions
	}

	type want struct {
		errorMsg string
	}
	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldPassWithNoRestrictions": {
			params: params{
				dnsNames:     []string{dnsName},
				commonName:   testName,
				restrictions: certv1alpha1.DomainRestrictions{},
			},
			want: want{
				errorMsg: "",
			},
		},
		"ShouldFailWithInvalidDomain": {
			params: params{
				dnsNames:   []string{dnsName},
				commonName: testName + "." + notAllowed,
				restrictions: certv1alpha1.DomainRestrictions{
					AllowedDomains: []string{allowed},
				},
			},
			want: want{
				errorMsg: fmt.Sprintf(errValidationFailedMsg, "commonName", fmt.Sprintf(errAllowedValuesStringMsg, ".spec.commonName domain", []string{allowed})),
			},
		},
		"ShouldPassWithValidDomain": {
			params: params{
				dnsNames:   []string{},
				commonName: testName + "." + allowed,
				restrictions: certv1alpha1.DomainRestrictions{
					AllowedDomains: []string{allowed},
				},
			},
			want: want{
				errorMsg: "",
			},
		},
		"ShouldFailWithInvalidDomainInDnsNames": {
			params: params{
				dnsNames:   []string{testName + "." + notAllowed},
				commonName: testName + "." + allowed,
				restrictions: certv1alpha1.DomainRestrictions{
					AllowedDomains: []string{allowed},
				},
			},
			want: want{
				errorMsg: fmt.Sprintf(errValidationFailedMsg, "dnsNames", fmt.Sprintf(errAllowedValuesStringMsg, ".spec.commonName domain", []string{allowed})),
			},
		},
		"ShouldPassWithValidDomainInDnsNames": {
			params: params{
				dnsNames:   []string{testName + "." + allowed},
				commonName: testName + "." + allowed,
				restrictions: certv1alpha1.DomainRestrictions{
					AllowedDomains: []string{allowed},
				},
			},
			want: want{
				errorMsg: "",
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			csr := &x509.CertificateRequest{
				DNSNames: tc.params.dnsNames,
				Subject: pkix.Name{
					CommonName: tc.params.commonName,
				},
			}
			err := validateDomain(csr, tc.params.restrictions)
			if err != nil || tc.want.errorMsg != "" {
				assert.EqualError(t, err, tc.want.errorMsg)
			}
		})
	}
}
