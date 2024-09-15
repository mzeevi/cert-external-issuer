package cert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"

	"github.com/dana-team/cert-external-issuer/internal/issuer/jsonutil"
	"github.com/go-logr/logr"
)

const (
	authorizationToken      = "Bearer %v"
	authorizationHeaderKey  = "Authorization"
	acceptHeaderKey         = "accept"
	acceptHeaderValue       = "application/json"
	contentTypeHeaderKey    = "Content-Type"
	contentTypeTextPlainKey = "text/plain"
	csrKey                  = "csr"
	fieldName               = "file"
	fileName                = "csr.pem"
)

var (
	errBodyIsNotJson               = errors.New("response body is not JSON")
	errFailedToUnmarshalBody       = errors.New("failed to unmarshal response body")
	errPostToCertFailed            = errors.New("POST to cert failed")
	errDownloadToCertFailed        = errors.New("download request to Cert API failed")
	errFailedToCreateMultipartForm = errors.New("failed to create multipart form")
)

// PostCertificate sends a POST request to the Cert API to create a new certificate and returns the GUID.
func (c *client) PostCertificate(ctx context.Context, logger logr.Logger, csrBytes []byte) (string, error) {
	url := fmt.Sprintf("%s%s", c.apiEndpoint, csrKey)

	requestBytes, formContentType, err := createMultipartForm(csrBytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToCreateMultipartForm, err)
	}

	response, err := c.localHttpClient.SendRequest(ctx, logger, http.MethodPost, url, requestBytes, c.constructHeaders(formContentType))
	if err != nil {
		return "", fmt.Errorf("%w: %v", errPostToCertFailed, err)
	}

	var responseBody PostCertificateResponse
	if err = parseResponseBody(response.Body, &responseBody); err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToUnmarshalBody, err)
	}

	return responseBody.Guid, nil
}

// createMultipartForm prepares a multipart/form-data request body containing the provided CSR bytes.
// It returns the encoded form as a byte slice, the content type for the HTTP header, and any error encountered.
func createMultipartForm(csrBytes []byte) ([]byte, string, error) {
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	part, err := writer.CreateFormFile(fieldName, fileName) // Use an appropriate field name and filename
	if err != nil {
		return []byte{}, "", err
	}

	if _, err := part.Write(csrBytes); err != nil {
		return []byte{}, "", err
	}

	if err := writer.Close(); err != nil {
		return []byte{}, "", err
	}

	return requestBody.Bytes(), writer.FormDataContentType(), nil
}

// DownloadCertificate sends a GET request and downloads a certificate from the Cert API.
func (c *client) DownloadCertificate(ctx context.Context, logger logr.Logger, guid string) (DownloadCertificateResponse, error) {
	url := fmt.Sprintf("%s%s%s%s", c.apiEndpoint, guid, c.downloadEndpoint, c.form)

	response, err := c.localHttpClient.SendRequest(ctx, logger, http.MethodGet, url, []byte{}, c.constructHeaders(contentTypeTextPlainKey))
	if err != nil {
		return DownloadCertificateResponse{}, fmt.Errorf("%w: %v", errDownloadToCertFailed, err)
	}

	var responseBody DownloadCertificateResponse
	if err = parseResponseBody(response.Body, &responseBody); err != nil {
		return DownloadCertificateResponse{}, fmt.Errorf("%w: %v", errFailedToUnmarshalBody, err)
	}

	return responseBody, nil
}

// parseResponseBody parses the response body received from the Cert API.
func parseResponseBody(body string, response interface{}) error {
	if !jsonutil.IsJSONString(body) {
		return errBodyIsNotJson
	}

	return json.Unmarshal([]byte(body), response)
}

// constructHeaders returns a map containing the needed headers for communicating with the Cert API.
func (c *client) constructHeaders(contentTypeValue string) map[string][]string {
	return map[string][]string{
		authorizationHeaderKey: {fmt.Sprintf(authorizationToken, c.token)},
		acceptHeaderKey:        {acceptHeaderValue},
		contentTypeHeaderKey:   {contentTypeValue},
	}
}
