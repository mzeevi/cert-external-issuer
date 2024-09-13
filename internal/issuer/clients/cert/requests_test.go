package cert

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var exampleBytes = []byte("example")

var (
	ctx = context.Background()
	log = zap.New()
)

const (
	postCert         = "PostCert"
	getCert          = "GetCert"
	failGetCert      = "FailGetCert"
	invalidResponse  = "InvalidResponse"
	testURL          = "https://test.com/"
	downloadEndpoint = "download/"
	guid             = "12345678/"
)

func TestPostCertificate(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	type args struct {
		name   string
		client Client
	}
	type want struct {
		method    string
		path      string
		responder httpmock.Responder
	}
	cases := map[string]struct {
		args args
		want want
	}{
		"ShouldSendPOSTRequestSuccessfully": {
			args: args{
				name:   postCert,
				client: NewClient(WithAPIEndpoint(testURL), WithHTTPClient(hClient)),
			},
			want: want{
				method: http.MethodPost,
				path:   fmt.Sprintf("%s%s", testURL, "csr"),
				responder: func(request *http.Request) (*http.Response, error) {
					return httpmock.NewJsonResponse(http.StatusOK, nil)
				},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			httpmock.Reset()
			cl := tc.args.client

			httpmock.RegisterResponder(tc.want.method, tc.want.path, tc.want.responder)

			switch tc.args.name {
			case postCert:
				_, err := cl.PostCertificate(ctx, log, exampleBytes)
				if err != nil {
					t.Fatalf("got error: %v", err)
				}
			}
		})
	}
}

func TestDownloadCertificate(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	type args struct {
		name   string
		client Client
	}
	type want struct {
		method    string
		path      string
		responder httpmock.Responder
	}
	cases := map[string]struct {
		args args
		want want
	}{
		"ShouldSendGETRequestSuccessfully": {
			args: args{
				name: getCert,
				client: NewClient(
					WithAPIEndpoint(testURL),
					WithForm(testForm),
					WithDownloadEndpoint(downloadEndpoint),
					WithHTTPClient(hClient),
				),
			},
			want: want{
				method: http.MethodGet,
				path:   fmt.Sprintf("%s%s%s%s", testURL, guid, downloadEndpoint, testForm),
				responder: func(request *http.Request) (*http.Response, error) {
					return httpmock.NewJsonResponse(http.StatusOK, map[string]string{"Data": string(exampleBytes)})
				},
			},
		},
		"ShouldNotDownloadOnError": {
			args: args{
				name: failGetCert,
				client: NewClient(
					WithAPIEndpoint(testURL),
					WithForm(testForm),
					WithDownloadEndpoint(downloadEndpoint),
					WithHTTPClient(hClient),
				),
			},
			want: want{
				method: http.MethodGet,
				path:   fmt.Sprintf("%s%s%s%s", testURL, guid, downloadEndpoint, testForm),
				responder: func(request *http.Request) (*http.Response, error) {
					return httpmock.NewJsonResponse(http.StatusBadRequest, map[string]string{"error": "error"})
				},
			},
		},
		"ShouldNotDownloadOnInvalidResponse": {
			args: args{
				name: invalidResponse,
				client: NewClient(
					WithAPIEndpoint(testURL),
					WithForm(testForm),
					WithDownloadEndpoint(downloadEndpoint),
					WithHTTPClient(hClient),
				),
			},
			want: want{
				method: http.MethodGet,
				path:   fmt.Sprintf("%s%s%s%s", testURL, guid, downloadEndpoint, testForm),
				responder: func(request *http.Request) (*http.Response, error) {
					return httpmock.NewJsonResponse(http.StatusOK, map[string]string{"bad": "format"})
				},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			httpmock.Reset()
			cl := tc.args.client

			httpmock.RegisterResponder(tc.want.method, tc.want.path, tc.want.responder)

			switch tc.args.name {
			case getCert:
				resp, err := cl.DownloadCertificate(ctx, log, guid)
				if err != nil {
					t.Fatalf("got error: %v", err)
				}
				if resp.Data != string(exampleBytes) {
					t.Fatalf("could not process response: %v", resp.Data)
				}
			case failGetCert:
				_, err := cl.DownloadCertificate(ctx, log, guid)
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
			case invalidResponse:
				resp, err := cl.DownloadCertificate(ctx, log, guid)
				if err != nil {
					t.Fatalf("got error: %v", err)
				}
				if resp.Data != "" {
					t.Fatalf("expected empty string, got %v", resp.Data)
				}
			}
		})
	}
}
