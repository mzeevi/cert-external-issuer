package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	testName    = "test"
	scheme      = "http"
	testURL     = scheme + "://" + testName + ".com"
	headerKey   = "Key"
	headerValue = "value"
)

var (
	logger  = zap.New()
	hClient http.Client
	ctx     = context.Background()
)

func TestSendRequest(t *testing.T) {
	httpmock.Activate()
	type params struct {
		url       string
		method    string
		body      []byte
		headers   map[string][]string
		responder httpmock.Responder
	}
	type want struct {
		response Response
		errMsg   string
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldSuccessfullySendRequestToCorrectURL": {
			params: params{
				url:     testURL,
				method:  http.MethodGet,
				body:    nil,
				headers: nil,
				responder: func(request *http.Request) (*http.Response, error) {
					if request.URL.String() != scheme+"://"+testName+".com" {
						return &http.Response{StatusCode: http.StatusBadRequest}, nil
					}
					return httpmock.NewStringResponse(http.StatusOK, ""), nil
				},
			},
			want: want{
				errMsg: "",
				response: Response{
					StatusCode: http.StatusOK,
					Headers:    map[string][]string{},
				},
			},
		},
		"ShouldSuccessfullySendRequestWithCorrectMethod": {
			params: params{
				url:     testURL,
				method:  http.MethodPatch,
				body:    nil,
				headers: nil,
				responder: func(request *http.Request) (*http.Response, error) {
					if request.Method != http.MethodPatch {
						return &http.Response{StatusCode: http.StatusBadRequest}, nil
					}
					return httpmock.NewStringResponse(http.StatusOK, ""), nil
				},
			},
			want: want{
				errMsg: "",
				response: Response{
					StatusCode: http.StatusOK,
					Headers:    map[string][]string{},
				},
			},
		},
		"ShouldSuccessfullySendRequestWithCorrectBody": {
			params: params{
				url:     testURL,
				method:  http.MethodPost,
				body:    []byte(testName),
				headers: nil,
				responder: func(request *http.Request) (*http.Response, error) {
					requestBody, _ := io.ReadAll(request.Body)
					if !bytes.Equal(requestBody, []byte(testName)) {
						return &http.Response{StatusCode: http.StatusBadRequest}, nil
					}
					return httpmock.NewStringResponse(http.StatusOK, testName), nil
				},
			},
			want: want{
				errMsg: "",
				response: Response{
					StatusCode: http.StatusOK,
					Body:       testName,
					Headers:    map[string][]string{},
				},
			},
		},
		"ShouldSendRequestWithCorrectHeaders": {
			params: params{
				url:    testURL,
				method: http.MethodGet,
				body:   nil,
				headers: map[string][]string{
					headerKey:       {headerValue},
					headerKey + "2": {headerValue + "2"},
				},
				responder: func(request *http.Request) (*http.Response, error) {
					if !(request.Header.Get(headerKey) == headerValue) || !(request.Header.Get(headerKey+"2") == headerValue+"2") {
						return &http.Response{StatusCode: http.StatusBadRequest}, nil
					}
					return &http.Response{StatusCode: http.StatusOK, Header: request.Header}, nil
				},
			},
			want: want{
				errMsg: "",
				response: Response{
					StatusCode: http.StatusOK,
					Headers: map[string][]string{
						headerKey:       {headerValue},
						headerKey + "2": {headerValue + "2"},
					},
				},
			},
		},
		"ShouldHandleBadResponse": {
			params: params{
				url:     testURL,
				method:  http.MethodGet,
				body:    nil,
				headers: nil,
				responder: func(request *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusNotFound}, nil
				},
			},
			want: want{
				errMsg:   "Not Found",
				response: Response{},
			},
		},
		"ShouldHandleError": {
			params: params{
				url:     testURL,
				method:  http.MethodGet,
				body:    nil,
				headers: nil,
				responder: func(request *http.Request) (*http.Response, error) {
					return nil, http.ErrServerClosed
				},
			},
			want: want{
				errMsg:   fmt.Sprintf("http request to %q failed: Get %q: %v", testURL, testURL, http.ErrServerClosed),
				response: Response{},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			httpmock.Reset()
			httpmock.RegisterResponder(tc.params.method, tc.params.url, tc.params.responder)
			c := NewClient(hClient)
			response, err := c.SendRequest(ctx, logger, tc.params.method, tc.params.url, tc.params.body, tc.params.headers)
			if err != nil {
				if err.Error() != tc.want.errMsg {
					assert.EqualError(t, err, tc.want.errMsg)
				}
			}
			assert.Equal(t, tc.want.response, response)
		})
	}
}
