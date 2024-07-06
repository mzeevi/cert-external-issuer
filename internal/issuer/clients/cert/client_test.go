package cert

import (
	"testing"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
)

var (
	testAPIEndpoint      = "https://api.endpoint"
	testDownloadEndpoint = "https://download.endpoint"
	testToken            = "dummy-token"
	testTimeout          = 2 * time.Minute
)

const (
	withAPIEndpoint      = "WithAPIEndpoint"
	withDownloadEndpoint = "WithDownloadEndpoint"
	withToken            = "WithToken"
	withTimeout          = "WithTimeout"
)

func TestClientOptions(t *testing.T) {
	type args struct {
		name   string
		option func(*client)
	}
	type want struct {
		value interface{}
	}

	cases := map[string]struct {
		args args
		want want
	}{
		"ShouldCreateSuccessfullyWithAPIEndpoint": {
			args: args{
				name:   withAPIEndpoint,
				option: WithAPIEndpoint(testAPIEndpoint),
			},
			want: want{
				value: testAPIEndpoint,
			},
		},
		"ShouldCreateSuccessfullyWithDownloadEndpoint": {
			args: args{
				name:   withDownloadEndpoint,
				option: WithDownloadEndpoint(testDownloadEndpoint),
			},
			want: want{
				value: testDownloadEndpoint,
			},
		},
		"ShouldCreateSuccessfullyWithToken": {
			args: args{
				name:   withToken,
				option: WithToken(testToken),
			},
			want: want{
				value: testToken,
			},
		},
		"ShouldCreateSuccessfullyWithTimeout": {
			args: args{
				name:   withTimeout,
				option: WithTimeout(testTimeout),
			},
			want: want{
				value: testTimeout,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cl := NewClient(logr.Logger{}, tc.args.option)
			switch tc.args.name {
			case withAPIEndpoint:
				if diff := cmp.Diff(tc.want.value, cl.(*client).apiEndpoint, test.EquateErrors()); diff != "" {
					t.Fatalf("createClient(...): -want error, +got error: %v", diff)
				}
			case withDownloadEndpoint:
				if diff := cmp.Diff(tc.want.value, cl.(*client).downloadEndpoint, test.EquateErrors()); diff != "" {
					t.Fatalf("createClient(...): -want error, +got error: %v", diff)
				}
			case withToken:
				if diff := cmp.Diff(tc.want.value, cl.(*client).token, test.EquateErrors()); diff != "" {
					t.Fatalf("createClient(...): -want error, +got error: %v", diff)
				}
			case withTimeout:
				if diff := cmp.Diff(tc.want.value, cl.(*client).timeout, test.EquateErrors()); diff != "" {
					t.Fatalf("createClient(...): -want error, +got error: %v", diff)
				}
			}

		})
	}
}
