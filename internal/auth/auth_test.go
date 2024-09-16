package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		authValue string
		want      string
	}{
		{
			"normal auth",
			"ApiKey 12345",
			"12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("Authorization", tt.authValue)

			got, err := GetAPIKey(h)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.want != got {
				t.Errorf("want %s, got %s", tt.want, got)
			}
		})
	}
}

func TestGetAPIKeyError(t *testing.T) {
	test := []struct {
		name      string
		authValue string
		want      error
	}{
		{
			"no auth value provided",
			"",
			ErrNoAuthHeaderIncluded,
		},
		{
			"keyword but no key",
			"ApiKey",
			errors.New("malformed authorization header"),
		},
		{
			"key but no keyword",
			"12345",
			errors.New("malformed authorization header"),
		},
		{
			"key != 'ApiKey'",
			"Bearer 12345",
			errors.New("malformed authorization header"),
		},
		{
			"too many fields",
			"ApiKey 1234 5678",
			errors.New("malformed authorization header"),
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("Authorization", tt.authValue)

			_, err := GetAPIKey(h)
			if err == nil {
				t.Fatalf("expected error for test '%s'", tt.name)
			}

			if tt.want.Error() != err.Error() {
				t.Errorf("want '%s', got '%s'", tt.want.Error(), err.Error())
			}
		})
	}
}
