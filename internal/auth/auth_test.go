package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "No Authorization Header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed Authorization Header - Missing ApiKey",
			headers: http.Header{"Authorization": []string{"Bearer sometoken"}},
			wantKey: "",
			wantErr: ErrMalformedHeaders(),
		},
		{
			name:    "Malformed Authorization Header - Only ApiKey",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: ErrMalformedHeader(),
		},
		{
			name:    "Valid ApiKey Header",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		{
			name:    "Valid ApiKey Header With Extra Spaces",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key extra"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %v, want %v", gotKey, tt.wantKey)
			}
			if (gotErr != nil && tt.wantErr == nil) || (gotErr == nil && tt.wantErr != nil) {
				t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tt.wantErr)
			}
			if gotErr != nil && tt.wantErr != nil && gotErr.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tt.wantErr)
			}
		})
	}
}

// helper for error comparison
func ErrMalformedHeader() error {
	return errors.New("malformed authorization header")
}
