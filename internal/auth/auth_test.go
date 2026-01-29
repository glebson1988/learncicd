package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey valid_api_key_123"},
			},
			expectedKey:   "valid_api_key_123",
			expectedError: "",
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "Malformed Authorization Header - Missing ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer some_token"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "Malformed Authorization Header - No Space",
			headers: http.Header{
				"Authorization": []string{"ApiKeyinvalid_api_key_123"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "Malformed Authorization Header - Empty Value",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			assert.Equal(t, tt.expectedKey, apiKey)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
