package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	headerWithAPIKey := http.Header{}
	headerWithAPIKey.Add("Authorization", "ApiKey the-api-key")

	emptyHeader := http.Header{}

	malformedHeader1 := http.Header{}
	malformedHeader1.Add("Authorization", "whatever-key")

	malformedHeader2 := http.Header{}
	malformedHeader2.Add("Authorization", "nothing-here whatever-key")

	malformedHeader3 := http.Header{}
	malformedHeader3.Add("Authorization", "too-many nothing-here whatever-key")

	tests := []struct {
		name      string
		header    http.Header
		expected  string
		expectErr bool
		errMsg    error
	}{
		{
			name:      "header with API key",
			header:    headerWithAPIKey,
			expected:  "the-api-key",
			expectErr: false,
			errMsg:    nil,
		},
		{
			name:      "empty header",
			header:    emptyHeader,
			expected:  "",
			expectErr: true,
			errMsg:    ErrNoAuthHeaderIncluded,
		},
		{
			name:      "malformed Key (no ApiKey identifier)",
			header:    malformedHeader1,
			expected:  "",
			expectErr: true,
			errMsg:    ErrMalformedHeader,
		},
		{
			name:      "malformed Key (something other than ApiKey)",
			header:    malformedHeader2,
			expected:  "",
			expectErr: true,
			errMsg:    ErrMalformedHeader,
		},
		{
			name:      "malformed Key (Too many fields)",
			header:    malformedHeader3,
			expected:  "",
			expectErr: true,
			errMsg:    ErrMalformedHeader,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := GetAPIKey(test.header)

			if test.expectErr && (err != nil) {
				if err != test.errMsg {
					t.Errorf("Error %v expected; got %v\n", test.expectErr, err)
				}
			}

			if result != test.expected {
				t.Errorf("Expected API key: %s; got %s", test.expected, result)
			}
		})
	}
}
