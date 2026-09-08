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
		want    string
		wantErr error
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "missing API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "wrong authorization type",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			want:    "abc123",
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}

			if tc.wantErr != nil {
				if err == nil || err.Error() != tc.wantErr.Error() {
					t.Errorf("got error %v, want %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Errorf("got error %v, want nil", err)
			}
		})
	}
}