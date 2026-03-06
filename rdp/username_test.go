package rdp

import "testing"

func TestSanitizeRdpUsername(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		candidate string
		want      string
	}{
		{
			name:      "keeps valid username",
			candidate: "admin-user",
			want:      "admin-user",
		},
		{
			name:      "trims whitespace",
			candidate: "  user01  ",
			want:      "user01",
		},
		{
			name:      "rejects placeholder hello",
			candidate: "hello",
			want:      "",
		},
		{
			name:      "rejects placeholder hello case insensitive",
			candidate: "HeLLo",
			want:      "",
		},
		{
			name:      "rejects ip literal",
			candidate: "203.0.113.10",
			want:      "",
		},
		{
			name:      "rejects empty",
			candidate: "   ",
			want:      "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := sanitizeRdpUsername(tt.candidate)
			if got != tt.want {
				t.Fatalf("sanitizeRdpUsername() = %q, want %q", got, tt.want)
			}
		})
	}
}
