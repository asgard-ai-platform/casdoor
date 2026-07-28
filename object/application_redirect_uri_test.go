// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import "testing"

func TestIsRedirectUriValid(t *testing.T) {
	application := &Application{
		RedirectUris: []string{
			"https://platform.dev.asgard-ai.com",
			"https://platform.dev.asgard-ai.com/auth/callback",
		},
	}

	tests := []struct {
		name        string
		redirectUri string
		want        bool
	}{
		// Registered URIs and paths under a registered origin.
		{"exact match", "https://platform.dev.asgard-ai.com/auth/callback", true},
		{"registered origin itself", "https://platform.dev.asgard-ai.com", true},
		{"other path on registered origin", "https://platform.dev.asgard-ai.com/auth/other", true},

		// Built-in local development targets.
		{"localhost", "http://localhost:9000/callback", true},
		{"loopback ip", "http://127.0.0.1:9000/callback", true},
		{"chrome extension", "https://abcdef.chromiumapp.org/", true},

		// The payload the DAST scan reported: the allowed URI is carried in the query
		// string of an attacker-controlled origin.
		{"allowed uri in query string", "https://bxss.me?https://platform.dev.asgard-ai.com/auth/callback", false},
		{"allowed uri in path", "https://evil.example.com/x?u=https://platform.dev.asgard-ai.com/auth/callback", false},

		// The allowed URI was compiled as an unanchored regex, so "." matched any
		// character and the attacker did not even need the literal string.
		{"regex dot as wildcard", "https://platformXdevXasgard-aiXcom.evil.example.com/auth/callback", false},

		// Other ways to look like the allowed origin without being it.
		{"allowed origin as userinfo", "https://platform.dev.asgard-ai.com@evil.example.com/", false},
		{"allowed origin as subdomain prefix", "https://platform.dev.asgard-ai.com.evil.example.com/", false},
		{"attacker suffix on registered host", "https://platform.dev.asgard-ai.com.tw/auth/callback", false},
		{"scheme downgrade", "http://platform.dev.asgard-ai.com/auth/callback", false},
		{"path prefix without separator", "https://platform.dev.asgard-ai.comX/auth/callback", false},

		// Unrelated destinations.
		{"unrelated origin", "https://bxss.me/", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := application.IsRedirectUriValid(tt.redirectUri); got != tt.want {
				t.Errorf("IsRedirectUriValid(%q) = %v, want %v", tt.redirectUri, got, tt.want)
			}
		})
	}
}

// An allowed URI that is not a valid regular expression used to panic the request via
// regexp.MustCompile.
func TestIsRedirectUriValidWithInvalidRegex(t *testing.T) {
	application := &Application{
		RedirectUris: []string{"https://platform.dev.asgard-ai.com/auth/callback(("},
	}

	if application.IsRedirectUriValid("https://evil.example.com/") {
		t.Error("an attacker-controlled origin must not be accepted")
	}
}
