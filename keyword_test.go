package main

import "testing"

func TestDeriveKeywordFromGitleaksID(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		// Simple cases
		{"openai-api-key", "openai"},
		{"anthropic-api-key", "anthropic"},
		{"stripe-access-token", "stripe"},
		{"sendgrid-api-token", "sendgrid"},

		// GitHub variants — all map to "github"
		{"github-pat", "github"},
		{"github-fine-grained-pat", "github"},
		{"github-oauth", "github"},
		{"github-app-token", "github"},
		{"github-refresh-token", "github"},

		// GitLab variants — all map to "gitlab"
		{"gitlab-pat", "gitlab"},
		{"gitlab-deploy-token", "gitlab"},
		{"gitlab-cicd-job-token", "gitlab"},
		{"gitlab-runner-authentication-token", "gitlab"},
		{"gitlab-ptt", "gitlab"},
		{"gitlab-rrt", "gitlab"},
		{"gitlab-scim-token", "gitlab"},
		{"gitlab-session-cookie", "gitlab"},

		// Slack variants — all map to "slack"
		{"slack-bot-token", "slack"},
		{"slack-user-token", "slack"},
		{"slack-app-token", "slack"},
		{"slack-legacy-bot-token", "slack"},
		{"slack-webhook-url", "slack"},

		// Multi-word service names
		{"cloudflare-api-key", "cloudflare"},
		{"cloudflare-global-api-key", "cloudflare"},
		{"cloudflare-origin-ca-key", "cloudflare"},
		{"digitalocean-access-token", "digitalocean"},
		{"digitalocean-pat", "digitalocean"},

		// Compound service names kept intact
		{"cisco-meraki-api-key", "cisco-meraki"},
		{"microsoft-teams-webhook", "microsoft-teams"},

		// Overrides
		{"aws-amazon-bedrock-api-key-long-lived", "aws"},
		{"hashicorp-tf-api-token", "hashicorp"},
		{"new-relic-user-api-key", "newrelic"},
		{"settlemint-application-access-token", "settlemint"},
		{"yandex-aws-access-token", "yandex"},

		// Modifiers correctly treated as credential words
		{"shopify-shared-secret", "shopify"},
		{"shopify-custom-access-token", "shopify"},
		{"facebook-page-access-token", "facebook"},
		{"twitter-bearer-token", "twitter"},
		{"flutterwave-encryption-key", "flutterwave"},

		// Edge cases
		{"jwt", "jwt"},
		{"jwt-base64", "jwt"},
		{"private-key", "private-key"},     // all words are credential-type, falls back to full ID
		{"generic-api-key", "generic"},
		{"", ""},
		{"  ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := deriveKeywordFromGitleaksID(tt.ruleID)
			if got != tt.want {
				t.Errorf("deriveKeywordFromGitleaksID(%q) = %q, want %q", tt.ruleID, got, tt.want)
			}
		})
	}
}

func TestDeriveKeywordFromTHName(t *testing.T) {
	tests := []struct {
		dirName string
		want    string
	}{
		// Simple names (no suffix to strip)
		{"anthropic", "anthropic"},
		{"openai", "openai"},
		{"stripe", "stripe"},
		{"github", "github"},

		// Credential-type suffix stripping
		{"cloudflareapitoken", "cloudflare"},
		{"cloudflareglobalapikey", "cloudflare"},
		{"cloudflarecakey", "cloudflare"},
		{"datadogtoken", "datadog"},
		{"digitaloceantoken", "digitalocean"},
		{"digitaloceanv2", "digitalocean"},
		{"discordbottoken", "discord"},
		{"discordwebhook", "discord"},
		{"facebookoauth", "facebook"},
		{"fastlypersonaltoken", "fastly"},
		{"npmtoken", "npm"},
		{"npmtokenv2", "npm"},       // strips "v2" first? Let's check
		{"nugetapikey", "nuget"},
		{"snykkey", "snyk"},
		{"sentryorgtoken", "sentry"},
		{"telegrambottoken", "telegram"},
		{"twitterconsumerkey", "twitter"},
		{"airtableoauth", "airtable"},
		{"airtablepersonalaccesstoken", "airtable"},
		{"asanaoauth", "asana"},
		{"asanapersonalaccesstoken", "asana"},
		{"bitbucketapppassword", "bitbucket"},
		{"contentfulpersonalaccesstoken", "contentful"},
		{"linearapi", "linear"},
		{"newrelicpersonalapikey", "newrelic"},
		{"sendbirdorganizationapi", "sendbird"},
		{"sendinbluev2", "sendinblue"},
		{"sonarcloud", "sonar"},

		// Manual overrides
		{"adafruitio", "adafruit"},
		{"adobeio", "adobe"},
		{"flyio", "flyio"},
		{"frameio", "frameio"},
		{"privatekey", "privatekey"},
		{"gcpapplicationdefaultcredentials", "gcp"},
		{"hubspot_apikey", "hubspot"},

		// .io services that should NOT have io stripped
		{"customerio", "customerio"},
		{"twilio", "twilio"},
		{"keenio", "keenio"},
		{"logzio", "logzio"},
		{"podio", "podio"},

		// Short names where suffix stripping would be too aggressive
		{"npm", "npm"},
		{"gcp", "gcp"},

		// Edge cases
		{"", ""},
		{"a", "a"}, // too short to strip
	}

	for _, tt := range tests {
		t.Run(tt.dirName, func(t *testing.T) {
			got := deriveKeywordFromTHName(tt.dirName)
			if got != tt.want {
				t.Errorf("deriveKeywordFromTHName(%q) = %q, want %q", tt.dirName, got, tt.want)
			}
		})
	}
}

func TestNormalizeKeyword(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"cloudflare", "cloudflare"},
		{"Cloudflare", "cloudflare"},
		{"new-relic", "newrelic"},
		{"hubspot_apikey", "hubspotapikey"},
		{"GITHUB", "github"},
		{"cisco-meraki", "ciscomeraki"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeKeyword(tt.input)
			if got != tt.want {
				t.Errorf("normalizeKeyword(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestNoFalsePositives verifies that short keywords don't accidentally match
// unrelated services.
func TestNoFalsePositives(t *testing.T) {
	// "vault" should NOT derive from "alienvault"
	got := deriveKeywordFromTHName("alienvault")
	if got == "vault" {
		t.Errorf("alienvault should NOT produce keyword 'vault', got %q", got)
	}

	// "age" should NOT match "finage" or "imagekit"
	got = deriveKeywordFromTHName("finage")
	if got == "age" {
		t.Errorf("finage should NOT produce keyword 'age', got %q", got)
	}

	// "coin" from "coinbase" shouldn't match random "coin" TH entries
	got = deriveKeywordFromTHName("coincap")
	if got == "coinbase" {
		t.Errorf("coincap should NOT produce keyword 'coinbase', got %q", got)
	}
}
