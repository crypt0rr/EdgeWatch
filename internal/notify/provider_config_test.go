package notify

import (
	"net/url"
	"strings"
	"testing"

	"github.com/containrrr/shoutrrr/pkg/format"
	"github.com/containrrr/shoutrrr/pkg/services/discord"
	"github.com/containrrr/shoutrrr/pkg/services/ntfy"
	"github.com/containrrr/shoutrrr/pkg/services/smtp"
)

func TestCompileProviderConfigRoundTripsSupportedCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  ProviderConfig
		verify func(t *testing.T, raw string)
	}{
		{
			name: "SMTP encodes credentials and recipients",
			input: ProviderConfig{Provider: "smtp", Fields: map[string]string{
				"host": "mail.example.test", "port": "587",
				"from": "edgewatch@example.test", "to": "ops+edge@example.test, oncall@example.test",
				"username": "smtp-user", "password": "p@ss:/?&%",
			}},
			verify: func(t *testing.T, raw string) {
				t.Helper()
				u, err := url.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				config := smtp.Config{}
				resolver := format.NewPropKeyResolver(&config)
				if err := resolver.SetDefaultProps(&config); err != nil {
					t.Fatal("apply SMTP defaults:", err)
				}
				if err := config.SetURL(u); err != nil {
					t.Fatal("parse generated SMTP configuration:", err)
				}
				if config.Password != "p@ss:/?&%" || config.Username != "smtp-user" {
					t.Fatalf("SMTP credentials did not round-trip: username=%q password=%q", config.Username, config.Password)
				}
				if config.FromAddress != "edgewatch@example.test" || len(config.ToAddresses) != 2 || config.ToAddresses[0] != "ops+edge@example.test" {
					t.Fatalf("SMTP addresses did not round-trip: from=%q to=%#v", config.FromAddress, config.ToAddresses)
				}
				if config.Port != 587 || !config.UseStartTLS {
					t.Fatalf("SMTP defaults did not apply: port=%d STARTTLS=%v", config.Port, config.UseStartTLS)
				}
			},
		},
		{
			name: "Discord converts a native webhook URL",
			input: ProviderConfig{Provider: "discord", Fields: map[string]string{
				"webhook_url": "https://discord.com/api/webhooks/123456789012345678/token.part_value-1",
			}},
			verify: func(t *testing.T, raw string) {
				t.Helper()
				u, err := url.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				config := discord.Config{}
				if err := config.SetURL(u); err != nil {
					t.Fatal("parse generated Discord configuration:", err)
				}
				if config.WebhookID != "123456789012345678" || config.Token != "token.part_value-1" {
					t.Fatalf("Discord webhook did not round-trip: id=%q token=%q", config.WebhookID, config.Token)
				}
			},
		},
		{
			name: "ntfy applies its server default and escapes a token",
			input: ProviderConfig{Provider: "ntfy", Fields: map[string]string{
				"topic": "edgewatch-alerts", "username": "operator", "password": "token&with/slash",
			}},
			verify: func(t *testing.T, raw string) {
				t.Helper()
				u, err := url.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				config := ntfy.Config{}
				if err := config.SetURL(u); err != nil {
					t.Fatal("parse generated ntfy configuration:", err)
				}
				resolver := format.NewPropKeyResolver(&config)
				if err := resolver.SetDefaultProps(&config); err != nil {
					t.Fatal("apply ntfy defaults:", err)
				}
				if config.Host != "ntfy.sh" || config.Scheme != "https" || config.Topic != "edgewatch-alerts" ||
					config.Username != "operator" || config.Password != "token&with/slash" {
					t.Fatalf("ntfy configuration did not round-trip: %+v", config)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := CompileProviderConfig(test.input)
			if err != nil {
				t.Fatal("compile provider config:", err)
			}
			test.verify(t, raw)
		})
	}
}

func TestCompileProviderConfigRejectsMalformedAndUnsupportedInput(t *testing.T) {
	t.Parallel()
	secret := "never-echo-this-token"
	tests := []ProviderConfig{
		{Provider: "unknown", Fields: map[string]string{"url": "generic://example.test"}},
		{Provider: "smtp", Fields: map[string]string{"host": "smtp.example.test/path", "from": "from@example.test", "to": "to@example.test"}},
		{Provider: "smtp", Fields: map[string]string{"host": "smtp.example.test", "port": "70000", "from": "from@example.test", "to": "to@example.test"}},
		{Provider: "smtp", Fields: map[string]string{"host": "smtp.example.test", "from": "from@example.test\r\nBcc: attacker@example.test", "to": "to@example.test"}},
		{Provider: "smtp", Fields: map[string]string{"host": "smtp.example.test", "from": "from@example.test", "to": "not-an-email"}},
		{Provider: "smtp", Fields: map[string]string{"host": "smtp.example.test", "from": "from@example.test", "to": "to@example.test", "unexpected": "value"}},
		{Provider: "discord", Fields: map[string]string{"webhook_url": "https://attacker.example/api/webhooks/12345678/" + secret}},
		{Provider: "discord", Fields: map[string]string{"webhook_url": "http://discord.com/api/webhooks/12345678/" + secret}},
	}
	for _, input := range tests {
		_, err := CompileProviderConfig(input)
		if err == nil || err != ErrInvalidProviderConfiguration {
			t.Fatalf("CompileProviderConfig(%+v) error = %v, want generic validation error", input, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatal("provider error disclosed a credential")
		}
	}
}
