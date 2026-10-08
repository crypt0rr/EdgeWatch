package notify

import (
	"errors"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/containrrr/shoutrrr"
	"github.com/containrrr/shoutrrr/pkg/format"
	"github.com/containrrr/shoutrrr/pkg/services/discord"
	"github.com/containrrr/shoutrrr/pkg/services/ntfy"
	"github.com/containrrr/shoutrrr/pkg/services/smtp"
)

var ErrInvalidProviderConfiguration = errors.New("notification provider configuration is invalid")

const (
	discordWebhookHost       = "discord" + "." + "com"
	discordLegacyWebhookHost = "discordapp" + "." + "com"
)

// ProviderConfig contains the fields needed to build one supported Shoutrrr
// destination. Credentials only travel through the existing encrypted write.
type ProviderConfig struct {
	Provider string            `json:"provider"`
	Fields   map[string]string `json:"fields"`
}

// CompileProviderConfig builds a Shoutrrr URL from a supported provider form
// and validates it with the pinned Shoutrrr parser. The returned URL contains
// credentials and must only be passed to existing encrypted destination
// operations.
func CompileProviderConfig(input ProviderConfig) (string, error) {
	fields, err := checkedProviderFields(input.Provider, input.Fields)
	if err != nil {
		return "", err
	}
	var raw string
	switch input.Provider {
	case "smtp":
		raw, err = compileSMTP(fields)
	case "discord":
		raw, err = compileDiscord(fields)
	case "ntfy":
		raw, err = compileNtfy(fields)
	default:
		return "", ErrInvalidProviderConfiguration
	}
	if err != nil {
		return "", ErrInvalidProviderConfiguration
	}
	if _, err := shoutrrr.CreateSender(raw); err != nil {
		return "", ErrInvalidProviderConfiguration
	}
	return raw, nil
}

func checkedProviderFields(provider string, fields map[string]string) (map[string]string, error) {
	var allowed map[string]struct{}
	switch provider {
	case "smtp":
		allowed = fieldSet("host", "port", "from", "to", "username", "password")
	case "discord":
		allowed = fieldSet("webhook_url")
	case "ntfy":
		allowed = fieldSet("server", "topic", "username", "password")
	default:
		return nil, ErrInvalidProviderConfiguration
	}
	if len(fields) > len(allowed) {
		return nil, ErrInvalidProviderConfiguration
	}
	for key, value := range fields {
		if _, ok := allowed[key]; !ok || len(value) > 4096 {
			return nil, ErrInvalidProviderConfiguration
		}
	}
	return fields, nil
}

func fieldSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func field(fields map[string]string, name string) string { return strings.TrimSpace(fields[name]) }

func compileSMTP(fields map[string]string) (string, error) {
	host := field(fields, "host")
	host, ok := normalizedSMTPHost(host)
	if !ok {
		return "", ErrInvalidProviderConfiguration
	}
	port := 25
	if rawPort := field(fields, "port"); rawPort != "" {
		parsed, err := strconv.Atoi(rawPort)
		if err != nil || parsed < 1 || parsed > 65535 {
			return "", ErrInvalidProviderConfiguration
		}
		port = parsed
	}
	from, err := parseMailAddress(field(fields, "from"))
	if err != nil {
		return "", ErrInvalidProviderConfiguration
	}
	recipients := splitRecipients(field(fields, "to"))
	if len(recipients) == 0 {
		return "", ErrInvalidProviderConfiguration
	}
	for index, recipient := range recipients {
		recipients[index], err = parseMailAddress(recipient)
		if err != nil {
			return "", ErrInvalidProviderConfiguration
		}
	}
	config := smtp.Config{}
	resolver := format.NewPropKeyResolver(&config)
	if err := resolver.SetDefaultProps(&config); err != nil {
		return "", ErrInvalidProviderConfiguration
	}
	config.Host = host
	config.Port = uint16(port)
	config.Username = field(fields, "username")
	config.Password = fields["password"]
	config.FromAddress = from
	config.ToAddresses = recipients
	destination := config.GetURL()
	destination.Host = net.JoinHostPort(host, strconv.Itoa(port))
	return destination.String(), nil
}

func compileDiscord(fields map[string]string) (string, error) {
	u, err := url.Parse(field(fields, "webhook_url"))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrInvalidProviderConfiguration
	}
	if host := strings.ToLower(u.Hostname()); host != discordWebhookHost && host != discordLegacyWebhookHost {
		return "", ErrInvalidProviderConfiguration
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "webhooks" {
		return "", ErrInvalidProviderConfiguration
	}
	webhookID, err := url.PathUnescape(parts[2])
	if err != nil || !digitsOnly(webhookID) {
		return "", ErrInvalidProviderConfiguration
	}
	token, err := url.PathUnescape(parts[3])
	if err != nil || token == "" || strings.ContainsAny(token, "/?#\r\n") {
		return "", ErrInvalidProviderConfiguration
	}
	config := discord.Config{}
	resolver := format.NewPropKeyResolver(&config)
	if err := resolver.SetDefaultProps(&config); err != nil {
		return "", ErrInvalidProviderConfiguration
	}
	config.WebhookID = webhookID
	config.Token = token
	return config.GetURL().String(), nil
}

func compileNtfy(fields map[string]string) (string, error) {
	topic := field(fields, "topic")
	if topic == "" || strings.ContainsAny(topic, "/?#\r\n") {
		return "", ErrInvalidProviderConfiguration
	}
	server := field(fields, "server")
	if server == "" {
		server = "https://ntfy.sh"
	}
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrInvalidProviderConfiguration
	}
	username, password := field(fields, "username"), fields["password"]
	config := ntfy.Config{}
	resolver := format.NewPropKeyResolver(&config)
	if err := resolver.SetDefaultProps(&config); err != nil {
		return "", ErrInvalidProviderConfiguration
	}
	config.Host = u.Host
	config.Scheme = u.Scheme
	config.Topic = topic
	config.Username = username
	config.Password = password
	return config.GetURL().String(), nil
}

func normalizedSMTPHost(host string) (string, bool) {
	if host == "" || strings.ContainsAny(host, " \t\r\n/@?#") {
		return "", false
	}
	u, err := url.Parse("smtp://" + host)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		u.Port() != "" || u.Host != host || u.Hostname() == "" || strings.Contains(u.Hostname(), ":") {
		return "", false
	}
	return u.Hostname(), true
}

func parseMailAddress(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", ErrInvalidProviderConfiguration
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address == "" {
		return "", ErrInvalidProviderConfiguration
	}
	return address.Address, nil
}

func splitRecipients(value string) []string {
	var recipients []string
	for _, recipient := range strings.Split(value, ",") {
		if recipient = strings.TrimSpace(recipient); recipient != "" {
			recipients = append(recipients, recipient)
		}
	}
	return recipients
}

func digitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
