// Package updatecheck retrieves the latest stable EdgeWatch release from the
// fixed GitHub repository endpoint. It deliberately has no persistence or
// notification concerns so those responsibilities can be tested separately.
package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	LatestReleaseEndpoint = "https://api.github.com/repos/crypt0rr/EdgeWatch/releases/latest"
	ReleasePageBase       = "https://github.com/crypt0rr/EdgeWatch/releases/tag/"
	CheckInterval         = 3 * time.Hour
	RequestTimeout        = 8 * time.Second
	MaxResponseBytes      = 1 << 20
	maxReleaseName        = 256
	maxPublishedAt        = 64
	maxETag               = 512
)

// Release is the bounded, normalized subset of a GitHub release used by the
// application. Raw release JSON is never persisted or exposed by EdgeWatch.
type Release struct {
	Version     string
	URL         string
	Name        string
	PublishedAt string
}

// Result describes a successful release check. A 304 response has
// NotModified=true and does not carry a new release.
type Result struct {
	Release     Release
	ETag        string
	NotModified bool
}

// Client is safe to use concurrently. Endpoint and HTTPClient are injectable
// for deterministic tests; production uses NewClient and the fixed HTTPS
// GitHub endpoint.
type Client struct {
	Endpoint         string
	HTTPClient       *http.Client
	UserAgent        string
	MaxResponseBytes int64
}

func NewClient() *Client {
	return &Client{
		Endpoint:         LatestReleaseEndpoint,
		HTTPClient:       &http.Client{},
		UserAgent:        "EdgeWatch update checker",
		MaxResponseBytes: MaxResponseBytes,
	}
}

// NormalizeVersion accepts the v-prefixed and unprefixed forms used by build
// pipelines and Git tags. Empty, development, and malformed values return an
// empty string rather than being treated as semantic versions.
func NormalizeVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "dev") {
		return ""
	}
	if !strings.HasPrefix(raw, "v") {
		raw = "v" + raw
	}
	if !semver.IsValid(raw) {
		return ""
	}
	// Canonicalization deliberately normalizes equivalent forms such as
	// 1.2 -> v1.2.0 and drops build metadata, which is not meaningful when
	// ordering releases. The returned value is the only form persisted or
	// compared by EdgeWatch.
	return semver.Canonical(raw)
}

func CompareVersions(left, right string) int {
	left, right = NormalizeVersion(left), NormalizeVersion(right)
	if left == "" || right == "" {
		return 0
	}
	return semver.Compare(left, right)
}

// ReleasePageURL returns the repository release page for a validated tag.
// Invalid and development versions intentionally return an empty string.
func ReleasePageURL(version string) string {
	version = NormalizeVersion(version)
	if version == "" {
		return ""
	}
	return ReleasePageBase + url.PathEscape(version)
}

type githubRelease struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
}

func boundedString(raw string, max int) string {
	raw = strings.TrimSpace(raw)
	if len(raw) > max {
		return raw[:max]
	}
	return raw
}

func validateHTMLURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), "github.com") || (parsed.Port() != "" && parsed.Port() != "443") || parsed.User != nil || !strings.HasPrefix(parsed.EscapedPath(), "/crypt0rr/EdgeWatch/releases/tag/") {
		return errors.New("release response has an invalid release URL")
	}
	return nil
}

func (c *Client) Check(ctx context.Context, etag string) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = LatestReleaseEndpoint
	}
	endpointURL, err := url.Parse(endpoint)
	if err != nil || endpointURL.Scheme != "https" || endpointURL.Host == "" || endpointURL.User != nil {
		return Result{}, errors.New("release endpoint must use HTTPS")
	}
	requestCtx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Result{}, fmt.Errorf("create release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	userAgent := c.UserAgent
	if userAgent == "" {
		userAgent = "EdgeWatch update checker"
	}
	req.Header.Set("User-Agent", userAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	// Keep redirects inside the fixed HTTPS GitHub host. This also prevents a
	// compromised intermediary from turning the checker into an open fetcher.
	clientCopy := *client
	clientCopy.CheckRedirect = func(redirect *http.Request, via []*http.Request) error {
		// net/http passes every request already followed in via. The initial
		// request is entry zero, so a length of four means the fourth redirect
		// is about to be followed. Allow at most three redirects.
		if len(via) >= 4 {
			return errors.New("release endpoint redirected too many times")
		}
		if redirect.URL.Scheme != "https" ||
			!strings.EqualFold(redirect.URL.Hostname(), endpointURL.Hostname()) ||
			redirect.URL.Port() != endpointURL.Port() ||
			redirect.URL.User != nil {
			return errors.New("release endpoint redirect is not permitted")
		}
		return nil
	}
	response, err := clientCopy.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("release check request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return Result{ETag: boundedString(response.Header.Get("ETag"), maxETag), NotModified: true}, nil
	}
	if response.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("release check returned HTTP %d", response.StatusCode)
	}
	maxBytes := c.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = MaxResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read release response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return Result{}, errors.New("release response exceeds size limit")
	}
	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return Result{}, fmt.Errorf("decode release response: %w", err)
	}
	if release.Draft || release.Prerelease {
		return Result{}, errors.New("release response is not a stable release")
	}
	if err := validateHTMLURL(release.HTMLURL); err != nil {
		return Result{}, err
	}
	version := NormalizeVersion(release.TagName)
	if version == "" || semver.Prerelease(version) != "" {
		return Result{}, errors.New("release response has an invalid semantic version")
	}
	// Build the link from the validated tag instead of trusting an arbitrary
	// html_url returned by an upstream response.
	releaseURL := ReleasePageURL(version)
	return Result{
		ETag: boundedString(response.Header.Get("ETag"), maxETag),
		Release: Release{
			Version:     version,
			URL:         releaseURL,
			Name:        boundedString(release.Name, maxReleaseName),
			PublishedAt: boundedString(release.PublishedAt, maxPublishedAt),
		},
	}, nil
}
