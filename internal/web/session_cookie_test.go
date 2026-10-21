package web

import (
	"net/http"

	"github.com/crypt0rr/edgewatch/internal/auth"
)

// addTestSessionCookie models the cookie name the request's transport uses.
// Tests that exercise trusted forwarded HTTPS set the cookie returned by the
// login handler directly, so those requests retain the configured trust check.
func addTestSessionCookie(request *http.Request, value string) {
	name := auth.SessionCookie
	if auth.SessionCookieSecure(request, false) {
		name = auth.SecureSessionCookie
	}
	request.AddCookie(&http.Cookie{Name: name, Value: value})
}
