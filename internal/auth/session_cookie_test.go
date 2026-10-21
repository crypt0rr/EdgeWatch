package auth

import (
	"net/http"
)

func addAuthTestSessionCookie(request *http.Request, value string) {
	name := SessionCookie
	if SessionCookieSecure(request, false) {
		name = SecureSessionCookie
	}
	request.AddCookie(&http.Cookie{Name: name, Value: value})
}
