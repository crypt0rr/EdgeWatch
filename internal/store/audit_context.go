package store

import "context"

// AuditContext carries request-scoped correlation data into store mutations.
// It lives in the store package so every transactional audit insertion path
// can apply the same attribution without coupling the store to the web layer.
type AuditContext struct {
	RequestID string
	SourceIP  string
}

type auditContextKey struct{}

// WithAuditContext attaches the request correlation and resolved client
// identity used for subsequent audit records. Empty values are accepted for
// non-HTTP callers and leave supplied AuditEntry values unchanged.
func WithAuditContext(ctx context.Context, requestID, sourceIP string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, auditContextKey{}, AuditContext{RequestID: requestID, SourceIP: sourceIP})
}

func auditContextFromContext(ctx context.Context) AuditContext {
	if ctx == nil {
		return AuditContext{}
	}
	value, _ := ctx.Value(auditContextKey{}).(AuditContext)
	return value
}
