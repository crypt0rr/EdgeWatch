package store

import (
	"context"
	"time"
)

// The account fixtures of the store's tests. The store's own writers check
// what a fixture must be free of: CreateUserWithInvite needs an
// administrator and creates a pending account, CreateUserInviteWithAudit
// needs one and revokes the account's older links, and CreateSignInSession
// needs the account's verified credentials.

// createTestUser creates the account in the tenant as createUser does, with
// its password and enabled state, without an actor check or a link.
func createTestUser(ctx context.Context, ts *TenantStore, u User, audit AuditEntry) (User, error) {
	if err := ts.ready(); err != nil {
		return User{}, err
	}
	return ts.createUser(ctx, u, nil, audit, nil)
}

// createTestLink stores a link for the tenant's account, by the hash of its
// token, without an issuer or a record, and keeps the account's other
// links. Another tenant's account is ErrNotFound.
func createTestLink(ctx context.Context, ts *TenantStore, idHash, userID string, created, expires time.Time) error {
	if err := ts.ready(); err != nil {
		return err
	}
	inserted, err := execCount(ctx, ts.store.DB, `INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at,used_at) SELECT ?,id,'',?,?,NULL FROM users WHERE id=? AND tenant_id=?`, idHash, created.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), userID, ts.scope.id)
	if err == nil && inserted != 1 {
		err = ErrNotFound
	}
	return err
}

// createTestSession inserts a session of the account as a sign-in does,
// removing the account's least recently used sessions beyond
// MaxSessionsPerAccount, without checking its credentials.
func createTestSession(ctx context.Context, s *Store, userID, idHash, csrf string, created, expires time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertSessionTx(ctx, tx, idHash, userID, csrf, created, expires); err != nil {
		return err
	}
	return tx.Commit()
}

// saveTestRecoveryCodes replaces the account's recovery codes with the
// stored hashes.
func saveTestRecoveryCodes(ctx context.Context, s *Store, userID string, hashes []string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, hash := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash,user_id) VALUES(?,?)`, hash, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
