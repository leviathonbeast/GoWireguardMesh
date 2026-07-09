package store

import (
	"context"
	"errors"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !verifyPassword(hash, "correct horse battery staple") {
		t.Fatal("verifyPassword rejected the correct password")
	}
	if verifyPassword(hash, "wrong password") {
		t.Fatal("verifyPassword accepted a wrong password")
	}
	if verifyPassword("", "anything") || verifyPassword("$argon2id$garbage", "x") {
		t.Fatal("verifyPassword accepted a malformed hash")
	}
}

func TestCreateAndAuthenticateUser(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	if _, err := st.CreateLocalUser(ctx, "alice", "s3cret-password"); err != nil {
		t.Fatalf("CreateLocalUser: %v", err)
	}

	u, err := st.Authenticate(ctx, "alice", "s3cret-password")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if u.Username != "alice" || u.AuthSource != "local" {
		t.Fatalf("unexpected user %+v", u)
	}

	if _, err := st.Authenticate(ctx, "alice", "nope"); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password err = %v, want ErrAuth", err)
	}
	if _, err := st.Authenticate(ctx, "ghost", "whatever"); !errors.Is(err, ErrAuth) {
		t.Fatalf("unknown user err = %v, want ErrAuth", err)
	}

	// Duplicate username rejected.
	if _, err := st.CreateLocalUser(ctx, "alice", "another-pass"); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate user err = %v, want ErrUserExists", err)
	}

	// Weak password rejected.
	if _, err := st.CreateLocalUser(ctx, "bob", "short"); err == nil {
		t.Fatal("short password should be rejected")
	}
}

func TestSetPasswordBumpsSessionEpoch(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	u, err := st.CreateLocalUser(ctx, "alice", "s3cret-password")
	if err != nil {
		t.Fatalf("CreateLocalUser: %v", err)
	}
	if u.SessionEpoch != 0 {
		t.Fatalf("initial epoch = %d, want 0", u.SessionEpoch)
	}

	if err := st.SetPassword(ctx, u.ID, "new-password-123"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	after, err := st.UserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if after.SessionEpoch != 1 {
		t.Fatalf("epoch after change = %d, want 1", after.SessionEpoch)
	}
	if _, err := st.Authenticate(ctx, "alice", "new-password-123"); err != nil {
		t.Fatalf("auth with new password: %v", err)
	}
	if _, err := st.Authenticate(ctx, "alice", "s3cret-password"); !errors.Is(err, ErrAuth) {
		t.Fatal("old password still works after change")
	}
}

func TestEnsureSeedUserOnceAndShortToken(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	// A short bootstrap password (a legacy admin token) must still seed —
	// otherwise an existing deployment would be locked out on upgrade.
	seeded, err := st.EnsureSeedUser(ctx, "admin", "short")
	if err != nil {
		t.Fatalf("EnsureSeedUser: %v", err)
	}
	if !seeded {
		t.Fatal("first EnsureSeedUser should seed")
	}
	if _, err := st.Authenticate(ctx, "admin", "short"); err != nil {
		t.Fatalf("seeded admin cannot authenticate: %v", err)
	}

	// Idempotent: a second call with any credential does nothing.
	seeded, err = st.EnsureSeedUser(ctx, "admin", "different")
	if err != nil {
		t.Fatalf("second EnsureSeedUser: %v", err)
	}
	if seeded {
		t.Fatal("second EnsureSeedUser should be a no-op")
	}
}

func TestDeleteUserGuardsLastAdmin(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t, "100.64.0.0/16")

	a, err := st.CreateLocalUser(ctx, "alice", "s3cret-password")
	if err != nil {
		t.Fatalf("CreateLocalUser: %v", err)
	}
	// Deleting the only user is refused.
	if err := st.DeleteUser(ctx, a.ID); err == nil {
		t.Fatal("deleting the last admin should fail")
	}

	b, err := st.CreateLocalUser(ctx, "bob", "s3cret-password")
	if err != nil {
		t.Fatalf("CreateLocalUser bob: %v", err)
	}
	if _, err := st.CreateLocalUser(ctx, "carol", "s3cret-password"); err != nil {
		t.Fatalf("CreateLocalUser carol: %v", err)
	}
	// With three users, deleting one succeeds.
	if err := st.DeleteUser(ctx, b.ID); err != nil {
		t.Fatalf("deleting a non-last user should succeed: %v", err)
	}
	// Deleting a now-missing user (two remain, so the last-admin guard does
	// not fire) reports ErrNotFound.
	if err := st.DeleteUser(ctx, b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-delete err = %v, want ErrNotFound", err)
	}
}
