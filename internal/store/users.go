package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// ErrUserExists is returned when creating a user whose username is taken.
var ErrUserExists = errors.New("user already exists")

// ErrAuth is returned for a failed username/password check. It is
// deliberately identical for "no such user" and "wrong password" so the
// caller cannot use it to enumerate accounts.
var ErrAuth = errors.New("invalid username or password")

// User is an admin account that can sign into the web UI.
type User struct {
	ID           int64
	Username     string
	AuthSource   string // "local" | "oidc"
	SessionEpoch int64  // bumped to invalidate this user's sessions
	CreatedAt    string
	UpdatedAt    string
}

// argon2id parameters. These are the OWASP-recommended interactive
// defaults; they cost ~40ms per hash on commodity hardware, which is fine
// for a login form and expensive for offline cracking.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// hashPassword returns a self-describing PHC-style argon2id string.
func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// verifyPassword checks password against a PHC-style argon2id encoding in
// constant time. A malformed or empty hash never verifies.
func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false
	}
	var mem, tim, par int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &tim, &par); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	got := argon2.IDKey([]byte(password), salt, uint32(tim), uint32(mem), uint8(par), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func validateUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	if len(username) > 64 {
		return "", fmt.Errorf("username too long (max 64)")
	}
	for _, r := range username {
		ok := r == '-' || r == '_' || r == '.' || r == '@' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return "", fmt.Errorf("username may contain only letters, digits, and -_.@")
		}
	}
	return username, nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 512 {
		return fmt.Errorf("password too long (max 512)")
	}
	return nil
}

// CreateLocalUser inserts a local username/password admin account.
func (s *Store) CreateLocalUser(ctx context.Context, username, password string) (User, error) {
	username, err := validateUsername(username)
	if err != nil {
		return User{}, err
	}
	if err := validatePassword(password); err != nil {
		return User{}, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}

	now := time.Now().UTC().Format(timeFormat)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, auth_source, created_at, updated_at)
		 VALUES (?, ?, 'local', ?, ?)`,
		username, hash, now, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, fmt.Errorf("%w: %s", ErrUserExists, username)
		}
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	id, _ := res.LastInsertId()
	return s.userByID(ctx, id)
}

// EnsureSeedUser creates the initial admin account on first boot when no
// users exist yet, using the bearer admin token as the bootstrap password.
// This keeps existing deployments working: sign in as this username with
// the admin token, then change the password. Returns whether it seeded.
func (s *Store) EnsureSeedUser(ctx context.Context, username, bootstrapPassword string) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return false, fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return false, nil
	}
	if _, err := s.CreateLocalUser(ctx, username, bootstrapPassword); err != nil {
		// A too-short admin token still seeds: we skip the length rule for
		// the bootstrap account so a legacy short token isn't locked out.
		hash, herr := hashPassword(bootstrapPassword)
		if herr != nil {
			return false, herr
		}
		now := time.Now().UTC().Format(timeFormat)
		if _, ierr := s.db.ExecContext(ctx,
			`INSERT INTO users (username, password_hash, auth_source, created_at, updated_at)
			 VALUES (?, ?, 'local', ?, ?)`, username, hash, now, now); ierr != nil {
			return false, fmt.Errorf("seed user: %w", ierr)
		}
	}
	return true, nil
}

// Authenticate verifies a username/password pair and returns the user.
// Always does the argon2 work (against a dummy hash for unknown users) so
// response timing does not reveal whether the username exists.
func (s *Store) Authenticate(ctx context.Context, username, password string) (User, error) {
	username = strings.TrimSpace(username)

	var (
		id     int64
		hash   string
		source string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, password_hash, auth_source FROM users WHERE username = ?`, username,
	).Scan(&id, &hash, &source)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Constant-work path: verify against a throwaway hash.
		verifyPassword("$argon2id$v=19$m=65536,t=1,p=4$YWJjZGVmZ2hpamtsbW5vcA$"+
			"c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ", password)
		return User{}, ErrAuth
	case err != nil:
		return User{}, fmt.Errorf("look up user: %w", err)
	}

	if source != "local" || !verifyPassword(hash, password) {
		return User{}, ErrAuth
	}
	return s.userByID(ctx, id)
}

// SetPassword changes a user's password and bumps their session epoch so
// existing session cookies are invalidated.
func (s *Store) SetPassword(ctx context.Context, userID int64, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(timeFormat)
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, session_epoch = session_epoch + 1, updated_at = ?
		 WHERE id = ? AND auth_source = 'local'`,
		hash, now, userID,
	)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser removes an account. Refuses to delete the last remaining user
// so the UI can never be locked out.
func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete user: %w", err)
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if count <= 1 {
		return fmt.Errorf("cannot delete the last remaining admin user")
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// ListUsers returns all admin accounts, ordered by id.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, auth_source, session_epoch, created_at, updated_at
		 FROM users ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.AuthSource, &u.SessionEpoch, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserByID returns one user (for session validation). Exported so the HTTP
// layer can confirm a cookie's user still exists and matches its epoch.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return s.userByID(ctx, id)
}

func (s *Store) userByID(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, auth_source, session_epoch, created_at, updated_at
		 FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Username, &u.AuthSource, &u.SessionEpoch, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("look up user %d: %w", id, err)
	}
	return u, nil
}
