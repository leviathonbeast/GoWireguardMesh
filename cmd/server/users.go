package main

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"gowireguard/internal/store"
)

type userJSON struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	AuthSource string `json:"auth_source"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

func userInfoJSON(u store.User) userJSON {
	return userJSON{
		ID:         u.ID,
		Username:   u.Username,
		AuthSource: u.AuthSource,
		CreatedAt:  u.CreatedAt,
		UpdatedAt:  u.UpdatedAt,
	}
}

// requireSession wraps handlers that need to know WHICH admin user is
// acting (change-own-password, "who am I"). Unlike requireAdmin it does
// not accept the bare bearer token, because that is not tied to a user.
func (s *server) requireSession(next func(http.ResponseWriter, *http.Request, store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.sessionUser(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "sign in to the web UI to use this endpoint")
			return
		}
		next(w, r, user)
	}
}

// handleAccount returns the signed-in user (for the UI header / account page).
func (s *server) handleAccount(w http.ResponseWriter, r *http.Request, user store.User) {
	writeJSON(w, http.StatusOK, userInfoJSON(user))
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request, user store.User) {
	var req changePasswordRequest
	if !decodeJSON(w, r, 4<<10, &req) {
		return
	}

	// Re-authenticate with the current password before allowing a change.
	if _, err := s.store.Authenticate(r.Context(), user.Username, req.CurrentPassword); err != nil {
		s.audit(r, "password_change_failed", http.StatusUnauthorized, "user="+user.Username)
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	if err := s.store.SetPassword(r.Context(), user.ID, req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// SetPassword bumped the session epoch, so this request's cookie is now
	// stale — issue a fresh one so the user stays signed in.
	refreshed, err := s.store.UserByID(r.Context(), user.ID)
	if err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     uiSessionCookie,
			Value:    s.signUISession(refreshed, time.Now().UTC()),
			Path:     "/",
			MaxAge:   int(uiSessionTTL.Seconds()),
			HttpOnly: true,
			Secure:   s.requestIsHTTPS(r),
			SameSite: http.SameSiteStrictMode,
		})
	}

	s.audit(r, "password_change", http.StatusOK, "user="+user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}

func (s *server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, userInfoJSON(u))
	}
	writeJSON(w, http.StatusOK, out)
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !decodeJSON(w, r, 4<<10, &req) {
		return
	}

	user, err := s.store.CreateLocalUser(r.Context(), req.Username, req.Password)
	switch {
	case errors.Is(err, store.ErrUserExists):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.audit(r, "user_create", http.StatusOK, "user="+user.Username)
	writeJSON(w, http.StatusOK, userInfoJSON(user))
}

func (s *server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.audit(r, "user_delete", http.StatusOK, "user_id="+strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
