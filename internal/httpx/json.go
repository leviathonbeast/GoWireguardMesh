package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// DecodeJSON decodes a JSON request body of at most maxBytes into v.
// On failure it writes the error response (413 for oversized bodies,
// 400 otherwise) and returns false. Public handlers should use this
// instead of an unbounded json.Decoder.
func DecodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, v any) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes)).Decode(v)
	if err == nil {
		return true
	}

	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		WriteError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", tooLarge.Limit))
		return false
	}

	WriteError(w, http.StatusBadRequest, "invalid JSON")

	return false
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// API responses can carry secrets — setup keys, and a static peer's
	// WireGuard config embeds its private key — so nothing may land in a
	// browser or intermediary cache.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("write response failed", "error", err)
	}
}

func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}
