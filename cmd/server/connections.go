package main

import (
	"log/slog"
	"net/http"
	"strconv"
)

type connectionEventJSON struct {
	ID               int64  `json:"id"`
	At               string `json:"at"`
	Kind             string `json:"kind"` // direct | relay
	FromState        string `json:"from_state,omitempty"`
	ToState          string `json:"to_state"`
	ReporterPeerID   int64  `json:"reporter_peer_id"`
	ReporterHostname string `json:"reporter_hostname,omitempty"`
	RemotePeerID     int64  `json:"remote_peer_id"`
	RemoteHostname   string `json:"remote_hostname,omitempty"`
}

func (s *server) handleListConnectionEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200

	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > 2000 {
			writeError(w, http.StatusBadRequest, "limit must be 1-2000")
			return
		}

		limit = n
	}

	rows, err := s.store.ListConnectionEvents(r.Context(), limit)
	if err != nil {
		slog.Error("list connection events failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]connectionEventJSON, 0, len(rows))
	for _, e := range rows {
		out = append(out, connectionEventJSON(e))
	}

	writeJSON(w, http.StatusOK, out)
}
