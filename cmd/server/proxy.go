package main

import (
	"log/slog"
	"net/http"
	"strconv"
)

type proxyEventJSON struct {
	ID           int64  `json:"id"`
	At           string `json:"at"`
	PeerID       int64  `json:"peer_id,omitempty"`
	PeerHostname string `json:"peer_hostname,omitempty"`
	Method       string `json:"method,omitempty"`
	Host         string `json:"host,omitempty"`
	Path         string `json:"path,omitempty"`
	Status       int    `json:"status,omitempty"`
	DurationMS   int64  `json:"duration_ms,omitempty"`
	ReqBytes     int64  `json:"req_bytes,omitempty"`
	RespBytes    int64  `json:"resp_bytes,omitempty"`
	ClientIP     string `json:"client_ip,omitempty"`
	Service      string `json:"service,omitempty"`
}

func (s *server) handleListProxyEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200

	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > 2000 {
			writeError(w, http.StatusBadRequest, "limit must be 1-2000")
			return
		}

		limit = n
	}

	rows, err := s.store.ListProxyEvents(r.Context(), limit)
	if err != nil {
		slog.Error("list proxy events failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]proxyEventJSON, 0, len(rows))
	for _, e := range rows {
		out = append(out, proxyEventJSON(e))
	}

	writeJSON(w, http.StatusOK, out)
}
