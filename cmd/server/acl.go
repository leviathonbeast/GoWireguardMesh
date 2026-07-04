package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"gowireguard/internal/store"
)

type aclRuleJSON struct {
	ID        int64  `json:"id"`
	SrcPeerID *int64 `json:"src_peer_id"` // null = any
	SrcLabel  string `json:"src_label"`
	DstPeerID *int64 `json:"dst_peer_id"` // null = any
	DstLabel  string `json:"dst_label"`
	CreatedAt string `json:"created_at"`
}

func (s *server) handleListACL(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListACLRules(r.Context())
	if err != nil {
		log.Printf("list acl rules: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]aclRuleJSON, 0, len(rules))
	for _, rule := range rules {
		out = append(out, aclRuleJSON(rule))
	}

	policy := "deny"
	if s.store.DefaultAllow {
		policy = "allow"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"default_policy": policy,
		"rules":          out,
	})
}

func (s *server) handleCreateACL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SrcPeerID *int64 `json:"src_peer_id"` // null = any
		DstPeerID *int64 `json:"dst_peer_id"` // null = any
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	id, err := s.store.CreateACLRule(r.Context(), req.SrcPeerID, req.DstPeerID)
	if err != nil {
		log.Printf("create acl rule: %v", err)
		writeError(w, http.StatusBadRequest, "could not create rule (same peer twice, or unknown peer id?)")

		return
	}

	log.Printf("admin created acl rule %d", id)
	writeJSON(w, http.StatusOK, map[string]int64{"id": id})
}

func (s *server) handleDeleteACL(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}

	switch err := s.store.DeleteACLRule(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case err != nil:
		log.Printf("delete acl rule %d: %v", id, err)
		writeError(w, http.StatusInternalServerError, "internal error")
	default:
		log.Printf("admin deleted acl rule %d", id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}
