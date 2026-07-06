package main

import (
	"errors"
	"fmt"
	"log/slog"
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
	Name      string `json:"name,omitempty"`
	Protocol  string `json:"protocol"`
	PortMin   *int64 `json:"port_min,omitempty"`
	PortMax   *int64 `json:"port_max,omitempty"`
	CreatedAt string `json:"created_at"`
}

func (s *server) handleListACL(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListACLRules(r.Context())
	if err != nil {
		slog.Error("list acl rules failed", "error", err)
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
		Name      string `json:"name,omitempty"`
		Protocol  string `json:"protocol,omitempty"`
		PortMin   *int64 `json:"port_min,omitempty"`
		PortMax   *int64 `json:"port_max,omitempty"`
	}

	if !decodeJSON(w, r, 64<<10, &req) {
		return
	}

	id, err := s.store.CreateACLRuleDetailed(r.Context(), store.ACLRule{
		SrcPeerID: req.SrcPeerID,
		DstPeerID: req.DstPeerID,
		Name:      req.Name,
		Protocol:  req.Protocol,
		PortMin:   req.PortMin,
		PortMax:   req.PortMax,
	})
	if err != nil {
		slog.Warn("create acl rule failed", "error", err)
		writeError(w, http.StatusBadRequest, "could not create rule (check peers, protocol, and port range)")

		return
	}

	slog.Info("admin created acl rule", "rule_id", id)
	s.audit(r, "acl_create", http.StatusOK, fmt.Sprintf("rule id=%d name=%q src=%v dst=%v proto=%q ports=%v-%v", id, req.Name, req.SrcPeerID, req.DstPeerID, req.Protocol, req.PortMin, req.PortMax))
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
		slog.Error("delete acl rule failed", "rule_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	default:
		slog.Info("admin deleted acl rule", "rule_id", id)
		s.audit(r, "acl_delete", http.StatusOK, fmt.Sprintf("rule id=%d", id))
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}
