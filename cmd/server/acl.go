package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

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

type aclExportJSON struct {
	Version       int           `json:"version"`
	ExportedAt    string        `json:"exported_at"`
	DefaultPolicy string        `json:"default_policy"`
	Rules         []aclRuleJSON `json:"rules"`
	RuleCount     int           `json:"rule_count"`
}

type aclImportRequest struct {
	Replace *bool         `json:"replace,omitempty"`
	Rules   []aclRuleJSON `json:"rules"`
}

func (s *server) handleListACL(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListACLRules(r.Context())
	if err != nil {
		slog.Error("list acl rules failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeACLResponse(w, s.defaultPolicyName(), rules)
}

func (s *server) handleExportACL(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListACLRules(r.Context())
	if err != nil {
		slog.Error("export acl rules failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := aclRulesJSON(rules)
	writeJSON(w, http.StatusOK, aclExportJSON{
		Version:       1,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		DefaultPolicy: s.defaultPolicyName(),
		Rules:         out,
		RuleCount:     len(out),
	})
}

func (s *server) handleImportACL(w http.ResponseWriter, r *http.Request) {
	var req aclImportRequest
	if !decodeJSON(w, r, 1<<20, &req) {
		return
	}

	replace := true
	if req.Replace != nil {
		replace = *req.Replace
	}

	rules := make([]store.ACLRule, 0, len(req.Rules))
	for _, rule := range req.Rules {
		rules = append(rules, store.ACLRule{
			SrcPeerID: rule.SrcPeerID,
			DstPeerID: rule.DstPeerID,
			Name:      rule.Name,
			Protocol:  rule.Protocol,
			PortMin:   rule.PortMin,
			PortMax:   rule.PortMax,
		})
	}

	n, err := s.store.ImportACLRules(r.Context(), rules, replace)
	if err != nil {
		slog.Warn("import acl rules failed", "error", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	slog.Info("admin imported acl rules", "rules", n, "replace", replace)
	s.audit(r, "acl_import", http.StatusOK, fmt.Sprintf("rules=%d replace=%v", n, replace))

	imported, err := s.store.ListACLRules(r.Context())
	if err != nil {
		slog.Error("list acl rules after import failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeACLResponse(w, s.defaultPolicyName(), imported)
}

func (s *server) defaultPolicyName() string {
	policy := "deny"
	if s.store.DefaultAllow {
		policy = "allow"
	}

	return policy
}

func writeACLResponse(w http.ResponseWriter, policy string, rules []store.ACLRule) {
	writeJSON(w, http.StatusOK, map[string]any{
		"default_policy": policy,
		"rules":          aclRulesJSON(rules),
	})
}

func aclRulesJSON(rules []store.ACLRule) []aclRuleJSON {
	out := make([]aclRuleJSON, 0, len(rules))
	for _, rule := range rules {
		out = append(out, aclRuleJSON(rule))
	}
	return out
}

// peerRef renders an optional ACL peer reference for audit detail:
// "any" when the field is nil (wildcard), otherwise the peer id. The
// fields are *int64, so %v would print <nil> or a pointer address.
func peerRef(id *int64) string {
	if id == nil {
		return "any"
	}
	return strconv.FormatInt(*id, 10)
}

// portRange renders an optional ACL port range for audit detail.
func portRange(portMin, portMax *int64) string {
	switch {
	case portMin == nil && portMax == nil:
		return "any"
	case portMin != nil && portMax != nil && *portMin == *portMax:
		return strconv.FormatInt(*portMin, 10)
	default:
		lo, hi := "any", "any"
		if portMin != nil {
			lo = strconv.FormatInt(*portMin, 10)
		}
		if portMax != nil {
			hi = strconv.FormatInt(*portMax, 10)
		}
		return lo + "-" + hi
	}
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
	proto := req.Protocol
	if proto == "" {
		proto = "any"
	}
	s.audit(r, "acl_create", http.StatusOK, fmt.Sprintf("rule id=%d name=%q src=%s dst=%s proto=%q ports=%s",
		id, req.Name, peerRef(req.SrcPeerID), peerRef(req.DstPeerID), proto, portRange(req.PortMin, req.PortMax)))
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
