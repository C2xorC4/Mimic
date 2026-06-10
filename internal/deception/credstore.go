package deception

import (
	"fmt"
	"regexp"
	"sort"
)

// Credential is a fake account in the shared deception pool. It is the single
// source of truth: the same Credential both authenticates against a honeypot
// (e.g. the SMB server) and is "leaked" by another service, so the planted value
// and the accepted value cannot drift.
type Credential struct {
	ID       string
	Username string
	Password string
	Domain   string
}

// CredStore is the shared, protocol-neutral credential pool, keyed by id.
type CredStore struct {
	byID map[string]Credential
}

// NewCredStore builds a store from a credential slice (last write wins on id).
func NewCredStore(creds []Credential) *CredStore {
	m := make(map[string]Credential, len(creds))
	for _, c := range creds {
		m[c.ID] = c
	}
	return &CredStore{byID: m}
}

// Get returns the credential for id. Safe on a nil store.
func (s *CredStore) Get(id string) (Credential, bool) {
	if s == nil {
		return Credential{}, false
	}
	c, ok := s.byID[id]
	return c, ok
}

// All returns the credentials sorted by id (deterministic order).
func (s *CredStore) All() []Credential {
	if s == nil {
		return nil
	}
	out := make([]Credential, 0, len(s.byID))
	for _, c := range s.byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// credPlaceholder matches {{cred:<id>.<field>}} where field is username|password|domain.
// The id excludes '.' so the field separator is unambiguous.
var credPlaceholder = regexp.MustCompile(`\{\{cred:([A-Za-z0-9_-]+)\.(username|password|domain)\}\}`)

// Render substitutes {{cred:id.field}} placeholders in tmpl against the store.
// It returns an error (and leaves the offending placeholder in place) when an id
// is unknown, so misconfigured seeded content fails loudly at startup.
func (s *CredStore) Render(tmpl string) (string, error) {
	var rerr error
	out := credPlaceholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		sub := credPlaceholder.FindStringSubmatch(m)
		id, field := sub[1], sub[2]
		c, ok := s.Get(id)
		if !ok {
			rerr = fmt.Errorf("unknown credential id %q in template", id)
			return m
		}
		switch field {
		case "username":
			return c.Username
		case "password":
			return c.Password
		case "domain":
			return c.Domain
		}
		return m
	})
	return out, rerr
}

// LeakString returns the conventional "username:password" form for a credential
// id, used by services that leak a credential in a banner or response body.
func (s *CredStore) LeakString(id string) (string, bool) {
	c, ok := s.Get(id)
	if !ok {
		return "", false
	}
	return c.Username + ":" + c.Password, true
}
