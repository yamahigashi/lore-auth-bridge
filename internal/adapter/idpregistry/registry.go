package idpregistry

import (
	"fmt"
	"sort"

	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
)

type Registry struct {
	defaultID string
	byID      map[string]ports.IdentityProvider
}

func New(defaultID string) *Registry {
	return &Registry{defaultID: defaultID, byID: map[string]ports.IdentityProvider{}}
}

func (r *Registry) Register(provider ports.IdentityProvider) error {
	if provider == nil {
		return fmt.Errorf("idp registry: provider is nil")
	}
	descriptor := provider.Descriptor()
	if descriptor.ID == "" {
		return fmt.Errorf("idp registry: provider id is required")
	}
	if _, exists := r.byID[descriptor.ID]; exists {
		return fmt.Errorf("idp registry: duplicate provider id %q", descriptor.ID)
	}
	r.byID[descriptor.ID] = provider
	return nil
}

func (r *Registry) Get(id string) (ports.IdentityProvider, bool) {
	if r == nil {
		return nil, false
	}
	provider, ok := r.byID[id]
	return provider, ok
}

func (r *Registry) DefaultID() string {
	if r == nil {
		return ""
	}
	return r.defaultID
}

func (r *Registry) List() []ports.IdentityProviderDescriptor {
	if r == nil {
		return nil
	}
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ports.IdentityProviderDescriptor, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.byID[id].Descriptor())
	}
	return out
}
