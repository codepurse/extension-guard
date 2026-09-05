package policy

import (
	"fmt"
	"strings"
)

// Validate refuses a config the guard would otherwise have to guess at.
//
// It runs at load rather than at use, so a hand-edited file is rejected where
// somebody can see the message instead of quietly enforcing something its author
// did not write. That distinction is the whole reason this is a separate step:
// every field here has a "not sure" state, and the guard's answer to not being
// sure is always to refuse rather than to pick.
func (c Config) Validate() error {
	if err := c.validateHardening(); err != nil {
		return err
	}
	seen := make(map[string]bool, len(c.Extensions))
	for _, e := range c.Extensions {
		name := strings.ToLower(strings.TrimSpace(e.Name))
		if name == "" {
			return fmt.Errorf("an extension has no name")
		}
		if seen[name] {
			return fmt.Errorf("duplicate extension name %q", e.Name)
		}
		seen[name] = true
	}
	return nil
}
