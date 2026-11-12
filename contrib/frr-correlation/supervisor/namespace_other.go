//go:build !linux

package supervisor

import "context"

// Namespace is unavailable off Linux; every constructor refuses.
type Namespace struct{}

func NewNamespace(context.Context) (*Namespace, error) { return nil, ErrUnsupported }

func (*Namespace) Identity() (Identity, error) { return Identity{}, ErrUnsupported }

func (*Namespace) Close() error { return ErrUnsupported }
