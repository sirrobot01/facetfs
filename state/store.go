package state

import "context"

type Store interface {
	Get(context.Context, string) ([]byte, error)
	Put(context.Context, string, []byte) error
	CompareAndSwap(context.Context, string, []byte, []byte) (bool, error)
	Delete(context.Context, string) error
}
