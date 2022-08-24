package kademlia

import "fmt"

type ErrNotFound struct {
	Key []byte
}

func (e ErrNotFound) Error() string {
	return fmt.Sprintf("key %q not found", e.Key)
}
