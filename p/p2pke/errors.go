package p2pke

import "fmt"

type ErrNoCommonSuite struct {
	ServerSupports []string
}

func (e ErrNoCommonSuite) Error() string {
	return fmt.Sprintf("p2pke: no common suites: server supports %v", e.ServerSupports)
}

type ErrSessionExpired struct{}

func (e ErrSessionExpired) Error() string {
	return fmt.Sprintf("p2pke: session expired")
}
