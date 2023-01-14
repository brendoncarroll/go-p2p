package oids

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
)

type OID struct {
	s string
}

func New(xs ...int) OID {
	sb := strings.Builder{}
	for _, x := range xs {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(x))
		sb.Write(buf[:])
	}
	return OID{s: sb.String()}
}

func (oid OID) Len() int {
	return len(oid.s) / 8
}

func (oid OID) At(i int) uint64 {
	begin := i * 8
	end := begin + 8
	return binary.BigEndian.Uint64([]byte(oid.s[begin:end]))
}

func (oid OID) String() string {
	sb := strings.Builder{}
	for i := 0; i < oid.Len(); i++ {
		if i > 0 {
			sb.WriteString(".")
		}
		n := oid.At(i)
		fmt.Fprintf(&sb, "%d", n)
	}
	return sb.String()
}

func (oid OID) IsZero() bool {
	return oid.s == ""
}

func (oid OID) ASN1() (ret asn1.ObjectIdentifier) {
	for i := 0; i < oid.Len(); i++ {
		ret = append(ret, int(oid.At(i)))
	}
	return ret
}
