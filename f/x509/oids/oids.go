package oids

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
)

type OID string

func New(xs ...int) OID {
	sb := strings.Builder{}
	for _, x := range xs {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(x))
		sb.Write(buf[:])
	}
	return OID(sb.String())
}

func (oid OID) Len() int {
	return len(oid) / 8
}

func (oid OID) At(i int) uint64 {
	begin := i * 8
	end := begin + 8
	return binary.BigEndian.Uint64([]byte(oid[begin:end]))
}

func (oid OID) String() string {
	sb := strings.Builder{}
	sb.WriteString("OID{")
	for i := 0; i < oid.Len(); i++ {
		n := oid.At(i)
		fmt.Fprintf(&sb, "%d", n)
	}
	sb.WriteString("}")
	return sb.String()
}

func (oid OID) ASN1() (ret asn1.ObjectIdentifier) {
	for i := 0; i < oid.Len(); i++ {
		ret = append(ret, int(oid.At(i)))
	}
	return ret
}
