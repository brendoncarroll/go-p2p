package p2p

import (
	"net"
)

type Addr interface {
	Key() string
	MarshalText() ([]byte, error)
	UnmarshalText([]byte) error
}

type TextAddr []byte

func (a TextAddr) MarshalText() ([]byte, error) {
	return []byte(a), nil
}

func (a TextAddr) Key() string {
	panic("cannot use TextAddr")
}

func (a TextAddr) UnmarshalText(data []byte) error {
	panic("cannot unmarshal into TextAddr")
}

type HasIP interface {
	Addr
	GetIP() net.IP
	MapIP(net.IP) Addr
}

type HasTCP interface {
	GetTCP() net.TCPAddr
	MapTCP(net.TCPAddr) Addr
}

type HasUDP interface {
	GetUDP() net.UDPAddr
	MapUDP(net.UDPAddr) Addr
}

func ExpandUnspecifiedIPs(xs []Addr) (ys []Addr) {
	for _, x := range xs {
		hasIP, ok := x.(HasIP)
		if !ok {
			// Doesn't have an IP component, passthrough
			ys = append(ys, x)
			continue
		}

		// Has an IP, check if it's specified
		ipAddr := hasIP.GetIP()
		if ipAddr.IsUnspecified() {
			addrs, err := net.InterfaceAddrs()
			if err != nil {
				panic(err)
			}
			for _, addr := range addrs {
				ipNet := addr.(*net.IPNet)
				switch {
				case ipNet.IP.IsLoopback():
					continue
				case ipNet.IP.IsLinkLocalMulticast():
					continue
				default:
					y := hasIP.MapIP(ipNet.IP)
					ys = append(ys, y)
				}
			}
		} else {
			ys = append(ys, hasIP.(Addr))
		}
	}
	return ys
}

var privateNetworks = []*net.IPNet{}

func init() {
	for _, x := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	} {
		_, ipNet, err := net.ParseCIDR(x)
		if err != nil {
			panic(err)
		}
		privateNetworks = append(privateNetworks, ipNet)
	}
}

func FilterLocal(xs []Addr) (ys []Addr) {
	for _, x := range xs {
		hasIP, ok := x.(HasIP)
		if !ok {
			// Doesn't have an IP component, passthrough
			ys = append(ys, x)
			continue
		}

		ipAddr := hasIP.GetIP()
		switch {
		case ipAddr.To4() != nil:
			contains := false
			for _, ipNet := range privateNetworks {
				if ipNet.Contains(ipAddr) {
					contains = true
					break
				}
			}
			if !contains && !ipAddr.IsLinkLocalUnicast() {
				ys = append(ys, x)
			}
		case ipAddr.To16() != nil:
			if ipAddr.IsLinkLocalMulticast() || ipAddr.IsLinkLocalMulticast() {
				continue
			}
			ys = append(ys, x)
		default:
			panic("ip is neither v4 nor v6")
		}
	}
	return ys
}
