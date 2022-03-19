package p2p

import (
	"net"
	"net/netip"
)

type HasIP interface {
	GetIP() netip.Addr
	MapIP(func(netip.Addr) netip.Addr) Addr
}

func ExtractIP(x Addr) (netip.Addr, bool) {
	if hasIP, ok := x.(HasIP); ok {
		return hasIP.GetIP(), true
	}
	if unwrap, ok := x.(UnwrapAddr); ok {
		return ExtractIP(unwrap.Unwrap())
	}
	return netip.Addr{}, false
}

func MapIP(x Addr, fn func(netip.Addr) netip.Addr) Addr {
	if x, ok := x.(HasIP); ok {
		return x.MapIP(fn)
	}
	if x, ok := x.(UnwrapAddr); ok {
		return x.Map(func(inner Addr) Addr {
			return MapIP(inner, fn)
		})
	}
	return x
}

func FilterIPs(xs []Addr, preds ...func(netip.Addr) bool) (ys []Addr) {
	for _, x := range xs {
		ip, ok := ExtractIP(x)
		keep := true
		if ok {
			for _, pred := range preds {
				if !pred(ip) {
					keep = false
					break
				}
			}
		}
		if keep {
			ys = append(ys, x)
		}
	}
	return ys
}

type hasIP2[Self Addr] interface {
	Addr
	GetIP() netip.Addr
	MapIP(func(netip.Addr) netip.Addr) Self
}

// ExpandUnspecifiedIPs will expand 0.0.0.0 into all of IPs on the host.
func ExpandUnspecifiedIPs[A hasIP2[A]](xs []A) (ys []A) {
	for _, x := range xs {
		ipAddr := x.GetIP()
		// Has an IP, check if it's specified
		if ipAddr.IsUnspecified() {
			addrs, err := net.InterfaceAddrs()
			if err != nil {
				panic(err)
			}
			for _, addr := range addrs {
				ipNet := addr.(*net.IPNet)
				switch {
				// case ipNet.IP.IsLoopback():
				// 	continue
				// case ipNet.IP.IsLinkLocalMulticast():
				// 	continue
				default:
					y := x.MapIP(func(netip.Addr) netip.Addr {
						a, _ := netip.AddrFromSlice(ipNet.IP)
						return a
					})
					ys = append(ys, y)
				}
			}
		} else {
			ys = append(ys, x)
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

func OnlyGlobal(x net.IP) bool {
	switch {
	case x.To4() != nil:
		contains := false
		for _, ipNet := range privateNetworks {
			if ipNet.Contains(x) {
				contains = true
				break
			}
		}
		if !contains && !x.IsLinkLocalUnicast() {
			return true
		}
	case x.To16() != nil:
		if x.IsLinkLocalUnicast() || x.IsLinkLocalMulticast() {
			return false
		}
	default:
		panic("ip is neither v4 nor v6")
	}
	return false
}

func NoLinkLocal(x net.IP) bool {
	return !(x.IsLinkLocalUnicast() || x.IsLinkLocalMulticast() || x.IsInterfaceLocalMulticast())
}

func NoLoopback(x net.IP) bool {
	return !x.IsLoopback()
}
