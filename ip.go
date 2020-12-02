package p2p

import "net"

type HasIP interface {
	GetIP() net.IP
	MapIP(net.IP) Addr
}

func getIP(x Addr) net.IP {
	if hasIP, ok := x.(HasIP); ok {
		return hasIP.GetIP()
	}
	if unwrap, ok := x.(UnwrapAddr); ok {
		return getIP(unwrap.Unwrap())
	}
	return nil
}

func FilterIPs(xs []Addr, preds ...func(net.IP) bool) (ys []Addr) {
	for _, x := range xs {
		ip := getIP(x)
		keep := true
		if ip != nil {
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

func ExpandUnspecifiedIPs(xs []Addr) (ys []Addr) {
	for _, x := range xs {
		hasIP, ok := x.(HasIP)
		if !ok {
			ys = append(ys, x)
			continue
		}
		ipAddr := hasIP.GetIP()
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
