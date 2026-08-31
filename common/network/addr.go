package network

import (
	"net"
	"net/netip"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
)

func LocalAddrs() ([]netip.Addr, error) {
	interfaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return common.Map(interfaceAddrs, M.AddrFromNet), nil
}

func IsPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	// RFC 6598 Shared Address Space (CGNAT)，Go IsPrivate 不含此段
	if addr.Is4() {
		a4 := addr.As4()
		if a4[0] == 100 && a4[1] >= 64 && a4[1] <= 127 {
			return false
		}
	}
	return !(addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsUnspecified())
}

func IsVirtual(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsMulticast() || addr.IsInterfaceLocalMulticast()
}

func LocalPublicAddrs() ([]netip.Addr, error) {
	publicAddrs, err := LocalAddrs()
	if err != nil {
		return nil, err
	}
	return common.Filter(publicAddrs, IsPublicAddr), nil
}
