package grpcrebac

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const rebacServiceMethodPrefix = "/ucs.auth.RebacApi/"

func DefaultAllowedPeerCIDRs() []string {
	return []string{"127.0.0.1/32", "::1/128"}
}

func ParseAllowedPeerCIDRs(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for i, value := range values {
		prefix, err := parseAllowedPeerCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func UnaryPeerAllowlistInterceptor(prefixes []netip.Prefix) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info == nil || !strings.HasPrefix(info.FullMethod, rebacServiceMethodPrefix) {
			return handler(ctx, req)
		}
		addr, ok := peerAddr(ctx)
		if !ok || !addrAllowed(addr, prefixes) {
			return nil, status.Error(codes.PermissionDenied, "rebac caller is not allowed")
		}
		return handler(ctx, req)
	}
}

func parseAllowedPeerCIDR(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("CIDR must not be empty")
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func peerAddr(ctx context.Context) (netip.Addr, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return netip.Addr{}, false
	}
	switch addr := p.Addr.(type) {
	case *net.TCPAddr:
		return netIPAddr(addr.IP)
	case *net.UDPAddr:
		return netIPAddr(addr.IP)
	case *net.IPAddr:
		return netIPAddr(addr.IP)
	default:
		return parseAddrString(addr.String())
	}
}

func netIPAddr(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func parseAddrString(value string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = value
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func addrAllowed(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
