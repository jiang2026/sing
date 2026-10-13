package socks

import (
	"context"
	"net"
	"net/url"
	"os"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

type Version uint8

const (
	Version4 Version = iota
	Version4A
	Version5
)

func (v Version) String() string {
	switch v {
	case Version4:
		return "4"
	case Version4A:
		return "4a"
	case Version5:
		return "5"
	default:
		return "unknown"
	}
}

func ParseVersion(version string) (Version, error) {
	switch version {
	case "4":
		return Version4, nil
	case "4a":
		return Version4A, nil
	case "5":
		return Version5, nil
	}
	return 0, E.New("unknown socks version: ", version)
}

var _ N.Dialer = (*Client)(nil)

type Client struct {
	version    Version
	dialer     N.Dialer
	serverAddr M.Socksaddr
	username   string
	password   string
}

func NewClient(dialer N.Dialer, serverAddr M.Socksaddr, version Version, username string, password string) *Client {
	return &Client{
		version:    version,
		dialer:     dialer,
		serverAddr: serverAddr,
		username:   username,
		password:   password,
	}
}

func NewClientFromURL(dialer N.Dialer, rawURL string) (*Client, error) {
	var client Client
	if !strings.Contains(rawURL, "://") {
		rawURL = "socks://" + rawURL
	}
	proxyURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	client.dialer = dialer
	client.serverAddr = M.ParseSocksaddr(proxyURL.Host)
	switch proxyURL.Scheme {
	case "socks4":
		client.version = Version4
	case "socks4a":
		client.version = Version4A
	case "socks", "socks5", "":
		client.version = Version5
	default:
		return nil, E.New("socks: unknown scheme: ", proxyURL.Scheme)
	}
	if proxyURL.User != nil {
		if client.version == Version5 {
			client.username = proxyURL.User.Username()
			client.password, _ = proxyURL.User.Password()
		} else {
			client.username = proxyURL.User.String()
		}
	}
	return &client, nil
}

func (c *Client) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	network = N.NetworkName(network)
	var command byte
	switch network {
	case N.NetworkTCP:
		command = socks4.CommandConnect
	case N.NetworkUDP:
		if c.version != Version5 {
			return nil, E.New("socks4: udp unsupported")
		}
		command = socks5.CommandUDPAssociate
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	tcpConn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	if err != nil {
		return nil, err
	}
	if c.version == Version4 && address.IsDomain() {
		tcpAddr, err := net.ResolveTCPAddr(network, address.String())
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		address = M.SocksaddrFromNet(tcpAddr)
	}
	switch c.version {
	case Version4, Version4A:
		_, err = ClientHandshake4(tcpConn, command, address, c.username)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tcpConn, nil
	case Version5:
		response, err := ClientHandshake5(tcpConn, command, address, c.username, c.password)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		if command == socks5.CommandConnect {
			return tcpConn, nil
		}
		// 修复 SOCKS5 UDP ASSOCIATE：Bind 若为客户端不可达地址，改用可达的服务端地址 + Bind 端口。
		// 覆盖：未指定 / 回环 / RFC1918 / IPv6 ULA / 链路本地 / 组播 / CGNAT 100.64.0.0/10
		//
		// 关键：**不能无条件用 tcpConn.RemoteAddr()**。
		// 直连时 TCP 已握手，RemoteAddr 就是服务端真实公网 IP；
		// 但**链式(detour)时，本次 TCP 是经上游中继接出去的，RemoteAddr 是本地中继端点
		// （loopback / 私有），拿它当 relay 会得到一个不可达地址** ——
		// 实测：链式 UDP 时 relay 被算成 127.0.0.1:<随机端口>，UDP 报文发到第一跳的
		// loopback 上，永远超时；而单跳 UDP 正常。这正是「链式 UDP 不通」的根因。
		//
		// 因此：RemoteAddr 只有在**确实是公网地址**时才可用，否则回退到配置的服务器地址。
		// 服务器是域名时保留 Fqdn，交给 dialer（经 detour）解析。
		relay := response.Bind
		if !relay.Addr.IsValid() || !N.IsPublicAddr(relay.Addr) {
			tcpRemote := M.SocksaddrFromNet(tcpConn.RemoteAddr()).Unwrap()
			port := relay.Port
			if port == 0 {
				port = tcpRemote.Port
			}
			if port == 0 {
				port = c.serverAddr.Port
			}
			switch {
			case tcpRemote.Addr.IsValid() && N.IsPublicAddr(tcpRemote.Addr):
				relay = M.SocksaddrFrom(tcpRemote.Addr, port)
			case c.serverAddr.Addr.IsValid():
				relay = M.SocksaddrFrom(c.serverAddr.Addr, port)
			case c.serverAddr.Fqdn != "":
				relay = M.Socksaddr{Fqdn: c.serverAddr.Fqdn, Port: port}
			default:
				tcpConn.Close()
				return nil, E.New("socks5: udp associate: cannot resolve relay address from ", tcpConn.RemoteAddr())
			}
		}
		udpConn, err := c.dialer.DialContext(ctx, N.NetworkUDP, relay)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		return NewAssociatePacketConn(udpConn, address, tcpConn), nil
	}
	_ = tcpConn.Close()
	return nil, os.ErrInvalid
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := c.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return conn.(*AssociatePacketConn), nil
}

func (c *Client) BindContext(ctx context.Context, address M.Socksaddr) (net.Conn, error) {
	tcpConn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	if err != nil {
		return nil, err
	}
	switch c.version {
	case Version4, Version4A:
		_, err = ClientHandshake4(tcpConn, socks4.CommandBind, address, c.username)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tcpConn, nil
	case Version5:
		_, err = ClientHandshake5(tcpConn, socks5.CommandBind, address, c.username, c.password)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tcpConn, nil
	}
	_ = tcpConn.Close()
	return nil, os.ErrInvalid
}
