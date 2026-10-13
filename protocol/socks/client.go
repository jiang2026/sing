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
		// 关键：**不能用 tcpConn.RemoteAddr() 作为 relay 的地址来源**。
		//
		// 直连时它恰好等于服务端地址，所以看不出问题；但**链式(detour)时，本次 TCP 是
		// 经上游第一跳接出去的，RemoteAddr 是【第一跳】的地址**。
		// 而第一跳通常是**公网地址** —— 所以「只在 tcpRemote 非公网时才回退」这类判断
		// 根本拦不住它，relay 会被算成「第一跳 IP + 出口端口」，UDP 报文发到错误主机。
		//
		// 实测（App 内探针，s5→s5 链式）：
		//   出口跳: server=180.163.77.111:16740 tcpRemote=180.163.79.47:15970 bind=0.0.0.0:44092
		//          → 旧逻辑 relay=180.163.79.47:44092（第一跳 IP，错误，UDP 永不达）
		//   单节点: server=180.163.79.47:15970 tcpRemote=180.163.79.47:15970
		//          → relay=180.163.79.47:38255（正确，只因两者相同）
		//
		// 因此顺序必须反过来：**优先用配置的服务器地址**；它是域名时保留 Fqdn，
		// 交给 dialer（含 detour）解析 —— 这样经上游转发时才指向真正的出口节点。
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
			// 必须优先用【配置的服务器地址】而不是 tcpRemote：
			// 链式(detour)时 tcpRemote 是**上游中继（第一跳）**，而且它往往是公网地址，
			// 所以「tcpRemote 是公网就采用」的判断根本拦不住它 ——
			// 实测链式 UDP 时 relay 被算成「第一跳 IP + 出口端口」，
			// UDP 报文发到错误的主机上，链式 UDP 永久超时。
			//   链式出口跳: server=180.163.77.111:16740 tcpRemote=180.163.79.47:15970
			//               bind=0.0.0.0:44092 → 错 relay=180.163.79.47:44092
			//   单节点(对照): server=180.163.79.47:15970 tcpRemote=180.163.79.47:15970
			//               → relay=180.163.79.47:38255（正确，因为两者相同）
			// 用 serverAddr + bind 端口，经 dialer（含 detour）就能正确到达出口节点的 UDP relay。
			switch {
			case c.serverAddr.Addr.IsValid():
				relay = M.SocksaddrFrom(c.serverAddr.Addr, port)
			case c.serverAddr.Fqdn != "":
				relay = M.Socksaddr{Fqdn: c.serverAddr.Fqdn, Port: port}
			case tcpRemote.Addr.IsValid():
				relay = M.SocksaddrFrom(tcpRemote.Addr, port)
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
