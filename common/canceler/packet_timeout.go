package canceler

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type TimeoutPacketConn struct {
	N.PacketConn
	timeout time.Duration
	cancel  context.CancelCauseFunc
	// activeUnixNano 最近一次成功读写时间；0 表示尚未有成功 I/O
	activeUnixNano atomic.Int64
	// nextDeadlineRefresh 之前无需再 SetReadDeadline（减少每包 setsockopt 系统调用）
	nextDeadlineRefresh atomic.Int64
}

func NewTimeoutPacketConn(ctx context.Context, conn N.PacketConn, timeout time.Duration) (context.Context, PacketConn) {
	ctx, cancel := context.WithCancelCause(ctx)
	return ctx, &TimeoutPacketConn{
		PacketConn: conn,
		timeout:    timeout,
		cancel:     cancel,
	}
}

func (c *TimeoutPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	for {
		now := time.Now()
		nowNano := now.UnixNano()
		if nowNano >= c.nextDeadlineRefresh.Load() {
			if err = c.PacketConn.SetReadDeadline(now.Add(c.timeout)); err != nil {
				return
			}
			// 超时窗口内最多刷新少数几次 setsockopt，而不是每个 UDP 包一次
			refreshIn := c.timeout / 4
			if refreshIn < time.Second {
				refreshIn = time.Second
			}
			if refreshIn > 30*time.Second {
				refreshIn = 30 * time.Second
			}
			c.nextDeadlineRefresh.Store(now.Add(refreshIn).UnixNano())
		}

		destination, err = c.PacketConn.ReadPacket(buffer)
		if err == nil {
			c.activeUnixNano.Store(time.Now().UnixNano())
			return
		}
		if !E.IsTimeout(err) {
			return
		}
		active := c.activeUnixNano.Load()
		if active == 0 || time.Since(time.Unix(0, active)) > c.timeout {
			c.cancel(err)
			return
		}
		// 有近期活动：强制下次循环刷新 deadline
		c.nextDeadlineRefresh.Store(0)
	}
}

func (c *TimeoutPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := c.PacketConn.WritePacket(buffer, destination)
	if err == nil {
		c.activeUnixNano.Store(time.Now().UnixNano())
	}
	return err
}

func (c *TimeoutPacketConn) Timeout() time.Duration {
	return c.timeout
}

func (c *TimeoutPacketConn) SetTimeout(timeout time.Duration) bool {
	c.timeout = timeout
	c.nextDeadlineRefresh.Store(0)
	return c.PacketConn.SetReadDeadline(time.Now()) == nil
}

func (c *TimeoutPacketConn) Close() error {
	c.cancel(net.ErrClosed)
	return c.PacketConn.Close()
}

func (c *TimeoutPacketConn) Upstream() any {
	return c.PacketConn
}
