package canceler

import (
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type timerPackerReadWaiter struct {
	*TimerPacketConn
	readWaiter N.PacketReadWaiter
}

func (c *TimerPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(c.PacketConn)
	if !isReadWaiter {
		return nil, false
	}
	return &timerPackerReadWaiter{c, readWaiter}, true
}

func (w *timerPackerReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return w.readWaiter.InitializeReadWaiter(options)
}

func (w *timerPackerReadWaiter) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	buffer, destination, err = w.readWaiter.WaitReadPacket()
	if err == nil {
		w.instance.Update()
	}
	return
}

type timeoutPacketReadWaiter struct {
	*TimeoutPacketConn
	readWaiter N.PacketReadWaiter
}

func (c *TimeoutPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(c.PacketConn)
	if !isReadWaiter {
		return nil, false
	}
	return &timeoutPacketReadWaiter{c, readWaiter}, true
}

func (w *timeoutPacketReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return w.readWaiter.InitializeReadWaiter(options)
}

func (w *timeoutPacketReadWaiter) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	for {
		now := time.Now()
		nowNano := now.UnixNano()
		if nowNano >= w.nextDeadlineRefresh.Load() {
			if err = w.PacketConn.SetReadDeadline(now.Add(w.timeout)); err != nil {
				return
			}
			refreshIn := w.timeout / 4
			if refreshIn < time.Second {
				refreshIn = time.Second
			}
			if refreshIn > 30*time.Second {
				refreshIn = 30 * time.Second
			}
			w.nextDeadlineRefresh.Store(now.Add(refreshIn).UnixNano())
		}

		buffer, destination, err = w.readWaiter.WaitReadPacket()
		if err == nil {
			w.activeUnixNano.Store(time.Now().UnixNano())
			return
		}
		if !E.IsTimeout(err) {
			return
		}
		active := w.activeUnixNano.Load()
		if active == 0 || time.Since(time.Unix(0, active)) > w.timeout {
			w.cancel(err)
			return
		}
		w.nextDeadlineRefresh.Store(0)
	}
}
