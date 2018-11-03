package kcp

import (
	"github.com/pkg/errors"
	"sync/atomic"
)

func (s *UDPSession) defaultReadLoop() {
	buf := make([]byte, mtuLimit)
	var src string
	for {
		if n, addr, err := s.conn.ReadFrom(buf); err == nil {
			// make sure the packet is from the same source
			if src == "" { // set source address
				src = addr.String()
			} else if addr.String() != src {
				atomic.AddUint64(&DefaultSnmp.InErrs, 1)
				continue
			}

			if n >= s.headerSize+IKCP_OVERHEAD {
				s.packetInput(buf[:n])
			} else {
				atomic.AddUint64(&DefaultSnmp.InErrs, 1)
			}
		} else {
			s.notifyReadError(errors.WithStack(err))
			return
		}
	}
}
