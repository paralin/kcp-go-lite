package kcp

import (
	"sync/atomic"

	"github.com/pkg/errors"
)

func (s *UDPSession) tx(txqueue [][]byte) {
	nbytes := 0
	npkts := 0
	for k := range txqueue {
		if n, err := s.writer(txqueue[k]); err == nil {
			nbytes += n
			npkts++
			xmitBuf.Put(txqueue[k])
		} else {
			s.notifyWriteError(errors.WithStack(err))
			break
		}
	}
	atomic.AddUint64(&DefaultSnmp.OutPkts, uint64(npkts))
	atomic.AddUint64(&DefaultSnmp.OutBytes, uint64(nbytes))
}
