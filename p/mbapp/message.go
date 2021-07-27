package mbapp

import (
	"encoding/binary"
	"time"

	"github.com/pkg/errors"
)

const (
	HeaderSize = 6 * 4

	isAskBit   = 31
	isReplyBit = 30
)

// Header
// 	 |<-        32 bits             ->|
// 0 | mode bits       24| resp code 8|
// 1 | origin time                  32|
// 2 | counter                      32|
// 3 | part size 					32|
// 4 | part index   16| part count  16|
// 5 | timeout or dest time
type Header []byte

func ParseMessage(data []byte) (Header, []byte, error) {
	if len(data) < HeaderSize {
		return nil, nil, errors.Errorf("too short to be header")
	}
	return data[:HeaderSize], data[HeaderSize:], nil
}

// Word 0
func (h Header) IsAsk() bool {
	return h.getUint32Bit(0, isAskBit)
}

func (h Header) SetIsAsk(yes bool) {
	h.setUint32Bit(0, isAskBit, yes)
}

func (h Header) IsReply() bool {
	return getBit(h.getUint32(0), isReplyBit)
}

func (h Header) SetIsReply(yes bool) {
	h.setUint32Bit(0, isReplyBit, yes)
}

func (h Header) GetErrorCode() uint8 {
	return uint8(h.getUint32(0) & 0xFF)
}

// Word 1
func (h Header) GetOriginTime() PhaseTime32 {
	return PhaseTime32(h.getUint32(1))
}

func (h Header) SetOriginTime(pt PhaseTime32) {
	h.setUint32(1, uint32(pt))
}

// Word 2
func (h Header) GetCounter() uint32 {
	return h.getUint32(2)
}

func (h Header) SetCounter(x uint32) {
	h.setUint32(2, x)
}

// Word 3
func (h Header) GetTotalSize() uint32 {
	return h.getUint32(3)
}

func (h Header) SetTotalSize(size uint32) {
	h.setUint32(3, size)
}

// Word 4
func (h Header) GetPartIndex() uint16 {
	return uint16(h.getUint32(4) >> 16)
}

func (h Header) SetPartIndex(v uint16) {
	h.updateUint32(4, func(x uint32) uint32 {
		return x&0x0000_FFFF | uint32(v)<<16
	})
}

func (h Header) GetPartCount() uint16 {
	return uint16(h.getUint32(4) & 0x0000_FFFF)
}

func (h Header) SetPartCount(v uint16) {
	h.updateUint32(4, func(x uint32) uint32 {
		return (x & 0xFFFF_0000) | uint32(v)
	})
}

// Extensions
func (h Header) SetTimeout(t time.Duration) {
	timeout := uint32(t.Milliseconds())
	h.setUint32(5, timeout)
}

func (h Header) GetTimeout() time.Duration {
	return time.Duration(h.getUint32(5)) * time.Millisecond
}

func (h Header) GroupID() GroupID {
	return GroupID{
		Counter:    h.GetCounter(),
		OriginTime: h.GetOriginTime(),
	}
}

func (h Header) getUint32(n int) uint32 {
	return binary.BigEndian.Uint32(h[n*4 : (n+1)*4])
}

func (h Header) setUint32(n int, v uint32) {
	binary.BigEndian.PutUint32(h[n*4:(n+1)*4], v)
}

func (h Header) updateUint32(n int, fn func(x uint32) uint32) {
	h.setUint32(n, fn(h.getUint32(n)))
}

func (h Header) getUint32Bit(n int, b uint) bool {
	x := h.getUint32(n)
	return getBit(x, b)
}

func (h Header) setUint32Bit(n int, b uint, v bool) {
	h.updateUint32(n, func(x uint32) uint32 {
		if v {
			return setBit(x, b)
		} else {
			return unsetBit(x, b)
		}
	})
}

type GroupID struct {
	OriginTime PhaseTime32
	Counter    uint32
}

func getBit(x uint32, i uint) bool {
	return x&(1<<i) > 0
}

func setBit(x uint32, i uint) uint32 {
	return x | (1 << i)
}

func unsetBit(x uint32, i uint) uint32 {
	return x & (^(1 << i))
}
