package mbapp

import "time"

// PhaseTime32 represents a timestamp accurate to milliseconds
// but relative to another timestamp with a longer memory.
type PhaseTime32 uint32

func NewPhaseTime32(x time.Time, units time.Duration) PhaseTime32 {
	period := units * (1 << 31)
	x = x.UTC()
	evenEpoch := lastEvenEpoch(x, int64(period))
	oddEpoch := lastOddEpoch(x, int64(period))
	var y PhaseTime32
	epoch := evenEpoch
	if oddEpoch > evenEpoch {
		y |= 1 << 31
		epoch = oddEpoch
	}
	distNanos := (x.UnixNano() - epoch)
	distMillis := distNanos / 1e6
	y |= PhaseTime32(0x7FFFFFFF & distMillis)
	return y
}

func (pt PhaseTime32) UTC(now time.Time, units time.Duration) time.Time {
	period := units * (1 << 31)
	now = now.UTC()
	var epoch int64
	if (pt & 0x80000000) > 0 {
		epoch = lastOddEpoch(now, int64(period))
	} else {
		epoch = lastEvenEpoch(now, int64(period))
	}
	distMillis := int64(pt & 0x7FFFFFFF)
	distNanos := distMillis * 1e6
	return time.Unix(0, epoch+distNanos)
}

func period32(units time.Duration) int64 {
	return int64(units) * (1 << 31)
}

func lastEvenEpoch(x time.Time, period int64) int64 {
	ns := x.UnixNano()
	epoch := ns - (ns % period)
	return epoch
}

func lastOddEpoch(x time.Time, period int64) int64 {
	ns := x.UnixNano()
	epoch := ns - (ns % period) + period/2
	return epoch
}
