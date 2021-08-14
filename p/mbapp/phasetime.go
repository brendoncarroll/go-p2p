package mbapp

import "time"

// PhaseTime32 represents a timestamp but relative to another timestamp with a longer memory.
// If a bound can be placed on the difference in clocks between two processes it can provide
// higher accuracy with fewer bits.
type PhaseTime32 uint32

func NewPhaseTime32(x time.Time, units time.Duration) PhaseTime32 {
	period := period32(units)
	x = x.UTC()
	ns := x.UnixNano()
	epochs := [4]int64{
		ns - (ns % period) - period,
		ns - (ns % period) - period/2,
		ns - (ns % period),
		ns - (ns % period) + period/2,
	}
	var index int
	for i := 0; i < 4; i++ {
		dist := ns - epochs[i]
		if dist >= period/4 && dist < period*3/4 {
			index = i
			break
		}
	}
	epoch := epochs[index]
	var y PhaseTime32
	if index%2 == 1 {
		// odd
		y |= 1 << 31
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
	epochForward := ns - (ns % period) + period/2
	epochBackward := ns - (ns % period) - period/2
	if epochForward > ns {
		return epochBackward
	}
	return epochForward
}

func nextOddEpoch(x time.Time, period int64) int64 {
	ns := x.UnixNano()
	epoch := lastOddEpoch(x, period)
	if epoch < ns {
		epoch += period
	}
	return epoch
}
