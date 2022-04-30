package retry

import (
	"context"
	"math"
	"time"
)

// Retry calls fn until it returns nil.
// - To only retry on certain errors use WithPredicate to define a predicate.  True means retry.
// - To set the time between retries use WithPulseTrain and specify a pulse train.
// - To cancel, use the context, otherwise Retry runs until success.
func Retry(ctx context.Context, fn func() error, opts ...RetryOption) error {
	rc := retryConfig{
		predicate: func(error) bool { return true },
		waiter:    &backoffWaiter{bf: defaultBackoff},
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(&rc)
	}
	defer rc.waiter.Close()

	startTime := rc.now()
	for i := 0; ; i++ {
		if err := fn(); err == nil || !rc.predicate(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rc.waiter.Wait(i, startTime):
		}
	}
}

type retryConfig struct {
	predicate func(error) bool
	waiter    Waiter
	now       func() time.Time
}

// RetryOption is an option used to configure Retry
type RetryOption func(rc *retryConfig)

// WithPredicate sets p as a predicate for the retry
// if p returns false then Retry exits with the error.
// if p returns true then Retry continues normally.
func WithPredicate(p func(error) bool) RetryOption {
	return func(rc *retryConfig) {
		rc.predicate = p
	}
}

// WithBackoff sets a backoff function for Retry to use
func WithBackoff(bf BackoffFunc) RetryOption {
	return withWaiter(&backoffWaiter{bf: bf})
}

func withWaiter(w Waiter) RetryOption {
	return func(rc *retryConfig) {
		rc.waiter = w
	}
}

// BackoffFunc is called to determine the duration to wait based on a number
// retries and elapsed total time since the start of the first attempt.
type BackoffFunc = func(numRetries int, elapsed time.Duration) time.Duration

// NewConstantBackoff returns a backoff function
func NewConstantBackoff(d time.Duration) BackoffFunc {
	return func(int, time.Duration) time.Duration {
		return d
	}
}

// NewLinearBackoff returns a linear backoff functions
// which will increase by m every retry, and a starting duration of b
//
// `d = m * numRetries + b`
func NewLinearBackoff(m, b time.Duration) BackoffFunc {
	return func(numRetries int, elapsed time.Duration) time.Duration {
		return time.Duration(numRetries)*m + b
	}
}

// NewExponentialBackoff waits initial the first retry and doubles
func NewExponentialBackoff(initial time.Duration, doubleEvery int) BackoffFunc {
	return func(numRetries int, elapsed time.Duration) time.Duration {
		x := float64(numRetries) / float64(doubleEvery)
		return time.Duration(float64(initial) * math.Exp2(x))
	}
}

// MaxBackoff modifies fn to not produce values greater than max
func MaxBackoff(fn BackoffFunc, max time.Duration) BackoffFunc {
	return func(numRetries int, elapsed time.Duration) time.Duration {
		d := fn(numRetries, elapsed)
		if d > max {
			d = max
		}
		return d
	}
}

// MinBackoff modifies fn to not produce values less than min
func MinBackoff(fn BackoffFunc, min time.Duration) BackoffFunc {
	return func(numRetries int, elapsed time.Duration) time.Duration {
		d := fn(numRetries, elapsed)
		if d < min {
			d = min
		}
		return d
	}
}

var defaultBackoff = MaxBackoff(NewExponentialBackoff(100*time.Millisecond, 2), 30*time.Second)

// Waiter waits
type Waiter interface {
	// Wait returns a channel which will produce a single value, and then nothing.
	// Wait can return channels which block for different amounts of time.
	Wait(numRetries int, startTime time.Time) <-chan time.Time

	// Close releases any resources the waiter has
	Close() error
}

type backoffWaiter struct {
	bf BackoffFunc
}

func (w *backoffWaiter) Wait(retries int, startTime time.Time) <-chan time.Time {
	now := time.Now()
	dur := w.bf(retries, now.Sub(startTime))
	return time.After(dur)
}

func (w *backoffWaiter) Close() error { return nil }

// RetryRet1 is a convenience function for returning a value from a retry loop.
func RetryRet1[T any](ctx context.Context, fn func() (T, error), opts ...RetryOption) (ret T, _ error) {
	err := Retry(ctx, func() error {
		var err error
		ret, err = fn()
		return err
	}, opts...)
	return ret, err
}
