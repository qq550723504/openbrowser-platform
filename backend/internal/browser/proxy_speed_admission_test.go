package browser

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type twoProxyAdmissionDAO struct{ *blockingProxySpeedDAO }

func (d *twoProxyAdmissionDAO) List() ([]Proxy, error) {
	return []Proxy{{ProxyId: "one", ProxyConfig: "synthetic://one"}, {ProxyId: "two", ProxyConfig: "synthetic://two"}}, nil
}

func TestProxySpeedBatchCannotDispatchOrPublishUnderReplacement(t *testing.T) {
	dao := &twoProxyAdmissionDAO{&blockingProxySpeedDAO{finished: make(chan struct{})}}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var generation atomic.Uint64
	generation.Store(7)
	scheduler := NewProxySpeedScheduler(dao, func(string) (bool, int64, string) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return true, 1, ""
	}, time.Hour, 1)
	scheduler.CaptureAdmission = func() func() error {
		g := generation.Load()
		return func() error {
			if generation.Load() != g {
				return errors.New("authentication_required")
			}
			return nil
		}
	}
	go func() { scheduler.runAll(); close(done) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("mock test did not enter")
	}
	generation.Store(9)
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not settle")
	}
	if calls.Load() != 1 {
		t.Fatal("queued proxy borrowed replacement session")
	}
	select {
	case <-dao.finished:
		t.Fatal("old batch persisted a result")
	default:
	}
}
