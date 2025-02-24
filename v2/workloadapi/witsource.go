package workloadapi

import (
	"context"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/witsvid"
	"github.com/zeebo/errs"
)

var witsourceErr = errs.Class("witsource")

// WITSource is a source of WIT-SVID and WIT bundles maintained via the
// Workload API.
type WITSource struct {
	watcher *watcher
	picker  func([]*witsvid.SVID) *witsvid.SVID

	mtx     sync.RWMutex
	svid    *witsvid.SVID
	bundles *jwtbundle.Set

	closeMtx sync.RWMutex
	closed   bool
}

// NewWITSource creates a new WITSource. It blocks until the initial update
// has been received from the Workload API. The source should be closed when
// no longer in use to free underlying resources.
func NewWITSource(ctx context.Context, options ...WITSourceOption) (_ *WITSource, err error) {
	config := &witSourceConfig{}
	for _, option := range options {
		option.configureWITSource(config)
	}

	s := &WITSource{
		picker: config.picker,
	}

	s.watcher, err = newWatcher(ctx, config.watcher, nil, nil, s.setWITContext)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return an error after Close has been called.
// The underlying Workload API client will also be closed if it is owned by
// the WITSource (i.e. not provided via the WithClient option).
func (s *WITSource) Close() (err error) {
	s.closeMtx.Lock()
	s.closed = true
	s.closeMtx.Unlock()

	return s.watcher.Close()
}

// GetWITSVID returns an WIT-SVID from the source. It implements the
// witsvid.Source interface.
func (s *WITSource) GetWITSVID() (*witsvid.SVID, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	s.mtx.RLock()
	svid := s.svid
	s.mtx.RUnlock()

	if svid == nil {
		// This is a defensive check and should be unreachable since the source
		// waits for the initial Workload API update before returning from
		// New().
		return nil, witsourceErr.New("missing WIT-SVID")
	}
	return svid, nil
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
func (s *WITSource) WaitUntilUpdated(ctx context.Context) error {
	return s.watcher.WaitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
func (s *WITSource) Updated() <-chan struct{} {
	return s.watcher.Updated()
}

func (s *WITSource) setWITContext(witContext *WITContext) {
	var svid *witsvid.SVID
	if s.picker == nil {
		svid = witContext.DefaultSVID()
	} else {
		svid = s.picker(witContext.SVIDs)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.svid = svid
	s.bundles = witContext.Bundles
}

func (s *WITSource) checkClosed() error {
	s.closeMtx.RLock()
	defer s.closeMtx.RUnlock()
	if s.closed {
		return witsourceErr.New("source is closed")
	}
	return nil
}
