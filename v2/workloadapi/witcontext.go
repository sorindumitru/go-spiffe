package workloadapi

import (
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/witsvid"
)

// WITContext conveys X.509 materials from the Workload API.
type WITContext struct {
	// SVIDs is a list of workload WIT-SVIDs.
	SVIDs []*witsvid.SVID

	// Bundles is a set of X.509 bundles.
	Bundles *jwtbundle.Set
}

// Default returns the default WIT-SVID (the first in the list).
//
// See the SPIFFE Workload API standard Section 5.3.
// (https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md#53-default-identity)
func (x *WITContext) DefaultSVID() *witsvid.SVID {
	return x.SVIDs[0]
}
