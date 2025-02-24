package witsvid

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Params are JWT-SVID parameters used when fetching a new WIT-SVID.
type Params struct {
	PublicKey string
	Subject   spiffeid.ID
}

// Source represents a source of WIT-SVIDs.
type Source interface {
	// FetchWITSVID fetches a WIT-SVID from the source with the given
	// parameters.
	FetchWITSVID(ctx context.Context, params Params) (*SVID, error)
}
