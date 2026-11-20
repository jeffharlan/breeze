package heartbeat

import (
	"time"

	"github.com/breeze-rmm/agent/internal/opsign"
)

// observeOwnClock raises the operator trust store's high-water time from this
// device's clock (only while a bundle is pinned), so winding the clock back
// later cannot revive an approval that expired meanwhile. It runs on the local
// timer, before anything that needs the server, so a silent server cannot stop it.
func (h *Heartbeat) observeOwnClock() {
	if h.opsignStore != nil {
		h.opsignStore.ObserveClock(time.Now())
	}
}

// applyOperatorTrustBundle offers a bundle the server relayed to the pin store.
// One that does not apply is logged and ignored: the server may relay anything,
// and a bad offer must not stop the rest of the response being processed.
func (h *Heartbeat) applyOperatorTrustBundle(sb *opsign.SignedBundle) {
	if sb == nil {
		return
	}
	id, err := opsign.LocalIdentity(h.config.DeviceID, h.config.OrgID)
	if err == nil {
		_, err = opsign.ApplyBundle(h.opsignStore, *sb, id, time.Now())
	}
	if err != nil {
		logOncePerReason(&h.opsignApplyLogged, "warn", "operator trust bundle not applied", err.Error())
	}
}
