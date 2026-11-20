package heartbeat

import (
	"time"

	"github.com/breeze-rmm/agent/internal/opsign"
)

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
