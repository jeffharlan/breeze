package agentapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/breeze-rmm/agent/internal/config"
	"github.com/breeze-rmm/agent/internal/opsign"
)

// pinOperatorTrustFile offers the trust bundle an installer left in path to the
// pin store (#12257). No file is the normal case and is not an error. An agent
// that is not enrolled yet gets opsign.ErrPinIdentityMissing and pins later,
// from a heartbeat.
func pinOperatorTrustFile(store *opsign.Store, path string, cfg *config.Config) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var sb opsign.SignedBundle
	if err := json.Unmarshal(data, &sb); err != nil {
		return fmt.Errorf("%s is not a signed trust bundle: %w", path, err)
	}
	id, err := opsign.LocalIdentity(cfg.DeviceID, cfg.OrgID)
	if err != nil {
		return err
	}
	_, err = opsign.ApplyBundle(store, sb, id, time.Now())
	return err
}
