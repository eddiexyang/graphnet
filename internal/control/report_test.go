package control

import (
	"testing"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

func TestValidateReportAllowsActiveUnhealthyLink(t *testing.T) {
	netID := testutil.ID(1)
	edgeID := testutil.ID(2)
	snapshot := model.Snapshot{
		Revision: 1,
		Networks: []model.NetworkConfig{{
			ID: netID,
			Peers: []model.Peer{{
				Edge: model.Edge{
					ID:         edgeID,
					Transports: []model.Transport{model.TCP},
				},
			}},
		}},
	}
	report := model.AgentReport{
		AppliedRevision: 1,
		Links: []model.LinkStatus{{
			NetworkID: netID,
			EdgeID:    edgeID,
			LinkID:    "link-1",
			Transport: model.TCP,
			Healthy:   false,
			Unhealthy: true,
			Active:    true,
		}},
	}
	if err := validateReport(snapshot, report); err != nil {
		t.Fatalf("validateReport rejected active unhealthy link: %v", err)
	}

	report.Links[0].Unhealthy = false
	if err := validateReport(snapshot, report); err == nil {
		t.Fatal("validateReport accepted active link that is neither healthy nor unhealthy")
	}
}
