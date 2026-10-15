package job

import (
	"context"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/websocket"
)

// InboundSubscriptionJob periodically mirrors a remote share-link subscription
// into local inbounds, replacing what the previous run created.
type InboundSubscriptionJob struct {
	inboundSubService *service.InboundSubscriptionService
}

func NewInboundSubscriptionJob() *InboundSubscriptionJob {
	return &InboundSubscriptionJob{inboundSubService: service.NewInboundSubscriptionService()}
}

func (j *InboundSubscriptionJob) Run() {
	if j.inboundSubService == nil {
		j.inboundSubService = service.NewInboundSubscriptionService()
	}
	if !j.inboundSubService.Enabled() {
		return
	}
	result, err := j.inboundSubService.Refresh(context.Background())
	if err != nil {
		// A failed refresh leaves the previous inbounds in place; the operator
		// sees the reason in the panel log rather than losing their setup.
		logger.Warning("inbound subscription sync failed:", err)
		return
	}
	if result.Added > 0 || result.Removed > 0 {
		websocket.BroadcastInvalidate(websocket.MessageTypeInbounds)
	}
}
