package monitor

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

// FlowEvent represents a traffic event derived from conntrack
type FlowEvent struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	RxBytes uint64 // Bytes received by Original direction (usually upload if Src is local)
	TxBytes uint64 // Bytes sent by Original direction (usually download if Src is local)
	// Actually conntrack has counters for Original and Reply.
	// OrigBytes, ReplyBytes.
	OriginBytes uint64
	ReplyBytes  uint64

	FlowID    uint32 // Conntrack Flow ID
	Display   string // For debug
	Timestamp time.Time
	Type      EventType
}

type EventType int

const (
	EventUpdate EventType = iota
	EventDestroy
)

type flowState struct {
	LastOriginBytes uint64
	LastReplyBytes  uint64
}

type ConntrackMonitor struct {
	nw     *NeighborWatcher
	output chan FlowEvent
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// 状态差分机制
	mu        sync.Mutex
	lastState map[uint32]*flowState // Key: FlowID
}

func NewConntrackMonitor(nw *NeighborWatcher) *ConntrackMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConntrackMonitor{
		nw:        nw,
		output:    make(chan FlowEvent, 1024),
		ctx:       ctx,
		cancel:    cancel,
		lastState: make(map[uint32]*flowState),
	}
}

func (m *ConntrackMonitor) Start(pollInterval time.Duration) error {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return fmt.Errorf("failed to dial conntrack: %w", err)
	}

	// Listen returns (errChan, error)
	// We need to supply evChan
	evCh := make(chan conntrack.Event, 2048)

	// Increase socket buffer size to avoid "no buffer space available" on high traffic
	if err := c.SetReadBuffer(2097152); err != nil { // 2MB
		c.Close()
		return fmt.Errorf("failed to set read buffer: %w", err)
	}

	// GroupsCT includes New, Update, Destroy, etc.
	errCh, err := c.Listen(evCh, 4, netfilter.GroupsCT)
	if err != nil {
		c.Close()
		return fmt.Errorf("failed to listen to conntrack: %w", err)
	}

	// Dial a second connection for polling (Dump)
	pc, err := conntrack.Dial(nil)
	if err != nil {
		c.Close()
		return fmt.Errorf("failed to dial polling conntrack: %w", err)
	}

	m.wg.Go(func() {
		defer c.Close()
		defer pc.Close()

		// Polling Ticker
		// Use configured interval
		if pollInterval <= 0 {
			pollInterval = 1 * time.Second // Default
		}
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.poll(pc)
			case err := <-errCh:
				// Handle error (maybe log it)
				log.Printf("Conntrack listen error: %v\n", err)
				// If fatal, we might need to break or reconnect?
				// For now just log.
			case ev, ok := <-evCh:
				if !ok {
					return
				}
				m.processEvent(ev)
			}
		}
	})

	return nil
}

func (m *ConntrackMonitor) poll(c *conntrack.Conn) {
	flows, err := c.Dump(nil)
	if err != nil {
		log.Printf("Conntrack dump error: %v\n", err)
		return
	}

	for _, flow := range flows {
		f := flow // Copy for pointer
		// Create a synthetic event
		ev := conntrack.Event{
			Type: conntrack.EventUpdate,
			Flow: &f,
		}
		m.processEvent(ev)
	}
}

func (m *ConntrackMonitor) Stop() {
	m.cancel()
	m.wg.Wait()
	close(m.output)
}

func (m *ConntrackMonitor) Events() <-chan FlowEvent {
	return m.output
}

func (m *ConntrackMonitor) processEvent(ev conntrack.Event) {
	// Extract counters
	fid := ev.Flow.ID
	curOrig := ev.Flow.CountersOrig.Bytes
	curReply := ev.Flow.CountersReply.Bytes

	eventType := EventUpdate
	if ev.Type == conntrack.EventDestroy {
		eventType = EventDestroy
	}

	// Status Differential Calculation
	m.mu.Lock()
	last, exists := m.lastState[fid]

	var deltaOrig, deltaReply uint64
	if !exists {
		// First time seeing this FlowID: Conservative strategy, Delta = 0
		// This avoids false spikes on program restart
		m.lastState[fid] = &flowState{
			LastOriginBytes: curOrig,
			LastReplyBytes:  curReply,
		}
		deltaOrig = 0
		deltaReply = 0
	} else {
		// Calculate Delta (both Listen and Poll events handled the same way)
		if curOrig >= last.LastOriginBytes {
			deltaOrig = curOrig - last.LastOriginBytes
		} else {
			// Counter decreased: likely FlowID reuse or conntrack anomaly
			// Set Delta=0 to avoid counting cumulative value as increment
			deltaOrig = 0
		}

		if curReply >= last.LastReplyBytes {
			deltaReply = curReply - last.LastReplyBytes
		} else {
			// Counter decreased: likely FlowID reuse or conntrack anomaly
			// Set Delta=0 to avoid counting cumulative value as increment
			deltaReply = 0
		}

		// Update state
		last.LastOriginBytes = curOrig
		last.LastReplyBytes = curReply
	}

	// For Destroy events, remove from state
	if eventType == EventDestroy {
		delete(m.lastState, fid)
	}
	m.mu.Unlock()

	// Only send event if there's actual data change
	if deltaOrig == 0 && deltaReply == 0 {
		return
	}

	// DEBUG: Log delta values to help diagnose issues
	eventTypeStr := "UPDATE"
	if eventType == EventDestroy {
		eventTypeStr = "DESTROY"
	}
	log.Printf("[DEBUG] FlowID=%d Type=%s Delta: Orig=%d Reply=%d (Cur: Orig=%d Reply=%d, Exists=%v, StateSize=%d)",
		fid, eventTypeStr, deltaOrig, deltaReply, curOrig, curReply, exists, len(m.lastState))

	// Prepare event with DELTA values (not cumulative)
	srcSlice := ev.Flow.TupleOrig.IP.SourceAddress.AsSlice()
	dstSlice := ev.Flow.TupleOrig.IP.DestinationAddress.AsSlice()

	e := FlowEvent{
		SrcIP:       net.IP(srcSlice[:]),
		DstIP:       net.IP(dstSlice[:]),
		SrcPort:     ev.Flow.TupleOrig.Proto.SourcePort,
		DstPort:     ev.Flow.TupleOrig.Proto.DestinationPort,
		Proto:       ev.Flow.TupleOrig.Proto.Protocol,
		OriginBytes: deltaOrig,  // DELTA, not cumulative
		ReplyBytes:  deltaReply, // DELTA, not cumulative
		FlowID:      fid,
		Timestamp:   time.Now(),
		Type:        eventType,
	}

	select {
	case m.output <- e:
	default:
		// Drop event if channel full to avoid blocking
	}
}
