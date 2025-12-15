package monitor

import (
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

// NeighborWatcher watches for IP to MAC mappings
// For simplicity, we just parse /proc/net/arp periodically
type NeighborWatcher struct {
	ipToMac map[string]string
	mu      sync.RWMutex
	stop    chan struct{}
}

func NewNeighborWatcher() *NeighborWatcher {
	return &NeighborWatcher{
		ipToMac: make(map[string]string),
		stop:    make(chan struct{}),
	}
}

func (nw *NeighborWatcher) Start() {
	go nw.run()
}

func (nw *NeighborWatcher) Stop() {
	close(nw.stop)
}

func (nw *NeighborWatcher) run() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	nw.Refresh() // Initial load

	for {
		select {
		case <-ticker.C:
			nw.Refresh()
		case <-nw.stop:
			return
		}
	}
}

func (nw *NeighborWatcher) Refresh() {
	newMap := make(map[string]string)

	// IPv4
	neighs4, err := netlink.NeighList(0, netlink.FAMILY_V4)
	if err == nil {
		nw.processNeighs(neighs4, newMap)
	}

	// IPv6
	neighs6, err := netlink.NeighList(0, netlink.FAMILY_V6)
	if err == nil {
		nw.processNeighs(neighs6, newMap)
	}

	nw.mu.Lock()
	nw.ipToMac = newMap
	nw.mu.Unlock()
}

func (nw *NeighborWatcher) processNeighs(neighs []netlink.Neigh, m map[string]string) {
	for _, n := range neighs {
		// Filter out invalid states
		// NUD_INCOMPLETE = 0x01
		// NUD_REACHABLE  = 0x02
		// NUD_STALE      = 0x04
		// NUD_DELAY      = 0x08
		// NUD_PROBE      = 0x10
		// NUD_FAILED     = 0x20
		// NUD_NOARP      = 0x40
		// NUD_PERMANENT  = 0x80

		// We generally want cleaning valid entries.
		// Reachable, Stale, Permanent, Delay, Probe are good candidates.
		// Incomplete and Failed should be ignored.
		if n.State&(netlink.NUD_INCOMPLETE|netlink.NUD_FAILED) != 0 {
			continue
		}

		if len(n.HardwareAddr) == 6 {
			mac := n.HardwareAddr.String()
			if mac != "00:00:00:00:00:00" {
				m[n.IP.String()] = mac
			}
		}
	}
}

func (nw *NeighborWatcher) GetMAC(ip string) string {
	nw.mu.RLock()
	defer nw.mu.RUnlock()
	return nw.ipToMac[ip]
}
