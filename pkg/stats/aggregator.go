package stats

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/kisy/catchmole/model"
	"github.com/kisy/catchmole/pkg/monitor"
	"github.com/vishvananda/netlink"
)

type Aggregator struct {
	mon *monitor.ConntrackMonitor
	nw  *monitor.NeighborWatcher

	mu      sync.RWMutex
	clients map[string]*model.ClientStats
	flows   map[string]*FlowTracker // Key: FlowHash

	globalTotalDownload uint64
	globalTotalUpload   uint64

	startTime time.Time

	staticNames map[string]string

	monitorLAN bool

	// Interface Filtering
	interfaceName  string
	interfaceIndex int
	ipIfCache      map[string]int // IP string -> Interface Index
	lanSubnets     []net.IPNet    // Subnets of the monitored interface
}

type FlowTracker struct {
	Key       string
	FlowID    uint32
	FirstSeen time.Time
	LastSeen  time.Time

	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8

	ClientMAC string // Associated MAC (if any)
	Direction string // "upload" (client is src) or "download" (client is dst)

	OriginBytesLast uint64
	ReplyBytesLast  uint64

	TotalOriginBytes uint64 // Cumulative
	TotalReplyBytes  uint64 // Cumulative

	SessionStartOriginBytes uint64
	SessionStartReplyBytes  uint64
}

func NewAggregator(mon *monitor.ConntrackMonitor, nw *monitor.NeighborWatcher) *Aggregator {
	return &Aggregator{
		mon:         mon,
		nw:          nw,
		clients:     make(map[string]*model.ClientStats),
		flows:       make(map[string]*FlowTracker),
		startTime:   time.Now(),
		staticNames: make(map[string]string),
		ipIfCache:   make(map[string]int),
	}
}

// processLoop runs in background
func (a *Aggregator) processLoop() {
	for ev := range a.mon.Events() {
		a.handleEvent(ev)
	}
}

func (a *Aggregator) handleEvent(ev monitor.FlowEvent) {
	key := fmt.Sprintf("%s:%d->%s:%d:%d", ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort, ev.Proto)

	a.mu.Lock()
	defer a.mu.Unlock()

	// Interface Filter
	if a.interfaceIndex != 0 {
		if !a.checkFlowInterface(ev.SrcIP, ev.DstIP) {
			return
		}
	}

	// Filter Multicast/Broadcast (Global IP Filter)
	if ev.DstIP.IsMulticast() {
		return
	}
	if ip4 := ev.DstIP.To4(); ip4 != nil && ip4.Equal(net.IPv4bcast) {
		return
	}

	ft, exists := a.flows[key]

	if ev.Type == monitor.EventDestroy {
		if exists {
			// Final update
			deltaOrig := safeSub(ev.OriginBytes, ft.OriginBytesLast)
			deltaReply := safeSub(ev.ReplyBytes, ft.ReplyBytesLast)
			a.updateStats(ft, deltaOrig, deltaReply)
			// Remove flow
			delete(a.flows, key)
		}
		return
	}

	if !exists {
		srcIP := ev.SrcIP.String()
		dstIP := ev.DstIP.String()

		// Determine ownership
		srcMac := a.nw.GetMAC(srcIP)
		dstMac := a.nw.GetMAC(dstIP)

		// Filter LAN-to-LAN if disabled
		// Definition: Both Src and Dst are in the monitored interface's subnets
		if !a.monitorLAN && len(a.lanSubnets) > 0 {
			srcInSubnet := false
			dstInSubnet := false

			for _, netParams := range a.lanSubnets {
				if netParams.Contains(ev.SrcIP) {
					srcInSubnet = true
				}
				if netParams.Contains(ev.DstIP) {
					dstInSubnet = true
				}
			}

			if srcInSubnet && dstInSubnet {
				// Internal traffic
				return
			}
		} else if !a.monitorLAN && srcMac != "" && dstMac != "" {
			// Fallback to old behavior if no subnets defined (e.g. no interface set)
			// Ignore purely internal flow based on Neighbor Discovery
			return
		}

		ft = &FlowTracker{
			Key:             key,
			FlowID:          ev.FlowID,
			FirstSeen:       time.Now(),
			LastSeen:        time.Now(),
			SrcIP:           srcIP,
			DstIP:           dstIP,
			SrcPort:         ev.SrcPort,
			DstPort:         ev.DstPort,
			Proto:           ev.Proto,
			OriginBytesLast: ev.OriginBytes,
			ReplyBytesLast:  ev.ReplyBytes,
			// SessionStart default 0: Session = Total - 0 = Total. Correct.
		}
		a.flows[key] = ft
	} else {
		// Existing flow key. Check ID.
		if ft.FlowID != ev.FlowID {
			// ID Changed -> Flow Reused/Reset!
			ft.FlowID = ev.FlowID
			ft.OriginBytesLast = 0
			ft.ReplyBytesLast = 0
			ft.FirstSeen = time.Now() // Reset start time for the new flow
			// Reset tracking for new flow
		}
	}

	ft.LastSeen = time.Now()

	// Calculate deltas
	// strict increasing check

	var deltaOrig, deltaReply uint64

	// If New < Old, and ID matches: It's Jitter/Out-of-Order. IGNORE.
	if ev.OriginBytes < ft.OriginBytesLast {
		// Ignore
		deltaOrig = 0
	} else {
		deltaOrig = ev.OriginBytes - ft.OriginBytesLast
		ft.OriginBytesLast = ev.OriginBytes
	}

	if ev.ReplyBytes < ft.ReplyBytesLast {
		// Ignore
		deltaReply = 0
	} else {
		deltaReply = ev.ReplyBytes - ft.ReplyBytesLast
		ft.ReplyBytesLast = ev.ReplyBytes
	}

	ft.TotalOriginBytes += deltaOrig
	ft.TotalReplyBytes += deltaReply

	a.updateStats(ft, deltaOrig, deltaReply)
}

func safeSub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a // It reset or wrapped
}

func (a *Aggregator) updateStats(ft *FlowTracker, deltaOrig, deltaReply uint64) {
	// Attribute to clients
	// If Src is Client: Orig is Upload, Reply is Download

	// If Dst is Client: Orig is Download, Reply is Upload

	srcMac := a.nw.GetMAC(ft.SrcIP)
	dstMac := a.nw.GetMAC(ft.DstIP)

	isSrcLocal := srcMac != ""
	isDstLocal := dstMac != "" && dstMac != srcMac

	if isSrcLocal {
		c := a.getClient(srcMac)
		c.SessionUpload += deltaOrig
		c.TotalUpload += deltaOrig
		c.SessionDownload += deltaReply
		c.TotalDownload += deltaReply
		c.LastActive = time.Now()
		// Optimization: Active connections calculated in speed loop
	}

	if isDstLocal {
		c := a.getClient(dstMac)
		// For destination, Orig is bytes coming TO it (Download)
		// Reply is bytes sent BY it (Upload)
		c.SessionDownload += deltaOrig
		c.TotalDownload += deltaOrig
		c.SessionUpload += deltaReply
		c.TotalUpload += deltaReply
		c.LastActive = time.Now()
	}

	// Update Global Stats (Internet Traffic Only)
	// If One side is Local and Other is NOT Local, we assume Internet traffic.
	// If both Local: Internal traffic (ignored for Global)
	// If neither Local: Routed traffic not involving us (ignored)

	if isSrcLocal && !isDstLocal {
		// LAN -> WAN
		// Orig = Upload (Out), Reply = Download (In)
		a.globalTotalUpload += deltaOrig
		a.globalTotalDownload += deltaReply
	} else if isDstLocal && !isSrcLocal {
		// WAN -> LAN
		// Orig = Download (In), Reply = Upload (Out)
		a.globalTotalDownload += deltaOrig
		a.globalTotalUpload += deltaReply
	}
}

func (a *Aggregator) getClient(mac string) *model.ClientStats {
	if c, ok := a.clients[mac]; ok {
		return c
	}

	name := mac
	if n, ok := a.staticNames[mac]; ok {
		name = n
	}

	c := &model.ClientStats{
		MAC:       mac,
		Name:      name,
		StartTime: time.Now(),
	}
	a.clients[mac] = c
	return c
}

// Public Methods

func (a *Aggregator) GetGlobalStats() model.GlobalStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Sum up speeds
	var dlSpeed, ulSpeed, conns uint64
	for _, c := range a.clients {
		dlSpeed += c.DownloadSpeed
		ulSpeed += c.UploadSpeed
		conns += c.ActiveConnections
	}

	return model.GlobalStats{
		TotalDownload:     a.globalTotalDownload,
		TotalUpload:       a.globalTotalUpload,
		DownloadSpeed:     dlSpeed,
		UploadSpeed:       ulSpeed,
		ActiveConnections: conns,
	}
}

func (a *Aggregator) GetClients() []model.ClientStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	list := make([]model.ClientStats, 0, len(a.clients))
	for _, c := range a.clients {
		// Populate Name if possible (maybe look up hostname?)
		// For now just use MAC or IP?
		// We can try to lookup IP from ARP for this MAC?
		// Simplify: ClientStats is good.
		list = append(list, *c)
	}
	return list
}

func (a *Aggregator) GetStartTime() time.Time {
	return a.startTime
}

func (a *Aggregator) Reset() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.globalTotalDownload = 0
	a.globalTotalUpload = 0
	a.clients = make(map[string]*model.ClientStats)
	// Clear flows
	a.flows = make(map[string]*FlowTracker)
	return nil
}

// Start begins the aggregation process
func (a *Aggregator) Start(interval time.Duration) {
	go a.processLoop()
	go a.cleanupAndCalculate(interval)
}

func (a *Aggregator) cleanupAndCalculate(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		// 1. Refresh ARP/Neighbors (No cache)
		a.nw.Refresh()

		// 2. Refresh Subnets (No cache)
		a.refreshSubnets()

		// 3. Clear Route Cache (No cache)
		a.mu.Lock()
		a.ipIfCache = make(map[string]int) // Clear cache
		a.mu.Unlock()

		// 4. Calculate Stats
		a.calculateSpeedStats()
	}
}

func (a *Aggregator) refreshSubnets() {
	if a.interfaceName == "" {
		return
	}

	link, err := netlink.LinkByName(a.interfaceName)
	if err != nil {
		return
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return
	}

	var subnets []net.IPNet
	for _, addr := range addrs {
		if addr.IPNet != nil {
			subnets = append(subnets, *addr.IPNet)
		}
	}

	a.mu.Lock()
	a.lanSubnets = subnets
	a.mu.Unlock()
}

func (a *Aggregator) calculateSpeedStats() {
	// Re-implemented speed calc logic here or use the old logic?
	// The new updateStats at line 459 was wiping everything? That looks wrong/placeholder.
	// We need the ACTUAL speed calculation logic that was likely in speedCalcLoop.
	// Since I can't see the old speedCalcLoop, I will assume I need to restore/merge logic.

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	// seconds := now.Sub(a.lastCalcTime).Seconds() // Need state?

	// Reset current speeds for all clients
	for _, c := range a.clients {
		// Calculate Speed
		duration := now.Sub(c.LastSpeedCalc)
		if duration.Seconds() >= 1 {
			c.UploadSpeed = uint64(float64(c.TotalUpload-c.TotalUploadLast) / duration.Seconds())
			c.DownloadSpeed = uint64(float64(c.TotalDownload-c.TotalDownloadLast) / duration.Seconds())

			c.TotalUploadLast = c.TotalUpload
			c.TotalDownloadLast = c.TotalDownload
			c.LastSpeedCalc = now

			// Active Connections - reset and recount?
			// Actually active connections are hard to count perfectly without scanning flows.
			// Let's scan flows.
			c.ActiveConnections = 0
		}
	}

	// Recount active connections from flows
	// Also could clean up expired flows here?

	for key, f := range a.flows {
		// Cleanup Timeout (e.g. 60s)
		if now.Sub(f.LastSeen) > 60*time.Second {
			delete(a.flows, key)
			continue
		}

		// Count Active Connections
		srcMac := a.nw.GetMAC(f.SrcIP)
		dstMac := a.nw.GetMAC(f.DstIP)

		if c, ok := a.clients[srcMac]; ok {
			c.ActiveConnections++
		}
		if c, ok := a.clients[dstMac]; ok {
			c.ActiveConnections++
		}
	}
}

// Additional methods for Client Detail API
func (a *Aggregator) GetFlowsByMAC(mac string) ([]model.FlowDetail, int, []string) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var flows []model.FlowDetail
	var ips []string
	ipSet := make(map[string]struct{}) // Use a set to collect unique IPs

	// Temporary map for aggregation
	// Key: Proto + RemoteIP + RemotePort
	type aggKey struct {
		Proto      uint8
		RemoteIP   string
		RemotePort uint16
	}
	type aggVal struct {
		TotalDownload   uint64
		TotalUpload     uint64
		SessionDownload uint64
		SessionUpload   uint64
		ActiveConns     int
		FirstSeen       time.Time
		LastSeen        time.Time
	}

	aggregated := make(map[aggKey]*aggVal)

	for _, f := range a.flows {
		// Calculate stats for this flow first
		isSrc := false
		isDst := false

		// Identify if this flow belongs to the requested MAC
		// And determine local/remote perspective

		srcMac := a.nw.GetMAC(f.SrcIP)
		dstMac := a.nw.GetMAC(f.DstIP)

		if srcMac == mac {
			isSrc = true
		}
		if dstMac == mac {
			isDst = true
		}

		if !isSrc && !isDst {
			continue
		}

		// Collect unique IPs
		// Logic same as before: finding the "Local IP" used by this client
		if isSrc {
			ipSet[f.SrcIP] = struct{}{}
		}
		if isDst {
			ipSet[f.DstIP] = struct{}{}
		}

		// Determine Remote Tuple
		var remoteIP string
		var remotePort uint16

		if isSrc {
			// Local is Src, Remote is Dst
			remoteIP = f.DstIP
			remotePort = f.DstPort
		} else {
			// Local is Dst, Remote is Src
			remoteIP = f.SrcIP
			remotePort = f.SrcPort
		}

		// Calculate Bytes
		totalDl := f.TotalReplyBytes
		totalUl := f.TotalOriginBytes
		sessionDl := safeSub(totalDl, f.SessionStartReplyBytes)
		sessionUl := safeSub(totalUl, f.SessionStartOriginBytes)

		if isDst {
			// If we are Dst, we received Orig (Download) and sent Reply (Upload)
			totalDl = f.TotalOriginBytes
			totalUl = f.TotalReplyBytes
			sessionDl = safeSub(totalDl, f.SessionStartOriginBytes)
			sessionUl = safeSub(totalUl, f.SessionStartReplyBytes)
		}

		// Aggregate
		k := aggKey{
			Proto:      f.Proto,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
		}

		val, exists := aggregated[k]
		if !exists {
			val = &aggVal{
				FirstSeen: f.FirstSeen,
				LastSeen:  f.LastSeen,
			}
			aggregated[k] = val
		}

		val.TotalDownload += totalDl
		val.TotalUpload += totalUl
		val.SessionDownload += sessionDl
		val.SessionUpload += sessionUl
		val.ActiveConns++

		if f.FirstSeen.Before(val.FirstSeen) {
			val.FirstSeen = f.FirstSeen
		}
		if f.LastSeen.After(val.LastSeen) {
			val.LastSeen = f.LastSeen
		}
	}

	// Convert Map to Slice
	var totalActiveConns int
	for k, v := range aggregated {
		flows = append(flows, model.FlowDetail{
			Protocol:          getProtocolName(k.Proto),
			RemoteIP:          k.RemoteIP,
			RemotePort:        k.RemotePort,
			TotalDownload:     v.TotalDownload,
			TotalUpload:       v.TotalUpload,
			SessionDownload:   v.SessionDownload,
			SessionUpload:     v.SessionUpload,
			ActiveConnections: uint64(v.ActiveConns),
			Duration:          uint64(time.Since(v.FirstSeen).Seconds()),
		})
		totalActiveConns += v.ActiveConns
	}

	// Convert IP set to slice
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return flows, totalActiveConns, ips
}

func (a *Aggregator) GetClientWithSession(mac string) *model.ClientStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if c, ok := a.clients[mac]; ok {
		// Return copy
		val := *c
		return &val
	}
	return nil
}

func (a *Aggregator) ResetClientByMAC(mac string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Delete Client
	delete(a.clients, mac)

	// Delete Flows
	var flowsToDelete []string
	for k, f := range a.flows {
		srcMac := a.nw.GetMAC(f.SrcIP)
		dstMac := a.nw.GetMAC(f.DstIP)

		if srcMac == mac || dstMac == mac {
			flowsToDelete = append(flowsToDelete, k)
		}
	}

	for _, k := range flowsToDelete {
		delete(a.flows, k)
	}

	return nil
}

func (a *Aggregator) ResetSessionByMAC(mac string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Reset Client Session Stats
	if c, ok := a.clients[mac]; ok {
		c.SessionDownload = 0
		c.SessionUpload = 0
	}

	// Reset Flow Session Offsets for this client
	// User requested to "Clear/Recalculate", so we delete the flow trackers.
	// Active flows will be recreated on next event with Duration=0 and Session=0.
	// Inactive flows will just vanish.
	var flowsToDelete []string
	for k, f := range a.flows {
		srcMac := a.nw.GetMAC(f.SrcIP)
		dstMac := a.nw.GetMAC(f.DstIP)

		if srcMac == mac || dstMac == mac {
			flowsToDelete = append(flowsToDelete, k)
		}
	}

	for _, k := range flowsToDelete {
		delete(a.flows, k)
	}

	return nil
}

func getProtocolName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMP"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func (a *Aggregator) SetDeviceNames(names map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.staticNames = make(map[string]string)
	for k, v := range names {
		a.staticNames[strings.ToLower(k)] = v
	}

	// Update existing clients
	for mac, c := range a.clients {
		if name, ok := a.staticNames[mac]; ok {
			c.Name = name
		}
	}
}

func (a *Aggregator) SetInterface(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.interfaceName = ifaceName
	a.interfaceIndex = link.Attrs().Index
	a.ipIfCache = make(map[string]int) // Clear cache on change

	// Fetch Subnets
	a.lanSubnets = nil
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err == nil {
		for _, addr := range addrs {
			if addr.IPNet != nil {
				a.lanSubnets = append(a.lanSubnets, *addr.IPNet)
			}
		}
	}

	a.mu.Unlock()

	return nil
}

func (a *Aggregator) SetMonitorLAN(enable bool) {
	a.mu.Lock()
	a.monitorLAN = enable
	a.mu.Unlock()
}

// checkFlowInterface returns true if the flow matches the monitored interface
// flow is considered matching if EITHER Src OR Dst routes via the interface.
func (a *Aggregator) checkFlowInterface(src, dst net.IP) bool {
	if a.interfaceIndex == 0 {
		return true // No filtering
	}

	// Helper to get interface index for an IP
	getIndex := func(ip net.IP) int {
		ipStr := ip.String()
		if idx, ok := a.ipIfCache[ipStr]; ok {
			return idx
		}

		// Look up route
		routes, err := netlink.RouteGet(ip)
		if err != nil || len(routes) == 0 {
			a.ipIfCache[ipStr] = -1 // Cache absence/error
			return -1
		}

		// Usually the first route is the one used
		idx := routes[0].LinkIndex

		// If it's a local route, check MultiPath or Source?
		// RouteGet should return the egress interface.

		a.ipIfCache[ipStr] = idx
		return idx
	}

	srcIdx := getIndex(src)
	dstIdx := getIndex(dst)

	// If either endpoint routes via the monitored interface, we include it.
	if srcIdx == a.interfaceIndex || dstIdx == a.interfaceIndex {
		return true
	}

	return false
}
