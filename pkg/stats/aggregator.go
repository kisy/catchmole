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
	globalSmoothedConns float64

	startTime time.Time

	staticNames map[string]string

	ignoreLAN bool

	// Interface Filtering
	interfaceName  string
	interfaceIndex int
	lanSubnets     []net.IPNet // Subnets of the monitored interface

	// Config
	flowTTL time.Duration
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

	// Removed: OriginBytesLast, ReplyBytesLast
	// Delta calculation now happens in monitor layer

	TotalOriginBytes uint64 // Cumulative
	TotalReplyBytes  uint64 // Cumulative

	SessionStartOriginBytes uint64
	SessionStartReplyBytes  uint64

	// Speed Calculation
	OrigSpeed  uint64
	ReplySpeed uint64

	SpeedTotalOriginLast uint64
	SpeedTotalReplyLast  uint64
	SpeedLastCalc        time.Time
}

func NewAggregator(mon *monitor.ConntrackMonitor, nw *monitor.NeighborWatcher) *Aggregator {
	return &Aggregator{
		mon:         mon,
		nw:          nw,
		clients:     make(map[string]*model.ClientStats),
		flows:       make(map[string]*FlowTracker),
		startTime:   time.Now(),
		staticNames: make(map[string]string),
		flowTTL:     60 * time.Second, // Default
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

	// 1. Interface Filter (Subnet Based)
	if a.interfaceName != "" {
		if !a.checkFlowSubnet(ev.SrcIP, ev.DstIP) {
			return
		}
	}

	// Filter Multicast/Broadcast
	if ev.DstIP.IsMulticast() {
		return
	}
	if ip4 := ev.DstIP.To4(); ip4 != nil && ip4.Equal(net.IPv4bcast) {
		return
	}

	ft, exists := a.flows[key]

	if !exists {
		// New Flow Initialization
		srcIP := ev.SrcIP.String()
		dstIP := ev.DstIP.String()

		srcMac := a.nw.GetMAC(srcIP)
		dstMac := a.nw.GetMAC(dstIP)

		// Filter LAN-to-LAN if enabled (ignoreLAN is true)
		if a.ignoreLAN && len(a.lanSubnets) > 0 {
			srcInSubnet := false
			dstInSubnet := false

			for _, sn := range a.lanSubnets {
				if sn.Contains(ev.SrcIP) {
					srcInSubnet = true
				}
				if sn.Contains(ev.DstIP) {
					dstInSubnet = true
				}
			}

			if srcInSubnet && dstInSubnet {
				// Internal traffic, ignore
				return
			}
		} else if a.ignoreLAN && srcMac != "" && dstMac != "" {
			// Fallback (MAC based check)
			return
		}

		ft = &FlowTracker{
			Key:       key,
			FlowID:    ev.FlowID,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   ev.SrcPort,
			DstPort:   ev.DstPort,
			Proto:     ev.Proto,
		}
		a.flows[key] = ft
		// Note: Monitor sends Delta=0 for first seen flows, so no data accumulated here
	}

	// Update existing flow
	ft.LastSeen = time.Now()

	// Note: ev.OriginBytes and ev.ReplyBytes are now DELTA values from monitor layer
	// No need to calculate delta here, just accumulate
	deltaOrig := ev.OriginBytes
	deltaReply := ev.ReplyBytes

	// Safety Cap: If delta is unreasonably large (> 1GB), it's likely an error
	const SafeCap = 1 * 1024 * 1024 * 1024 // 1GB

	if deltaOrig > SafeCap {
		// log.Printf("[WARN] Huge Origin Delta detected: %d (Flow %d). Ignoring.", deltaOrig, ft.FlowID)
		deltaOrig = 0
	}
	if deltaReply > SafeCap {
		// log.Printf("[WARN] Huge Reply Delta detected: %d (Flow %d). Ignoring.", deltaReply, ft.FlowID)
		deltaReply = 0
	}

	// Accumulate totals
	ft.TotalOriginBytes += deltaOrig
	ft.TotalReplyBytes += deltaReply

	a.updateStats(ft, deltaOrig, deltaReply)
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
		ActiveConnections: uint64(a.globalSmoothedConns + 0.5),
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
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.startTime
}

func (a *Aggregator) Reset() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.startTime = time.Now()
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

		// 3. Calculate Stats
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

func (a *Aggregator) SetFlowTTL(ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flowTTL = ttl
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

	// 1. Reset current raw counts for all clients
	for _, c := range a.clients {
		c.RawActiveConns = 0
		// Calculate Speed
		if c.LastSpeedCalc.IsZero() {
			c.LastSpeedCalc = now
			c.TotalUploadLast = c.TotalUpload
			c.TotalDownloadLast = c.TotalDownload
			continue
		}

		duration := now.Sub(c.LastSpeedCalc)
		if duration.Seconds() >= 0.5 {
			// Avoid division by zero (shouldn't happen with check above)
			secs := duration.Seconds()
			c.UploadSpeed = uint64(float64(c.TotalUpload-c.TotalUploadLast) / secs)
			c.DownloadSpeed = uint64(float64(c.TotalDownload-c.TotalDownloadLast) / secs)

			c.TotalUploadLast = c.TotalUpload
			c.TotalDownloadLast = c.TotalDownload
			c.LastSpeedCalc = now
		}
	}

	// 2. Count Active Connections (Raw)
	var globalRawActiveCount uint64
	for key, f := range a.flows {
		// Cleanup Timeout (use Configured TTL)
		ttl := a.flowTTL
		if ttl <= 0 {
			ttl = 60 * time.Second
		}
		if now.Sub(f.LastSeen) > ttl {
			delete(a.flows, key)
			continue
		}

		// Calculate Flow Speed
		if f.SpeedLastCalc.IsZero() {
			f.SpeedLastCalc = now
			f.SpeedTotalOriginLast = f.TotalOriginBytes
			f.SpeedTotalReplyLast = f.TotalReplyBytes
		} else {
			fduration := now.Sub(f.SpeedLastCalc)
			if fduration.Seconds() >= 0.5 {
				fsecs := fduration.Seconds()

				// Origin Speed (Upload/Download depends on direction)
				origSpeed := uint64(float64(f.TotalOriginBytes-f.SpeedTotalOriginLast) / fsecs)
				replySpeed := uint64(float64(f.TotalReplyBytes-f.SpeedTotalReplyLast) / fsecs)

				f.OrigSpeed = origSpeed
				f.ReplySpeed = replySpeed

				f.SpeedTotalOriginLast = f.TotalOriginBytes
				f.SpeedTotalReplyLast = f.TotalReplyBytes
				f.SpeedLastCalc = now
			}
		}

		globalRawActiveCount++

		srcMac := a.nw.GetMAC(f.SrcIP)
		dstMac := a.nw.GetMAC(f.DstIP)

		if c, ok := a.clients[srcMac]; ok {
			c.RawActiveConns++
		}
		if c, ok := a.clients[dstMac]; ok {
			c.RawActiveConns++
		}
	}

	// 3. Apply Smoothing (EMA)
	// Alpha factor (0 < alpha <= 1). smaller = smoother.
	// Using 0.2 for "Industry Standard" like variance reduction
	const alpha = 0.2

	for _, c := range a.clients {
		// Initial: if 0, may be startup.
		// To avoid "slow ramp up" from 0, if Smoothed is 0, we can seed it with Raw.
		if c.SmoothedActiveConns == 0 && c.RawActiveConns > 0 {
			c.SmoothedActiveConns = float64(c.RawActiveConns)
		} else {
			c.SmoothedActiveConns = (alpha * float64(c.RawActiveConns)) + ((1 - alpha) * c.SmoothedActiveConns)
		}
		c.ActiveConnections = uint64(c.SmoothedActiveConns + 0.5) // Round
	}

	// Global Smoothing
	if a.globalSmoothedConns == 0 && globalRawActiveCount > 0 {
		a.globalSmoothedConns = float64(globalRawActiveCount)
	} else {
		a.globalSmoothedConns = (alpha * float64(globalRawActiveCount)) + ((1 - alpha) * a.globalSmoothedConns)
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
		DownloadSpeed   uint64
		UploadSpeed     uint64
		ActiveConns     int
		LocalIP         string
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

		// Determine Remote Tuple and Local IP
		var remoteIP string
		var remotePort uint16
		var localIP string

		if isSrc {
			// Local is Src, Remote is Dst
			localIP = f.SrcIP
			remoteIP = f.DstIP
			remotePort = f.DstPort
		} else {
			// Local is Dst, Remote is Src
			localIP = f.DstIP
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
				LocalIP:   localIP,
			}
			aggregated[k] = val
		}

		val.TotalDownload += totalDl
		val.TotalUpload += totalUl
		val.SessionDownload += sessionDl
		val.SessionUpload += sessionUl
		val.ActiveConns++

		// Sum Speeds
		// Orig = Src -> Dst
		// Reply = Dst -> Src
		if isSrc {
			// I am Src. My Upload is Orig. My Download is Reply.
			val.UploadSpeed += f.OrigSpeed
			val.DownloadSpeed += f.ReplySpeed
		} else {
			// I am Dst. My Upload is Reply. My Download is Orig.
			val.UploadSpeed += f.ReplySpeed
			val.DownloadSpeed += f.OrigSpeed
		}

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
			ClientIP:          v.LocalIP,
			RemoteIP:          k.RemoteIP,
			RemotePort:        k.RemotePort,
			TotalDownload:     v.TotalDownload,
			TotalUpload:       v.TotalUpload,
			SessionDownload:   v.SessionDownload,
			SessionUpload:     v.SessionUpload,
			DownloadSpeed:     v.DownloadSpeed,
			UploadSpeed:       v.UploadSpeed,
			ActiveConnections: uint64(v.ActiveConns),
			Duration:          uint64(v.LastSeen.Sub(v.FirstSeen).Seconds()),
			TTLRemaining:      int(a.flowTTL.Seconds() - time.Since(v.LastSeen).Seconds()),
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

	// Fetch Subnets
	a.lanSubnets = nil
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err == nil {
		for _, addr := range addrs {
			if addr.IPNet != nil {
				a.lanSubnets = append(a.lanSubnets, *addr.IPNet)
				fmt.Printf("[Info] Detected LAN Subnet: %s\n", addr.IPNet.String())
			}
		}
	}

	a.mu.Unlock()

	return nil
}

func (a *Aggregator) SetIgnoreLAN(ignore bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ignoreLAN = ignore
}

// checkFlowSubnet returns true if either Src or Dst matches the monitored interface subnets
func (a *Aggregator) checkFlowSubnet(src, dst net.IP) bool {
	if a.interfaceName == "" {
		return true // No filtering
	}

	// Helper to check if IP is in any LAN subnet
	inSubnet := func(ip net.IP) bool {
		for _, sn := range a.lanSubnets {
			if sn.Contains(ip) {
				return true
			}
		}
		return false
	}

	return inSubnet(src) || inSubnet(dst)
}

func safeSub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return 0
}
