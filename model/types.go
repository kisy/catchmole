package model

import "time"

// ClientStats contains aggregated statistics for a client (MAC-based)
type ClientStats struct {
	MAC               string    `json:"mac"`
	Name              string    `json:"name"`
	TotalDownload     uint64    `json:"total_download"`
	TotalUpload       uint64    `json:"total_upload"`
	SessionDownload   uint64    `json:"session_download"`
	SessionUpload     uint64    `json:"session_upload"`
	DownloadSpeed     uint64    `json:"download_speed"`
	UploadSpeed       uint64    `json:"upload_speed"`
	ActiveConnections uint64    `json:"active_connections"`
	LastUpdate        time.Time `json:"last_update"`
	StartTime         time.Time `json:"start_time"`
	LastActive        time.Time `json:"last_active"`

	// Internal state for speed calculation
	TotalUploadLast   uint64    `json:"-"`
	TotalDownloadLast uint64    `json:"-"`
	LastSpeedCalc     time.Time `json:"-"`

	// Active Connection Smoothing
	SmoothedActiveConns float64 `json:"-"`
	RawActiveConns      uint64  `json:"-"`
}

type FlowDetail struct {
	Protocol          string `json:"protocol"`
	ClientIP          string `json:"client_ip"`
	RemoteIP          string `json:"remote_ip"`
	RemotePort        uint16 `json:"remote_port"`
	TotalDownload     uint64 `json:"total_download"`
	TotalUpload       uint64 `json:"total_upload"`
	SessionDownload   uint64 `json:"session_download"`
	SessionUpload     uint64 `json:"session_upload"`
	DownloadSpeed     uint64 `json:"download_speed"`
	UploadSpeed       uint64 `json:"upload_speed"`
	Duration          uint64 `json:"duration"`
	SessionDuration   uint64 `json:"session_duration"`
	ActiveConnections uint64 `json:"active_connections"`
	TTLRemaining      int    `json:"ttl_remaining"`
}

type GlobalStats struct {
	TotalDownload uint64 `json:"total_download"`
	TotalUpload   uint64 `json:"total_upload"`
	DownloadSpeed uint64 `json:"download_speed"` // Bytes/sec
	UploadSpeed   uint64 `json:"upload_speed"`   // Bytes/sec

	// Internal state for speed calculation
	TotalUploadLast   uint64    `json:"-"`
	TotalDownloadLast uint64    `json:"-"`
	LastSpeedCalc     time.Time `json:"-"`
	ActiveConnections uint64    `json:"active_connections"`
}
