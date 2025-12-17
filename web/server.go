package web

import (
	"embed"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/kisy/catchmole/model"
	"github.com/kisy/catchmole/pkg/stats"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed clients.html
var htmlContent []byte

//go:embed client.html
var clientHtmlContent []byte

//go:embed static
var staticFiles embed.FS

type Server struct {
	agg     *stats.Aggregator
	ipTools map[string]string
}

func NewServer(agg *stats.Aggregator, ipTools map[string]string) *Server {
	return &Server{
		agg:     agg,
		ipTools: ipTools,
	}
}

func (s *Server) RegisterHandlers() {
	http.HandleFunc("/clients", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(htmlContent)
	})

	http.HandleFunc("/client", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(clientHtmlContent)
	})

	http.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	http.HandleFunc("/api/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := struct {
			IpTools map[string]string `json:"ip_tools"`
		}{
			IpTools: s.ipTools,
		}
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := struct {
			StartTime time.Time           `json:"start_time"`
			Global    model.GlobalStats   `json:"global"`
			Clients   []model.ClientStats `json:"clients"`
		}{
			StartTime: s.agg.GetStartTime(),
			Global:    s.agg.GetGlobalStats(),
			Clients:   s.agg.GetClients(),
		}
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.agg.Reset(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	http.HandleFunc("/api/client", func(w http.ResponseWriter, r *http.Request) {
		mac := r.URL.Query().Get("mac")
		if mac == "" {
			http.Error(w, "Missing mac parameter", http.StatusBadRequest)
			return
		}
		mac = strings.TrimSpace(strings.ToLower(mac))
		w.Header().Set("Content-Type", "application/json")

		flows, activeConns, localIPs := s.agg.GetFlowsByMAC(mac)

		clientStats := s.agg.GetClientWithSession(mac)
		if clientStats != nil {
			clientStats.ActiveConnections = uint64(activeConns)
		}

		response := struct {
			Client   *model.ClientStats `json:"client"`
			Flows    []model.FlowDetail `json:"flows"`
			LocalIPs []string           `json:"local_ips"`
		}{
			Client:   clientStats,
			Flows:    flows,
			LocalIPs: localIPs,
		}
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/api/client/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))
		log.Printf("API: Reset Client %s\n", mac)
		if err := s.agg.ResetClientByMAC(mac); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/client/reset_session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))
		log.Printf("API: Reset Session %s\n", mac)
		if err := s.agg.ResetSessionByMAC(mac); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("OK"))
	})
	http.Handle("/metrics", promhttp.Handler())
}
