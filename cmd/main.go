package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/kisy/catchmole/pkg/metrics"
	"github.com/kisy/catchmole/pkg/monitor"
	"github.com/kisy/catchmole/pkg/stats"
	"github.com/kisy/catchmole/web"
	"github.com/prometheus/client_golang/prometheus"
)

type Config struct {
	Listen          string            `toml:"listen"`
	Interface       string            `toml:"interface"`
	MonitorLAN      bool              `toml:"monitor_lan"`
	RefreshInterval int               `toml:"interval"`
	Devices         map[string]string `toml:"devices"`
}

func main() {
	var configFile string
	var listenAddr string
	var lanTraffic bool
	var interval int

	flag.StringVar(&configFile, "config", "catchmole.toml", "Path to configuration file")
	flag.StringVar(&listenAddr, "listen", "", "Server listen address (overrides config)")
	flag.BoolVar(&lanTraffic, "lan", false, "Enable monitoring of LAN-to-LAN traffic")
	flag.IntVar(&interval, "interval", 0, "Data refresh interval in seconds (default 1)")
	flag.Parse()

	// Load Config
	var config Config
	if _, err := os.Stat(configFile); err == nil {
		if _, err := toml.DecodeFile(configFile, &config); err != nil {
			log.Fatalf("Failed to parse config file: %v", err)
		}
		log.Printf("Loaded config from %s", configFile)
	} else if os.IsNotExist(err) && configFile != "catchghost.toml" {
		// Only error if user explicitly provided a config file that doesn't exist
		log.Fatalf("Config file not found: %s", configFile)
	}

	// Flag overrides config
	if listenAddr != "" {
		config.Listen = listenAddr
	}
	if interval > 0 {
		config.RefreshInterval = interval
	}
	// Default interval
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 1
	}

	if config.Listen == "" {
		config.Listen = ":8080" // Default
	}
	if lanTraffic {
		config.MonitorLAN = true
	}

	log.Println("Starting CatchGhost Monitor...")

	// 1. Initialize Neighbor Watcher (IP -> MAC)
	nw := monitor.NewNeighborWatcher()
	// nw.Start() -> We now manually trigger refresh in Aggregator
	// defer nw.Stop()

	// 2. Initialize Conntrack Monitor
	mon := monitor.NewConntrackMonitor(nw)
	if err := mon.Start(); err != nil {
		log.Fatalf("Failed to start Conntrack monitor: %v", err)
	}
	defer mon.Stop()

	// 3. Initialize Aggregator
	agg := stats.NewAggregator(mon, nw)
	if config.Interface != "" {
		if err := agg.SetInterface(config.Interface); err != nil {
			log.Printf("Warning: Failed to set interface %s: %v", config.Interface, err)
		} else {
			log.Printf("Monitoring specific interface: %s", config.Interface)
		}
	}
	agg.SetMonitorLAN(config.MonitorLAN)
	if config.MonitorLAN {
		log.Println("LAN-to-LAN traffic monitoring ENABLED")
	} else {
		log.Println("LAN-to-LAN traffic monitoring DISABLED (default)")
	}
	agg.SetDeviceNames(config.Devices) // Set static names

	log.Printf("Starting Aggregator with refresh interval: %d seconds", config.RefreshInterval)
	agg.Start(time.Duration(config.RefreshInterval) * time.Second)

	// 4. Initialize Prometheus Exporter
	exporter := metrics.NewExporter(agg)
	prometheus.MustRegister(exporter)

	// 5. Initialize Web Server
	srv := web.NewServer(agg)
	srv.RegisterHandlers()

	// 6. Run Server
	server := &http.Server{Addr: config.Listen}

	go func() {
		log.Printf("Web server listening on %s", config.Listen)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// 7. Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	// Cleanup happens via defers
}
