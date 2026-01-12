package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/half0wl/railtail/internal/config"
	"github.com/half0wl/railtail/internal/logger"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

type pingOptions struct {
	Target   netip.Addr
	Interval time.Duration
	Type     tailcfg.PingType
	Size     int
}

func main() {
	cfg, errs := config.LoadConfig()
	if len(errs) > 0 {
		logger.StderrWithSource.Error("configuration error(s) found", logger.ErrorsAttr(errs...))
		os.Exit(1)
	}

	parseErrors := []error{}

	diagnosticsEnabled, err := parseBoolSetting("TS_DIAGNOSTICS", cfg.TSDiagnostics)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	tsVerbose, err := parseBoolSetting("TS_VERBOSE", cfg.TSVerbose)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	dialTimeout, err := parseDurationSetting("TS_DIAL_TIMEOUT", cfg.TSDialTimeout)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	ioTimeout, err := parseDurationSetting("TS_IO_TIMEOUT", cfg.TSIOTimeout)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	pingTarget, err := parseIPSetting("TS_PING_TARGET", cfg.TSPingTarget)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	pingInterval, err := parseDurationSetting("TS_PING_INTERVAL", cfg.TSPingInterval)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	pingType, err := parsePingTypeSetting("TS_PING_TYPE", cfg.TSPingType)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	pingSize, err := parsePingSizeSetting("TS_PING_SIZE", cfg.TSPingSize)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	copyBufferSize, err := parseIntSetting("TS_COPY_BUFFER_SIZE", cfg.TSCopyBufferSize)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	readBufferBytes, err := parseIntSetting("TS_READ_BUFFER_BYTES", cfg.TSReadBufferBytes)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	writeBufferBytes, err := parseIntSetting("TS_WRITE_BUFFER_BYTES", cfg.TSWriteBufferBytes)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	keepAliveEnabled, err := parseBoolSetting("TS_KEEPALIVE", cfg.TSKeepAlive)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	keepAlivePeriod, err := parseDurationSetting("TS_KEEPALIVE_PERIOD", cfg.TSKeepAlivePeriod)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	noDelayEnabled, err := parseBoolSetting("TS_NO_DELAY", cfg.TSNoDelay)
	if err != nil {
		parseErrors = append(parseErrors, err)
	}

	if pingInterval > 0 && !pingTarget.IsValid() {
		parseErrors = append(parseErrors, fmt.Errorf("TS_PING_TARGET must be set when TS_PING_INTERVAL is enabled"))
	}

	if pingTarget.IsValid() && pingInterval <= 0 {
		parseErrors = append(parseErrors, fmt.Errorf("TS_PING_INTERVAL must be a positive duration when TS_PING_TARGET is set"))
	}

	if copyBufferSize < 0 || readBufferBytes < 0 || writeBufferBytes < 0 {
		parseErrors = append(parseErrors, fmt.Errorf("TS_COPY_BUFFER_SIZE, TS_READ_BUFFER_BYTES, and TS_WRITE_BUFFER_BYTES must be non-negative"))
	}

	if len(parseErrors) > 0 {
		logger.StderrWithSource.Error("configuration error(s) found", logger.ErrorsAttr(parseErrors...))
		os.Exit(1)
	}

	pingOptions := pingOptions{
		Target:   pingTarget,
		Interval: pingInterval,
		Type:     pingType,
		Size:     pingSize,
	}

	pingTargetValue := ""
	if pingOptions.Target.IsValid() {
		pingTargetValue = pingOptions.Target.String()
	}

	tcpOptions := tcpForwardOptions{
		Diagnostics:      diagnosticsEnabled,
		DialTimeout:      dialTimeout,
		IOTimeout:        ioTimeout,
		CopyBufferSize:   copyBufferSize,
		ReadBufferBytes:  readBufferBytes,
		WriteBufferBytes: writeBufferBytes,
		KeepAlive:        keepAliveEnabled,
		KeepAlivePeriod:  keepAlivePeriod,
		NoDelay:          noDelayEnabled,
	}

	ts := &tsnet.Server{
		Hostname:     cfg.TSHostname,
		AuthKey:      cfg.TSAuthKey,
		RunWebClient: false,
		Ephemeral:    false,
		ControlURL:   cfg.TSLoginServer,
		UserLogf: func(format string, v ...any) {
			logger.Stdout.Info(fmt.Sprintf(format, v...))
		},
		Dir: filepath.Join(cfg.TSStateDirPath, "railtail"),
	}

	if tsVerbose {
		ts.Logf = func(format string, v ...any) {
			logger.Stdout.Info("tsnet", slog.String("message", fmt.Sprintf(format, v...)))
		}
	}

	if err := ts.Start(); err != nil {
		logger.StderrWithSource.Error("failed to start tailscale network server", logger.ErrAttr(err))
		os.Exit(1)
	}

	defer ts.Close()

	startPcapCapture(ts, cfg.TSPcapPath)
	if diagnosticsEnabled {
		logTailscaleStatus(ts, pingOptions.Target)
	}
	startPingLoop(ts, pingOptions)

	listenAddr := "[::]:" + cfg.ListenPort

	logger.Stdout.Info("🚀 Starting railtail",
		slog.String("ts-hostname", cfg.TSHostname),
		slog.String("listen-addr", listenAddr),
		slog.String("target-addr", cfg.TargetAddr),
		slog.String("ts-login-server", cmp.Or(cfg.TSLoginServer, "using_default")),
		slog.String("ts-state-dir", filepath.Join(cfg.TSStateDirPath, "railtail")),
		slog.Bool("ts-verbose", tsVerbose),
		slog.Bool("ts-diagnostics", diagnosticsEnabled),
		slog.Duration("ts-dial-timeout", dialTimeout),
		slog.Duration("ts-io-timeout", ioTimeout),
		slog.String("ts-pcap-path", cfg.TSPcapPath),
		slog.String("ts-ping-target", pingTargetValue),
		slog.Duration("ts-ping-interval", pingOptions.Interval),
		slog.String("ts-ping-type", string(pingOptions.Type)),
		slog.Int("ts-ping-size", pingOptions.Size),
		slog.Int("ts-copy-buffer-size", tcpOptions.CopyBufferSize),
		slog.Int("ts-read-buffer-bytes", tcpOptions.ReadBufferBytes),
		slog.Int("ts-write-buffer-bytes", tcpOptions.WriteBufferBytes),
		slog.Bool("ts-keepalive", tcpOptions.KeepAlive),
		slog.Duration("ts-keepalive-period", tcpOptions.KeepAlivePeriod),
		slog.Bool("ts-no-delay", tcpOptions.NoDelay),
	)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.StderrWithSource.Error("failed to start local listener", logger.ErrAttr(err))
		os.Exit(1)
	}

	if cfg.ForwardTrafficType == config.ForwardTrafficTypeHTTP || cfg.ForwardTrafficType == config.ForwardTrafficTypeHTTPS {
		logger.Stdout.Info("running in HTTP/s proxy mode (http(s):// scheme detected in targetAddr)",
			slog.String("listen-addr", listenAddr),
			slog.String("target-addr", cfg.TargetAddr),
		)

		httpClient := ts.HTTPClient()
		httpClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}

		server := http.Server{
			IdleTimeout:       60 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwardingInfo := []any{
					slog.String("remote-addr", r.RemoteAddr),
					slog.String("target", cfg.TargetAddr),
				}

				logger.Stdout.Info("forwarding", forwardingInfo...)

				if err := fwdHttp(httpClient, cfg.TargetAddr, w, r); err != nil {
					logger.StderrWithSource.Error("failed to forward http request", append([]any{logger.ErrAttr(err)}, forwardingInfo...)...)
				}
			}),
		}

		if err := server.Serve(listener); err != nil {
			logger.StderrWithSource.Error("failed to start http server", logger.ErrAttr(err))
			os.Exit(1)
		}
	}

	logger.Stdout.Info("running in TCP tunnel mode (no HTTP scheme detected in targetAddr)",
		slog.String("listen-addr", listenAddr),
		slog.String("target-addr", cfg.TargetAddr),
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.StderrWithSource.Error("failed to accept connection", logger.ErrAttr(err))
			continue
		}

		forwardingInfo := []any{
			slog.String("local-addr", conn.LocalAddr().String()),
			slog.String("remote-addr", conn.RemoteAddr().String()),
			slog.String("target", cfg.TargetAddr),
		}

		logger.Stdout.Info("forwarding tcp connection", forwardingInfo...)

		go func() {
			if err := fwdTCP(conn, ts, cfg.TargetAddr, tcpOptions); err != nil {
				logger.StderrWithSource.Error("forwarding failed", append([]any{logger.ErrAttr(err)}, forwardingInfo...)...)
			}
		}()
	}
}

func parseBoolSetting(name, value string) (bool, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return false, nil
	}

	switch value {
	case "1", "true", "yes", "y", "on":
		return true, nil
	case "0", "false", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be a boolean value (got %q)", name, value)
	}
}

func parseDurationSetting(name, value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration (got %q)", name, value)
	}

	if parsed < 0 {
		return 0, fmt.Errorf("%s must be a positive duration (got %q)", name, value)
	}

	return parsed, nil
}

func parseIPSetting(name, value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s must be a valid IP address (got %q)", name, value)
	}

	return addr, nil
}

func parsePingTypeSetting(name, value string) (tailcfg.PingType, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return tailcfg.PingType("tsmp"), nil
	}

	switch value {
	case "tsmp", "disco", "icmp", "peerapi":
		return tailcfg.PingType(value), nil
	default:
		return "", fmt.Errorf("%s must be one of tsmp, disco, icmp, peerapi (got %q)", name, value)
	}
}

func parsePingSizeSetting(name, value string) (int, error) {
	return parseIntSetting(name, value)
}

func parseIntSetting(name, value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer (got %q)", name, value)
	}

	if parsed < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer (got %q)", name, value)
	}

	return parsed, nil
}

func startPcapCapture(ts *tsnet.Server, pcapPath string) {
	pcapPath = strings.TrimSpace(pcapPath)
	if pcapPath == "" {
		return
	}

	logger.Stdout.Info("starting tailscale pcap capture", slog.String("pcap-path", pcapPath))

	go func() {
		if err := ts.CapturePcap(context.Background(), pcapPath); err != nil {
			logger.StderrWithSource.Error("failed to start tailscale pcap capture", logger.ErrAttr(err), slog.String("pcap-path", pcapPath))
		}
	}()
}

func startPingLoop(ts *tsnet.Server, options pingOptions) {
	if !options.Target.IsValid() || options.Interval <= 0 {
		return
	}

	localClient, err := ts.LocalClient()
	if err != nil {
		logger.StderrWithSource.Error("failed to initialize tailscale ping client", logger.ErrAttr(err))
		return
	}

	logger.Stdout.Info("starting tailscale ping loop",
		slog.String("target", options.Target.String()),
		slog.Duration("interval", options.Interval),
		slog.String("ping-type", string(options.Type)),
		slog.Int("ping-size", options.Size),
	)

	go func() {
		ticker := time.NewTicker(options.Interval)
		defer ticker.Stop()

		for {
			timeout := 10 * time.Second
			if options.Interval > 0 && options.Interval < timeout {
				timeout = options.Interval
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			result, err := localClient.PingWithOpts(ctx, options.Target, options.Type, local.PingOpts{Size: options.Size})
			cancel()

			if err != nil {
				logger.StderrWithSource.Error("tailscale ping failed",
					logger.ErrAttr(err),
					slog.String("target", options.Target.String()),
					slog.String("ping-type", string(options.Type)),
				)
			} else {
				latency := time.Duration(result.LatencySeconds * float64(time.Second))
				attrs := []any{
					slog.String("target", options.Target.String()),
					slog.String("node-ip", result.NodeIP),
					slog.String("node-name", result.NodeName),
					slog.Duration("latency", latency),
					slog.String("endpoint", result.Endpoint),
					slog.String("peer-relay", result.PeerRelay),
					slog.Int("derp-region-id", result.DERPRegionID),
					slog.String("derp-region-code", result.DERPRegionCode),
					slog.String("ping-type", string(options.Type)),
				}

				if result.Err != "" {
					attrs = append(attrs, slog.String("error", result.Err))
					logger.StderrWithSource.Error("tailscale ping error", attrs...)
				} else {
					logger.Stdout.Info("tailscale ping", attrs...)
				}
			}

			<-ticker.C
		}
	}()
}

func logTailscaleStatus(ts *tsnet.Server, pingTarget netip.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	localClient, err := ts.LocalClient()
	if err != nil {
		logger.StderrWithSource.Error("failed to initialize tailscale local client", logger.ErrAttr(err))
		return
	}

	status, err := localClient.Status(ctx)
	if err != nil {
		logger.StderrWithSource.Error("failed to read tailscale status", logger.ErrAttr(err))
		return
	}

	tailscaleIPs := make([]string, 0, len(status.TailscaleIPs))
	for _, ip := range status.TailscaleIPs {
		tailscaleIPs = append(tailscaleIPs, ip.String())
	}

	selfDNS := ""
	selfRelay := ""
	selfPeerRelay := ""
	selfCurAddr := ""
	if status.Self != nil {
		selfDNS = strings.TrimSuffix(status.Self.DNSName, ".")
		selfRelay = status.Self.Relay
		selfPeerRelay = status.Self.PeerRelay
		selfCurAddr = status.Self.CurAddr
	}

	magicDNSSuffix := ""
	if status.CurrentTailnet != nil {
		magicDNSSuffix = status.CurrentTailnet.MagicDNSSuffix
	}

	logger.Stdout.Info("tailscale status",
		slog.Bool("kernel-tun", status.TUN),
		slog.String("backend-state", status.BackendState),
		slog.String("self-dns", selfDNS),
		slog.String("self-relay", selfRelay),
		slog.String("self-peer-relay", selfPeerRelay),
		slog.String("self-cur-addr", selfCurAddr),
		slog.String("tailscale-ips", strings.Join(tailscaleIPs, ", ")),
		slog.String("magic-dns-suffix", magicDNSSuffix),
	)

	if len(status.Health) > 0 {
		logger.Stdout.Info("tailscale health", slog.Any("issues", status.Health))
	}

	if pingTarget.IsValid() {
		logTargetPeerStatus(status, pingTarget)
	}
}

func logTargetPeerStatus(status *ipnstate.Status, target netip.Addr) {
	if status == nil {
		return
	}

	for _, peer := range status.Peer {
		for _, ip := range peer.TailscaleIPs {
			if ip == target {
				logger.Stdout.Info("tailscale peer status",
					slog.String("target", target.String()),
					slog.String("dns-name", strings.TrimSuffix(peer.DNSName, ".")),
					slog.String("relay", peer.Relay),
					slog.String("peer-relay", peer.PeerRelay),
					slog.String("cur-addr", peer.CurAddr),
					slog.Bool("active", peer.Active),
					slog.Bool("online", peer.Online),
					slog.Time("last-handshake", peer.LastHandshake),
					slog.Time("last-write", peer.LastWrite),
					slog.Int64("rx-bytes", peer.RxBytes),
					slog.Int64("tx-bytes", peer.TxBytes),
				)
				return
			}
		}
	}

	logger.Stdout.Info("tailscale peer status not found", slog.String("target", target.String()))
}
