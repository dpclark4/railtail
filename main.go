package main

import (
	"context"
	"cmp"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/half0wl/railtail/internal/config"
	"github.com/half0wl/railtail/internal/logger"

	"tailscale.com/tsnet"
)

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

	if len(parseErrors) > 0 {
		logger.StderrWithSource.Error("configuration error(s) found", logger.ErrorsAttr(parseErrors...))
		os.Exit(1)
	}

	tcpOptions := tcpForwardOptions{
		Diagnostics: diagnosticsEnabled,
		DialTimeout: dialTimeout,
		IOTimeout:   ioTimeout,
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
		logTailscaleStatus(ts)
	}

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

func logTailscaleStatus(ts *tsnet.Server) {
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
}
