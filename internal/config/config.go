package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/half0wl/railtail/internal/config/parser"
)

type ForwardTrafficType string

const (
	ForwardTrafficTypeTCP   ForwardTrafficType = "tcp"
	ForwardTrafficTypeHTTP  ForwardTrafficType = "http"
	ForwardTrafficTypeHTTPS ForwardTrafficType = "https"
)

var (
	ErrTargetAddrInvalid = errors.New("target-addr is invalid")
)

type Config struct {
	TSHostname         string `flag:"ts-hostname" env:"TS_HOSTNAME" usage:"hostname to use for tailscale"`
	ListenPort         string `flag:"listen-port" env:"LISTEN_PORT" usage:"port to listen on"`
	TargetAddr         string `flag:"target-addr" env:"TARGET_ADDR" usage:"address:port of a tailscale node to send traffic to"`
	TSLoginServer      string `flag:"ts-login-server" env:"TS_LOGIN_SERVER" default:"" usage:"base url of the control server, If you are using Headscale for your control server, use your Headscale instance's URL"`
	TSStateDirPath     string `flag:"ts-state-dir" env:"TS_STATEDIR_PATH" default:"/tmp/railtail" usage:"tailscale state dir"`
	TSAuthKey          string `env:"TS_AUTHKEY,TS_AUTH_KEY" usage:"tailscale auth key"`
	TSVerbose          string `flag:"ts-verbose" env:"TS_VERBOSE" default:"false" usage:"enable verbose tailscale logs"`
	TSDiagnostics      string `flag:"ts-diagnostics" env:"TS_DIAGNOSTICS" default:"false" usage:"enable diagnostic logging"`
	TSPcapPath         string `flag:"ts-pcap-path" env:"TS_PCAP_PATH" default:"" usage:"write tsnet packet capture to path"`
	TSDialTimeout      string `flag:"ts-dial-timeout" env:"TS_DIAL_TIMEOUT" default:"0s" usage:"timeout for tailscale dial (duration, e.g. 10s)"`
	TSIOTimeout        string `flag:"ts-io-timeout" env:"TS_IO_TIMEOUT" default:"0s" usage:"timeout for read/write inactivity (duration, e.g. 30s)"`
	TSPingTarget       string `flag:"ts-ping-target" env:"TS_PING_TARGET" default:"" usage:"tailscale IP to ping for diagnostics"`
	TSPingInterval     string `flag:"ts-ping-interval" env:"TS_PING_INTERVAL" default:"0s" usage:"interval for tailscale ping diagnostics"`
	TSPingType         string `flag:"ts-ping-type" env:"TS_PING_TYPE" default:"tsmp" usage:"tailscale ping type (tsmp, disco, icmp, peerapi)"`
	TSPingSize         string `flag:"ts-ping-size" env:"TS_PING_SIZE" default:"0" usage:"ping payload size in bytes"`
	TSCopyBufferSize   string `flag:"ts-copy-buffer-size" env:"TS_COPY_BUFFER_SIZE" default:"0" usage:"copy buffer size in bytes for TCP relay"`
	TSReadBufferBytes  string `flag:"ts-read-buffer-bytes" env:"TS_READ_BUFFER_BYTES" default:"0" usage:"set TCP read buffer size in bytes"`
	TSWriteBufferBytes string `flag:"ts-write-buffer-bytes" env:"TS_WRITE_BUFFER_BYTES" default:"0" usage:"set TCP write buffer size in bytes"`
	TSKeepAlive        string `flag:"ts-keepalive" env:"TS_KEEPALIVE" default:"false" usage:"enable TCP keepalive"`
	TSKeepAlivePeriod  string `flag:"ts-keepalive-period" env:"TS_KEEPALIVE_PERIOD" default:"0s" usage:"TCP keepalive period"`
	TSNoDelay          string `flag:"ts-no-delay" env:"TS_NO_DELAY" default:"false" usage:"enable TCP no-delay (disable Nagle)"`

	ForwardTrafficType ForwardTrafficType
}

func init() {
	// add help flag purely for the usage message
	flag.Bool("help", false, "Show help message")

	// Only parse and print usage if -help is present in arguments
	if checkForFlag("help") {
		// Create temporary config just to register all flags for usage message
		cfg := &Config{}

		parser.ParseFlags(cfg)

		flag.Usage()
		os.Exit(0)
	}
}

func LoadConfig() (*Config, []error) {
	cfg := &Config{}

	errors := parser.ParseConfig(cfg)

	// Validate target-addr if it's set to either be a valid URL with a port or a valid address:port
	if cfg.TargetAddr != "" {
		protocol := strings.SplitN(cfg.TargetAddr, "://", 2)[0]

		switch protocol {
		case "https", "http":
			cfg.ForwardTrafficType = ForwardTrafficType(protocol)

			u, err := url.Parse(cfg.TargetAddr)
			if err != nil {
				errors = append(errors, fmt.Errorf("%w: %w", ErrTargetAddrInvalid, err))
			}

			// Check if the URL has a port only if the URL is valid
			if err == nil && u.Port() == "" {
				errors = append(errors, fmt.Errorf("%w: address %s: missing port in address", ErrTargetAddrInvalid, cfg.TargetAddr))
			}
		default:
			cfg.ForwardTrafficType = ForwardTrafficTypeTCP

			_, _, err := net.SplitHostPort(cfg.TargetAddr)
			if err != nil {
				errors = append(errors, fmt.Errorf("%w: %w", ErrTargetAddrInvalid, err))
			}
		}
	}

	if len(errors) > 0 {
		return nil, errors
	}

	return cfg, nil
}
