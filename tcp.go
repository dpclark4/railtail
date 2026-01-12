package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/half0wl/railtail/internal/logger"
	"golang.org/x/sync/errgroup"
	"tailscale.com/tsnet"
)

type readBufferSetter interface {
	SetReadBuffer(bytes int) error
}

type writeBufferSetter interface {
	SetWriteBuffer(bytes int) error
}

type noDelaySetter interface {
	SetNoDelay(noDelay bool) error
}

type keepAliveSetter interface {
	SetKeepAlive(keepAlive bool) error
}

type keepAlivePeriodSetter interface {
	SetKeepAlivePeriod(period time.Duration) error
}

type tcpForwardOptions struct {
	Diagnostics      bool
	DialTimeout      time.Duration
	IOTimeout        time.Duration
	CopyBufferSize   int
	ReadBufferBytes  int
	WriteBufferBytes int
	KeepAlive        bool
	KeepAlivePeriod  time.Duration
	NoDelay          bool
}

type transferStats struct {
	direction string
	start     time.Time
	firstByte time.Time
	bytes     int64
	end       time.Time
	err       error
}

func fwdTCP(lstConn net.Conn, ts *tsnet.Server, targetAddr string, options tcpForwardOptions) error {
	defer lstConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connInfo := []any{
		slog.String("local-addr", lstConn.LocalAddr().String()),
		slog.String("remote-addr", lstConn.RemoteAddr().String()),
		slog.String("target", targetAddr),
	}

	connStart := time.Now()
	dialCtx := ctx
	if options.DialTimeout > 0 {
		var dialCancel context.CancelFunc
		dialCtx, dialCancel = context.WithTimeout(ctx, options.DialTimeout)
		defer dialCancel()
	}

	dialStart := time.Now()
	tsConn, err := ts.Dial(dialCtx, "tcp", targetAddr)
	dialDuration := time.Since(dialStart)
	if err != nil {
		if options.Diagnostics {
			logger.StderrWithSource.Error("tailscale dial failed", append([]any{logger.ErrAttr(err), slog.Duration("duration", dialDuration)}, connInfo...)...)
		}
		return fmt.Errorf("failed to dial tailscale node after %s: %w", dialDuration, err)
	}

	if options.Diagnostics {
		logger.Stdout.Info("tailscale dial succeeded", append([]any{slog.Duration("duration", dialDuration)}, connInfo...)...)
	}

	defer tsConn.Close()

	applyTCPOptions(lstConn, options, "client", connInfo)
	applyTCPOptions(tsConn, options, "tailnet", connInfo)

	g, _ := errgroup.WithContext(ctx)

	toTailnet := transferStats{direction: "client_to_tailnet"}
	fromTailnet := transferStats{direction: "tailnet_to_client"}

	g.Go(func() error {
		toTailnet.start = time.Now()
		defer func() {
			toTailnet.end = time.Now()
		}()

		err := copyWithStats(tsConn, lstConn, options.IOTimeout, options.CopyBufferSize, &toTailnet)
		toTailnet.err = err
		if err != nil {
			return fmt.Errorf("failed to copy data to tailscale node: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		fromTailnet.start = time.Now()
		defer func() {
			fromTailnet.end = time.Now()
		}()

		err := copyWithStats(lstConn, tsConn, options.IOTimeout, options.CopyBufferSize, &fromTailnet)
		fromTailnet.err = err
		if err != nil {
			return fmt.Errorf("failed to copy data from tailscale node: %w", err)
		}

		return nil
	})

	err = g.Wait()

	if options.Diagnostics {
		connDuration := time.Since(connStart)
		logger.Stdout.Info("tcp connection closed", append([]any{slog.Duration("duration", connDuration)}, connInfo...)...)
		logTransferStats(&toTailnet, connInfo)
		logTransferStats(&fromTailnet, connInfo)
	}

	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}

	return nil
}

func applyTCPOptions(conn net.Conn, options tcpForwardOptions, label string, connInfo []any) {
	if options.ReadBufferBytes > 0 {
		if setter, ok := conn.(readBufferSetter); ok {
			if err := setter.SetReadBuffer(options.ReadBufferBytes); err != nil && options.Diagnostics {
				logger.StderrWithSource.Error("failed to set read buffer",
					append([]any{logger.ErrAttr(err), slog.Int("bytes", options.ReadBufferBytes), slog.String("side", label)}, connInfo...)...)
			}
		} else if options.Diagnostics {
			logger.Stdout.Info("read buffer not supported", append([]any{slog.String("side", label)}, connInfo...)...)
		}
	}

	if options.WriteBufferBytes > 0 {
		if setter, ok := conn.(writeBufferSetter); ok {
			if err := setter.SetWriteBuffer(options.WriteBufferBytes); err != nil && options.Diagnostics {
				logger.StderrWithSource.Error("failed to set write buffer",
					append([]any{logger.ErrAttr(err), slog.Int("bytes", options.WriteBufferBytes), slog.String("side", label)}, connInfo...)...)
			}
		} else if options.Diagnostics {
			logger.Stdout.Info("write buffer not supported", append([]any{slog.String("side", label)}, connInfo...)...)
		}
	}

	if options.NoDelay {
		if setter, ok := conn.(noDelaySetter); ok {
			if err := setter.SetNoDelay(true); err != nil && options.Diagnostics {
				logger.StderrWithSource.Error("failed to set no-delay",
					append([]any{logger.ErrAttr(err), slog.String("side", label)}, connInfo...)...)
			}
		} else if options.Diagnostics {
			logger.Stdout.Info("no-delay not supported", append([]any{slog.String("side", label)}, connInfo...)...)
		}
	}

	if options.KeepAlive {
		if setter, ok := conn.(keepAliveSetter); ok {
			if err := setter.SetKeepAlive(true); err != nil && options.Diagnostics {
				logger.StderrWithSource.Error("failed to enable keepalive",
					append([]any{logger.ErrAttr(err), slog.String("side", label)}, connInfo...)...)
			}
		} else if options.Diagnostics {
			logger.Stdout.Info("keepalive not supported", append([]any{slog.String("side", label)}, connInfo...)...)
		}
	}

	if options.KeepAlive && options.KeepAlivePeriod > 0 {
		if setter, ok := conn.(keepAlivePeriodSetter); ok {
			if err := setter.SetKeepAlivePeriod(options.KeepAlivePeriod); err != nil && options.Diagnostics {
				logger.StderrWithSource.Error("failed to set keepalive period",
					append([]any{logger.ErrAttr(err), slog.Duration("period", options.KeepAlivePeriod), slog.String("side", label)}, connInfo...)...)
			}
		} else if options.Diagnostics {
			logger.Stdout.Info("keepalive period not supported", append([]any{slog.String("side", label)}, connInfo...)...)
		}
	}
}

func copyWithStats(dst net.Conn, src net.Conn, timeout time.Duration, bufferSize int, stats *transferStats) error {
	if bufferSize <= 0 {
		bufferSize = 32 * 1024
	}
	buffer := make([]byte, bufferSize)

	for {
		if timeout > 0 {
			_ = src.SetReadDeadline(time.Now().Add(timeout))
		}

		readBytes, readErr := src.Read(buffer)
		if readBytes > 0 {
			if stats.firstByte.IsZero() {
				stats.firstByte = time.Now()
			}

			if timeout > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(timeout))
			}

			written, writeErr := dst.Write(buffer[:readBytes])
			stats.bytes += int64(written)
			if writeErr != nil {
				return fmt.Errorf("write: %w", writeErr)
			}
			if written != readBytes {
				return io.ErrShortWrite
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return fmt.Errorf("read: %w", readErr)
		}
	}
}

func logTransferStats(stats *transferStats, connInfo []any) {
	duration := stats.end.Sub(stats.start)
	firstByteDelay := time.Duration(0)
	if !stats.firstByte.IsZero() {
		firstByteDelay = stats.firstByte.Sub(stats.start)
	}

	throughput := float64(0)
	if duration > 0 && stats.bytes > 0 {
		throughput = float64(stats.bytes) / duration.Seconds()
	}

	attrs := []any{
		slog.String("direction", stats.direction),
		slog.Int64("bytes", stats.bytes),
		slog.Duration("duration", duration),
		slog.Duration("time-to-first-byte", firstByteDelay),
		slog.Bool("saw-data", !stats.firstByte.IsZero()),
		slog.Float64("bytes-per-second", throughput),
	}

	if stats.err != nil {
		attrs = append(attrs, logger.ErrAttr(stats.err))
	}

	attrs = append(attrs, connInfo...)
	logger.Stdout.Info("tcp transfer stats", attrs...)
}
