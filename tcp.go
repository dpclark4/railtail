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

type tcpForwardOptions struct {
	Diagnostics bool
	DialTimeout time.Duration
	IOTimeout   time.Duration
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

	g, _ := errgroup.WithContext(ctx)

	toTailnet := transferStats{direction: "client_to_tailnet"}
	fromTailnet := transferStats{direction: "tailnet_to_client"}

	g.Go(func() error {
		toTailnet.start = time.Now()
		defer func() {
			toTailnet.end = time.Now()
		}()

		err := copyWithStats(tsConn, lstConn, options.IOTimeout, &toTailnet)
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

		err := copyWithStats(lstConn, tsConn, options.IOTimeout, &fromTailnet)
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

func copyWithStats(dst net.Conn, src net.Conn, timeout time.Duration, stats *transferStats) error {
	buffer := make([]byte, 32*1024)

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

	attrs := []any{
		slog.String("direction", stats.direction),
		slog.Int64("bytes", stats.bytes),
		slog.Duration("duration", duration),
		slog.Duration("time-to-first-byte", firstByteDelay),
		slog.Bool("saw-data", !stats.firstByte.IsZero()),
	}

	if stats.err != nil {
		attrs = append(attrs, logger.ErrAttr(stats.err))
	}

	attrs = append(attrs, connInfo...)
	logger.Stdout.Info("tcp transfer stats", attrs...)
}
