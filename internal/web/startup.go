package web

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
)

// The daemon opens the console's listener before it opens and migrates the
// database, so that GET /healthz tells a long upgrade apart from a daemon
// that is down. Until the console's server takes the listener over, the
// startup server answers it: /healthz, /metrics when it is enabled, and 503
// starting for every other path. It reads the health through a read-only
// handle of the database, which never migrates or writes, and has no store,
// no session, and no console.

// startupShutdownTimeout bounds the wait for the startup server's requests
// when the console's server takes the listener over, or when the start
// fails.
const startupShutdownTimeout = 5 * time.Second

// StartupListener is the console's listener while the daemon opens and
// migrates the database, served by the startup server.
type StartupListener struct {
	address string
	handoff *listenerHandoff
	server  *http.Server
	// served is closed once the startup server has stopped serving.
	served chan struct{}
	stop   sync.Once
	// mu guards taken, which records that the console's server took the
	// listener over or that Close closed it.
	mu    sync.Mutex
	taken bool
}

// ListenForStartup opens the console's listener on settings.Listen, as
// Server.ListenAndServe would, and serves it with the startup server, which
// reads the health of the database at database. The startup server limits
// and identifies clients like the console's server, with the forwarding
// settings of settings, and serves /metrics with its bearer token.
func ListenForStartup(settings config.Web, database, version string, logger *slog.Logger) (*StartupListener, error) {
	if logger == nil {
		logger = slog.Default()
	}
	listener, address, err := listenConsole(settings.Listen)
	if err != nil {
		return nil, err
	}
	return serveStartup(listener, address, newStartupServer(settings, database, version, logger)), nil
}

// serveStartup serves listener, which listens on address, with the startup
// server.
func serveStartup(listener net.Listener, address string, server *Server) *StartupListener {
	logger := server.Log
	handoff := newListenerHandoff(listener)
	startup := &StartupListener{
		address: address,
		handoff: handoff,
		server:  &http.Server{Handler: server.startupHandler(), ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: defaultHTTPWriteTimeout, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10},
		served:  make(chan struct{}),
	}
	view := handoff.view(false)
	go func() {
		defer close(startup.served)
		_ = startup.server.Serve(view)
	}()
	logger.Info("web interface answers health checks while the daemon starts", "address", address)
	return startup
}

// newStartupServer returns the startup server: a Server without an
// application or a store, which serves only the health and the metrics.
func newStartupServer(settings config.Web, database, version string, logger *slog.Logger) *Server {
	if version == "" {
		version = "dev"
	}
	s := &Server{Auth: auth.NewManager(nil), Log: logger, Version: version, now: time.Now, startupDatabase: database}
	// The console's server logs a rejected setting once it starts.
	_ = s.Auth.SetTrustedProxies(settings.TrustedProxies)
	_ = s.Auth.SetForwardedHeader(settings.ForwardedHeader)
	_ = s.Auth.SetIPv6RateLimitPrefix(settings.RateLimitIPv6Prefix())
	s.configureMetrics(settings.Metrics)
	return s
}

// startupHandler serves the listener while the daemon starts: /healthz and
// /metrics as the console's server does, and every other path, the console
// and both APIs, with 503 starting and a fixed body.
func (s *Server) startupHandler() http.Handler {
	return s.requestLogging(securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			s.healthz(w, r)
		case "/metrics":
			s.metricsEndpoint(w, r)
		default:
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "starting", "EdgeWatch is starting; try again shortly", nil)
		}
	})))
}

// stopStartupServer stops the startup server, waiting for its requests for
// at most startupShutdownTimeout, also when ctx has ended. The listener
// stays open.
func (l *StartupListener) stopStartupServer(ctx context.Context) {
	l.stop.Do(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), startupShutdownTimeout)
		defer cancel()
		_ = l.server.Shutdown(ctx)
		<-l.served
	})
}

// Close stops the startup server and closes the listener, for a start that
// fails before the console's server has taken the listener over. After
// ServeStartupListener it does nothing.
func (l *StartupListener) Close() error {
	if l == nil {
		return nil
	}
	l.stopStartupServer(context.Background())
	if !l.take() {
		return nil
	}
	return l.handoff.close()
}

// take reports whether the listener was neither taken over nor closed yet,
// and records that it now is.
func (l *StartupListener) take() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.taken {
		return false
	}
	l.taken = true
	return true
}

// ServeStartupListener serves the console on the listener that
// ListenForStartup opened, as ListenAndServe serves its own: it stops the
// startup server, whose requests finish first, and then serves every
// request on the listener with the console's handler. Connections that
// arrive in between wait in the listener's queue.
func (s *Server) ServeStartupListener(ctx context.Context, startup *StartupListener) error {
	startup.stopStartupServer(ctx)
	if !startup.take() {
		return net.ErrClosed
	}
	return s.serveListener(ctx, startup.handoff.view(true), startup.address, s.Handler())
}

// listenerHandoff accepts the connections of one listener and hands each to
// the server that serves the listener at the time: the startup server, and
// then the console's. A server's view of the listener closes without
// closing the listener, so the next server goes on accepting from it.
type listenerHandoff struct {
	listener  net.Listener
	accepted  chan acceptedConn
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// acceptedConn is the result of one Accept of the listener.
type acceptedConn struct {
	conn net.Conn
	err  error
}

func newListenerHandoff(listener net.Listener) *listenerHandoff {
	h := &listenerHandoff{listener: listener, accepted: make(chan acceptedConn), closed: make(chan struct{})}
	go h.accept()
	return h
}

// accept accepts connections until the listener is closed. It accepts the
// next one only once a server has taken the last, so connections wait in
// the listener's queue while no server accepts.
func (h *listenerHandoff) accept() {
	for {
		conn, err := h.listener.Accept()
		select {
		case h.accepted <- acceptedConn{conn: conn, err: err}:
		case <-h.closed:
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

// close closes the listener.
func (h *listenerHandoff) close() error {
	h.closeOnce.Do(func() {
		close(h.closed)
		h.closeErr = h.listener.Close()
	})
	return h.closeErr
}

// view returns a listener that accepts the handoff's connections until it
// is closed. Closing a view that owns the listener closes the listener too.
func (h *listenerHandoff) view(owner bool) net.Listener {
	return &handoffView{handoff: h, done: make(chan struct{}), owner: owner}
}

// handoffView is one server's view of a listenerHandoff.
type handoffView struct {
	handoff *listenerHandoff
	done    chan struct{}
	once    sync.Once
	owner   bool
}

func (v *handoffView) Accept() (net.Conn, error) {
	select {
	case <-v.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case result := <-v.handoff.accepted:
		return result.conn, result.err
	case <-v.done:
		return nil, net.ErrClosed
	case <-v.handoff.closed:
		return nil, net.ErrClosed
	}
}

func (v *handoffView) Close() error {
	v.once.Do(func() { close(v.done) })
	if v.owner {
		return v.handoff.close()
	}
	return nil
}

func (v *handoffView) Addr() net.Addr {
	return v.handoff.listener.Addr()
}
