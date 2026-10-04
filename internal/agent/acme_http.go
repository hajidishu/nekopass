package agent

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func (e *Engine) configureACME(c *pb.ControlMessage) error {
	if c.Node == nil || c.Node.Tls == nil || len(c.Node.Tls.Challenges) == 0 {
		if e.challengeServer != nil {
			e.challengeServer.Close()
			e.challengeServer = nil
		}
		return nil
	}
	if e.challengeServer!=nil{_,port,_:=net.SplitHostPort(e.challengeServer.Addr);if port!=strconv.Itoa(int(c.Node.Tls.ChallengePort)){e.challengeServer.Close();e.challengeServer=nil}}
	if e.challengeServer == nil {
		port := c.Node.Tls.ChallengePort
		if port < 1 || port > 65535 {
			return net.InvalidAddrError("invalid certificate validation port")
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(int(port))))
		if err != nil {
			return err
		}
		server := &http.Server{Addr: ln.Addr().String(), Handler: http.HandlerFunc(e.handleACME), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
		e.challengeServer = server
		e.wg.Add(1)
		go func() { defer e.wg.Done(); server.Serve(ln) }()
	}
	var ack int64
	for _, challenge := range c.Node.Tls.Challenges {
		ack = max(ack, challenge.Revision)
	}
	e.acmeAck.Store(ack)
	return nil
}
func (e *Engine) handleACME(w http.ResponseWriter, r *http.Request) {
	node := e.node.Load()
	if node == nil || node.Tls == nil || r.Method != "GET" && r.Method != "HEAD" {
		http.NotFound(w, r)
		return
	}
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	for _, challenge := range node.Tls.Challenges {
		if strings.EqualFold(host, challenge.Domain) && challenge.ExpiresUnix > time.Now().Unix() && r.URL.Path == "/.well-known/acme-challenge/"+challenge.Token {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, challenge.KeyAuthorization)
			return
		}
	}
	http.NotFound(w, r)
}
