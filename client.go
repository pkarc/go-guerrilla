package guerrilla

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"sync"
	"time"

	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
	"github.com/phires/go-guerrilla/mail/rfc5321"
	"github.com/phires/go-guerrilla/response"
)

// ClientState indicates which part of the SMTP transaction a given client is in.
type ClientState int

const (
	// The client has connected, and is awaiting our first response
	ClientGreeting = iota
	// We have responded to the client's connection and are awaiting a command
	ClientCmd
	// We have received the sender and recipient information
	ClientData
	// We have agreed with the client to secure the connection over TLS
	ClientStartTLS
	// Server will shutdown, client to shutdown on next command turn
	ClientShutdown
)

type client struct {
	*mail.Envelope
	ID          uint64
	ConnectedAt time.Time
	KilledAt    time.Time
	// Number of errors encountered during session with this client
	errors       int
	state        ClientState
	messagesSent int
	// Response to be written to the client (for debugging)
	response   bytes.Buffer
	bufErr     error
	conn       net.Conn
	bufin      *smtpBufferedReader
	bufout     *bufio.Writer
	smtpReader *textproto.Reader
	ar         *adjustableLimitedReader
	// guards access to conn
	connGuard sync.Mutex
	log       log.Logger
	parser    rfc5321.Parser
}

// NewClient allocates a new client.
func NewClient(conn net.Conn, clientID uint64, logger log.Logger, envelope *mail.Pool) *client {
	c := &client{
		conn: conn,
		// Envelope will be borrowed from the envelope pool
		// the envelope could be 'detached' from the client later when processing
		Envelope:    envelope.Borrow(getRemoteAddr(conn), clientID),
		ConnectedAt: time.Now(),
		bufin:       newSMTPBufferedReader(conn),
		bufout:      bufio.NewWriter(conn),
		ID:          clientID,
		log:         logger,
	}

	// used for reading the DATA state
	c.smtpReader = textproto.NewReader(c.bufin.Reader)
	return c
}

// sendResponse adds a response to be written on the next turn
// the response gets buffered
func (c *client) sendResponse(r ...interface{}) {
	c.bufout.Reset(c.conn)
	if c.log.IsDebug() {
		// an additional buffer so that we can log the response in debug mode only
		c.response.Reset()
	}
	var out string
	if c.bufErr != nil {
		c.bufErr = nil
	}
	for _, item := range r {
		switch v := item.(type) {
		case error:
			out = v.Error()
		case fmt.Stringer:
			out = v.String()
		case string:
			out = v
		}
		if _, c.bufErr = c.bufout.WriteString(out); c.bufErr != nil {
			c.log.WithError(c.bufErr).Error("could not write to c.bufout")
		}
		if c.log.IsDebug() {
			c.response.WriteString(out)
		}
		if c.bufErr != nil {
			return
		}
	}
	_, c.bufErr = c.bufout.WriteString("\r\n")
	if c.log.IsDebug() {
		c.response.WriteString("\r\n")
	}
}

// resetTransaction resets the SMTP transaction, ready for the next email (doesn't disconnect)
// Transaction ends on:
// -HELO/EHLO/REST command
// -End of DATA command
// TLS handshake
func (c *client) resetTransaction() {
	c.Envelope.ResetTransaction()
}

// isInTransaction returns true if the connection is inside a transaction.
// A transaction starts after a MAIL command gets issued by the client.
// Call resetTransaction to end the transaction
func (c *client) isInTransaction() bool {
	if len(c.MailFrom.User) == 0 && !c.MailFrom.NullPath {
		return false
	}
	return true
}

// kill flags the connection to close on the next turn
func (c *client) kill() {
	c.KilledAt = time.Now()
}

// isAlive returns true if the client is to close on the next turn
func (c *client) isAlive() bool {
	return c.KilledAt.IsZero()
}

// setTimeout adjust the timeout on the connection, goroutine safe
func (c *client) setTimeout(t time.Duration) (err error) {
	defer c.connGuard.Unlock()
	c.connGuard.Lock()
	if c.conn != nil {
		err = c.conn.SetDeadline(time.Now().Add(t * time.Second))
	}
	return
}

// closeConn closes a client connection, , goroutine safe
func (c *client) closeConn() {
	defer c.connGuard.Unlock()
	c.connGuard.Lock()
	_ = c.conn.Close()
	c.conn = nil
}

// init is called after the client is borrowed from the pool, to get it ready for the connection
func (c *client) init(conn net.Conn, clientID uint64, ep *mail.Pool) {
	c.conn = conn
	// reset our reader & writer
	c.bufout.Reset(conn)
	c.bufin.Reset(conn)
	// reset session data
	c.state = 0
	c.KilledAt = time.Time{}
	c.ConnectedAt = time.Now()
	c.ID = clientID
	c.errors = 0
	// borrow an envelope from the envelope pool
	c.Envelope = ep.Borrow(getRemoteAddr(conn), clientID)
}

// getID returns the client's unique ID
func (c *client) getID() uint64 {
	return c.ID
}

// UpgradeToTLS upgrades a client connection to TLS
func (c *client) upgradeToTLS(tlsConfig *tls.Config) error {
	// wrap c.conn in a new TLS server side connection
	tlsConn := tls.Server(c.conn, tlsConfig)
	// Call handshake here to get any handshake error before reading starts
	err := tlsConn.Handshake()
	if err != nil {
		return err
	}
	// convert tlsConn to net.Conn
	c.conn = net.Conn(tlsConn)
	c.bufout.Reset(c.conn)
	c.bufin.Reset(c.conn)
	c.TLS = true
	return err
}

func getRemoteAddr(conn net.Conn) string {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		// we just want the IP (not the port)
		return addr.IP.String()
	} else {
		return conn.RemoteAddr().Network()
	}
}

type pathParser func([]byte) error

func (c *client) parsePath(in []byte, p pathParser) (mail.Address, error) {
	address := mail.Address{}
	var err error
	if len(in) > rfc5321.LimitPath {
		return address, errors.New(response.Canned.FailPathTooLong.String())
	}
	if err = p(in); err != nil {
		return address, errors.New(response.Canned.FailInvalidAddress.String())
	} else if c.parser.NullPath {
		// bounce has empty from address
		address = mail.Address{}
	} else if len(c.parser.LocalPart) > rfc5321.LimitLocalPart {
		err = errors.New(response.Canned.FailLocalPartTooLong.String())
	} else if len(c.parser.Domain) > rfc5321.LimitDomain {
		err = errors.New(response.Canned.FailDomainTooLong.String())
	} else {
		address = mail.Address{
			User:       c.parser.LocalPart,
			Host:       c.parser.Domain,
			ADL:        c.parser.ADL,
			PathParams: c.parser.PathParams,
			NullPath:   c.parser.NullPath,
			Quoted:     c.parser.LocalPartQuotes,
			IP:         c.parser.IP,
		}
	}
	return address, err
}

type proxyHeader struct {
	Sig        [12]uint8
	Ver_cmd    uint8
	Family     uint8
	AddrLength uint16
}

type proxyAddressIPv4 struct {
	SrcAddr  uint32
	DestAddr uint32
	SrcPort  uint16
	DestPort uint16
}

type proxyAddressIPv6 struct {
	SrcAddr  [16]uint8
	DestAddr [16]uint8
	SrcPort  uint16
	DestPort uint16
}

const (
	// ProxyProtocolVersion2 is the version of the proxy protocol
	ProxyProtocolVersion2 = 0x02

	ProxyProtocolCommandLocal = 0x00
	ProxyProtocolCommandProxy = 0x01

	ProxyProtocolFamilyTCPv4 = 0x11 //TCP over IPv4
	ProxyProtocolFamilyTCPv6 = 0x21 //TCP over IPv6
)

var ppV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// Reads from the client until a \n terminator is encountered,
// or until a timeout occurs.
func (c *client) parseProxyProtocol() error {

	hb := make([]byte, 16)

	n, err := c.bufin.Read(hb)
	if err != nil {
		return err
	}

	c.log.Debugf("ProxyProtocol header: %x", hb)

	if n >= 16 && bytes.Contains(hb, []byte(ppV2Signature)) {

		proxyHeader := &proxyHeader{}
		err = binary.Read(bytes.NewReader(hb), binary.BigEndian, proxyHeader)
		if err != nil {
			return err
		}

		switch proxyHeader.Ver_cmd & 0xF {
		case ProxyProtocolCommandProxy:

			ab := make([]byte, proxyHeader.AddrLength)

			_, err := c.bufin.Read(ab)
			if err != nil {
				return err
			}

			c.log.Debugf("ProxyProtocol address: %x", ab)

			switch proxyHeader.Family {
			case ProxyProtocolFamilyTCPv4:
				proxyAddressIPv4 := &proxyAddressIPv4{}

				err = binary.Read(bytes.NewReader(ab), binary.BigEndian, proxyAddressIPv4)
				if err != nil {
					return err
				}

				ipv4 := make([]byte, 4)

				// convert the address to a byte array
				binary.BigEndian.PutUint32(ipv4, proxyAddressIPv4.SrcAddr)
				// replace the remote address with the proxy address
				c.RemoteIP = net.IP(ipv4).String()

			case ProxyProtocolFamilyTCPv6:
				proxyAddressIPv6 := &proxyAddressIPv6{}

				err = binary.Read(bytes.NewReader(ab), binary.BigEndian, proxyAddressIPv6)
				if err != nil {
					return err
				}

				ipv6 := make([]byte, 16)

				// convert the address to a byte array
				copy(ipv6, proxyAddressIPv6.SrcAddr[:])
				// replace the remote address with the proxy address
				c.RemoteIP = net.IP(ipv6).String()

			default:
				return errors.New("wrong protocol version/command")
			}

			return nil

		case ProxyProtocolCommandLocal:
			// do nothing, keep local connection address for LOCAL
			return nil
		default:
			return errors.New("wrong protocol version/command")
		}
	} else if n >= 8 && bytes.Contains(hb, []byte("PROXY ")) {
		//TODO: parse proxy protocol v1
		return nil
	} else {
		return errors.New("wrong protocol")
	}
}

func (s *server) rcptTo() (address mail.Address, err error) {
	return address, err
}
