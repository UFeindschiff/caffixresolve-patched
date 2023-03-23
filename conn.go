// Copyright © by Jeff Foley 2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"fmt"
	"net"
	"sync"
	"time"
	"strings"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
)

const maxUDPBufferSize = 64 * 1024 * 1024

type resp struct {
	Msg  *dns.Msg
	Addr *net.UDPAddr
}

type connections struct {
	sync.Mutex
	done      chan struct{}
	conns     []*net.UDPConn
	resps     queue.Queue
	rbufSize  int
	wbufSize  int
	nextWrite int
}

func newConnections(cpus int, resps queue.Queue) *connections {
	conns := &connections{
		done:  make(chan struct{}, 1),
		resps: resps,
	}

	for i := 0; i < cpus; i++ {
		if err := conns.Add(); err != nil {
			conns.Close()
			return nil
		}
	}
	return conns
}

func (c *connections) Close() {
	select {
	case <-c.done:
		return
	default:
	}
	close(c.done)
	for _, conn := range c.conns {
		conn.Close()
	}
}

func (c *connections) Next() *net.UDPConn {
	c.Lock()
	defer c.Unlock()

	cur := c.nextWrite
	c.nextWrite = (c.nextWrite + 1) % len(c.conns)
	return c.conns[cur]
}

func (c *connections) Add() error {
	var err error
	var addr *net.UDPAddr
	var conn *net.UDPConn

	if addr, err = net.ResolveUDPAddr("udp", ":0"); err == nil {
		if conn, err = net.ListenUDP("udp", addr); err == nil {
			_ = conn.SetDeadline(time.Time{})
			c.setMaxReadBufSize(conn)
			c.setMaxWriteBufSize(conn)
			c.conns = append(c.conns, conn)
			go c.responses(conn)
		}
	}
	return err
}

func (c *connections) WriteMsg(msg *dns.Msg, addr *net.UDPAddr) error {
	var n int
	var err error
	var out []byte

	if out, err = msg.Pack(); err == nil {
		conn := c.Next()

		conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err = conn.WriteToUDP(out, addr); err == nil && n < len(out) {
			err = fmt.Errorf("only wrote %d bytes of the %d byte message", n, len(out))
		}
	}
	return err
}

func (c *connections) responses(conn *net.UDPConn) {
	b := make([]byte, dns.DefaultMsgSize)

	for {
		select {
		case <-c.done:
			return
		default:
		}
		if n, addr, err := conn.ReadFromUDP(b); err == nil && n >= headerSize {
			m := new(dns.Msg)

			if err := m.Unpack(b[:n]); err == nil && len(m.Question) > 0 {
				if m.MsgHdr.Rcode == dns.RcodeServerFailure && !strings.Contains(m.Question[0].Name, "o-o.myaddr.l.google.com") {
					fmt.Println("Got SRVFAIL for " + sprintName(m.Question[0].Name))
					fmt.Println("Adding to blacklist...")
					registerSrvFail(sprintName(m.Question[0].Name))
				}
				c.resps.Append(&resp{
					Msg:  m,
					Addr: addr,
				})
			}
		}
	}
}

const (
	escapedByteSmall = "" +
		`\000\001\002\003\004\005\006\007\008\009` +
		`\010\011\012\013\014\015\016\017\018\019` +
		`\020\021\022\023\024\025\026\027\028\029` +
		`\030\031`
	escapedByteLarge = `\127\128\129` +
		`\130\131\132\133\134\135\136\137\138\139` +
		`\140\141\142\143\144\145\146\147\148\149` +
		`\150\151\152\153\154\155\156\157\158\159` +
		`\160\161\162\163\164\165\166\167\168\169` +
		`\170\171\172\173\174\175\176\177\178\179` +
		`\180\181\182\183\184\185\186\187\188\189` +
		`\190\191\192\193\194\195\196\197\198\199` +
		`\200\201\202\203\204\205\206\207\208\209` +
		`\210\211\212\213\214\215\216\217\218\219` +
		`\220\221\222\223\224\225\226\227\228\229` +
		`\230\231\232\233\234\235\236\237\238\239` +
		`\240\241\242\243\244\245\246\247\248\249` +
		`\250\251\252\253\254\255`
)

func sprintName(s string) string {
	var dst strings.Builder

	for i := 0; i < len(s); {
		if s[i] == '.' {
			if dst.Len() != 0 {
				dst.WriteByte('.')
			}
			i++
			continue
		}

		b, n := nextByte(s, i)
		if n == 0 {
			// Drop "dangling" incomplete escapes.
			if dst.Len() == 0 {
				return s[:i]
			}
			break
		}
		if isDomainNameLabelSpecial(b) {
			if dst.Len() == 0 {
				dst.Grow(len(s) * 2)
				dst.WriteString(s[:i])
			}
			dst.WriteByte('\\')
			dst.WriteByte(b)
		} else if b < ' ' || b > '~' { // unprintable, use \DDD
			if dst.Len() == 0 {
				dst.Grow(len(s) * 2)
				dst.WriteString(s[:i])
			}
			dst.WriteString(escapeByte(b))
		} else {
			if dst.Len() != 0 {
				dst.WriteByte(b)
			}
		}
		i += n
	}
	if dst.Len() == 0 {
		return s
	}
	return dst.String()
}

func nextByte(s string, offset int) (byte, int) {
	if offset >= len(s) {
		return 0, 0
	}
	if s[offset] != '\\' {
		// not an escape sequence
		return s[offset], 1
	}
	switch len(s) - offset {
	case 1: // dangling escape
		return 0, 0
	case 2, 3: // too short to be \ddd
	default: // maybe \ddd
		if isDigit(s[offset+1]) && isDigit(s[offset+2]) && isDigit(s[offset+3]) {
			return dddStringToByte(s[offset+1:]), 4
		}
	}
	// not \ddd, just an RFC 1035 "quoted" character
	return s[offset+1], 2
}

func dddStringToByte(s string) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func isDomainNameLabelSpecial(b byte) bool {
	switch b {
	case '.', ' ', '\'', '@', ';', '(', ')', '"', '\\':
		return true
	}
	return false
}

func escapeByte(b byte) string {
	if b < ' ' {
		return escapedByteSmall[b*4 : b*4+4]
	}

	b -= '~' + 1
	// The cast here is needed as b*4 may overflow byte.
	return escapedByteLarge[int(b)*4 : int(b)*4+4]
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9' 
}

func (c *connections) setMaxReadBufSize(conn *net.UDPConn) {
	c.Lock()
	defer c.Unlock()

	if c.rbufSize != 0 {
		_ = conn.SetReadBuffer(c.rbufSize)
		return
	}

	min := 1024
	for size := maxUDPBufferSize; size > min; size /= 2 {
		if err := conn.SetReadBuffer(size); err == nil {
			c.rbufSize = size
			return
		}
	}
}

func (c *connections) setMaxWriteBufSize(conn *net.UDPConn) {
	c.Lock()
	defer c.Unlock()

	if c.wbufSize != 0 {
		_ = conn.SetWriteBuffer(c.wbufSize)
		return
	}

	min := 1024
	for size := maxUDPBufferSize; size > min; size /= 2 {
		if err := conn.SetWriteBuffer(size); err == nil {
			c.wbufSize = size
			return
		}
	}
}
