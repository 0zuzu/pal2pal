// Minimal libp2p messenger skeleton (single-file)
// ------------------------------------------------
// Purpose: a minimal, practical starting point for a peer-to-peer chat node in Go
// - Uses libp2p (go-libp2p) with Noise (security), Yamux (muxer), Relay enabled, and mDNS for LAN discovery.
// - Sets a custom protocol `/p2pchat/1.0.0` and handles incoming streams.
// - Prints listen addresses (multiaddrs) so you can create an "invite" by sharing a multiaddr + peer ID.
// - Provides simple interactive commands via stdin: `peers`, `dial <multiaddr>`, `send <peerID> <message>`, `quit`.
//
// Notes:
// - This is intentionally small and synchronous for clarity. For production, split into packages, add error handling,
// persistent key storage, encrypted on-disk storage, background reconnection, UI, file transfer, and tests.
// - Replace or augment transports (QUIC, WebRTC), add AutoRelay settings, implement TURN relays, or integrate a
// rendezvous server for invite/QR flows
package p2p

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	yamux "github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"

	"github.com/0zuzu/pal2pal/utils"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	network "github.com/libp2p/go-libp2p/core/network"
	peer "github.com/libp2p/go-libp2p/core/peer"
	peerstore "github.com/libp2p/go-libp2p/core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	ProtocolID     = "/palchat/1.0.0"
	MdnsServiceTag = "palchat-mdns"
)

// Simple in-memory set of discovered peers (populated by mDNS)
type PeerStore struct {
	mu    sync.RWMutex
	peers map[peer.ID]peer.AddrInfo
}

func NewPeerStore() *PeerStore {
	return &PeerStore{peers: make(map[peer.ID]peer.AddrInfo)}
}

func (ps *PeerStore) Add(pi peer.AddrInfo) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.peers[pi.ID] = pi
}

func (ps *PeerStore) List() []peer.AddrInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]peer.AddrInfo, 0, len(ps.peers))
	for _, v := range ps.peers {
		out = append(out, v)
	}
	return out
}

// mdnsNotifee receives discovered peers from mDNS and stores them
type mdnsNotifee struct {
	host  host.Host
	store *PeerStore
}

func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	// Optionally try to connect immediately
	fmt.Printf("[mDNS] Discovered peer %s at %v\n", pi.ID, pi.Addrs)
	// Save to our own peerstore
	n.store.Add(pi)

	go func() {
		if err := n.host.Connect(context.Background(), pi); err != nil {
			fmt.Printf("[mDNS] Connect failed: %s\n", err)
		} else {
			fmt.Printf("[mDNS] Connected to %s\n", pi.ID)
		}
	}()
}

// Invite format (simple JSON). In production you'd sign this.
type Invite struct {
	PeerID    string   `json:"peer_id"`
	Addrs     []string `json:"addrs"`
	Timestamp int64    `json:"ts"`
}

func Start() {
	ctx := context.Background()
	ps := NewPeerStore()
	// 1) generate an identity (persist this in real apps)
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		panic(err)
	}
	// 2) connection manager (limits)
	cm, _ := connmgr.NewConnManager(100, 400)
	// 3) construct libp2p host with Noise security, Yamux muxer, Relay enabled, and conn manager
	host, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ConnectionManager(cm),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		libp2p.NATPortMap(),
		libp2p.EnableHolePunching(),
		libp2p.EnableAutoNATv2(),
	)
	if err != nil {
		panic(err)
	}
	host.SetStreamHandler(ProtocolID, handleIncomingStream)

	defer host.Close()

	// 4) show listen addresses & peer ID (this can be converted to an invite/QR)
	fmt.Println("=== Node started ===")
	fmt.Println("Peer ID:", host.ID())
	fmt.Println("Addresses:")
	for _, a := range host.Addrs() {
		fmt.Printf(" %s/p2p/%s\n", a, host.ID())
	}
	fmt.Println("===================")

	// 5) Start mDNS for LAN peer discovery
	mdnsSvc := mdns.NewMdnsService(host, MdnsServiceTag, &mdnsNotifee{host: host, store: ps})
	if err := mdnsSvc.Start(); err != nil {
		panic(err)
	}

	// 7) interactive CLI
	scanner := bufio.NewScanner(os.Stdin)
	printHelp()
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		switch parts[0] {
		case "help":
			printHelp()
		case "peers":
			list := ps.List()
			if len(list) == 0 {
				fmt.Println("(no peers discovered)")
			}
			for _, pi := range list {
				fmt.Printf("%s -> %v\n", pi.ID, pi.Addrs)
			}
		case "invite":
			// 1. Create the Invite struct
			ex := Invite{
				PeerID:    host.ID().String(),
				Timestamp: time.Now().Unix(),
			}
			// 2. Add all listen addresses
			for _, a := range host.Addrs() {
				ex.Addrs = append(ex.Addrs, a.String())
			}
			// 3. Marshal to JSON
			b, err := json.Marshal(ex)
			if err != nil {
				fmt.Println("Error creating invite:", err)
				continue
			}
			// 4. Encode to Base64 (makes it a safe, single string for the CLI)
			b64Token := base64.StdEncoding.EncodeToString(b)
			fmt.Println("--- Copy this Invite Token ---")
			fmt.Println(b64Token)
			fmt.Println("------------------------------")

		case "dial":
			if len(parts) < 2 {
				fmt.Println("usage: dial <invite-token>")
				continue
			}
			tokenStr := parts[1]

			// 1. Decode Base64
			jsonBytes, err := base64.StdEncoding.DecodeString(tokenStr)
			if err != nil {
				fmt.Println("invalid token format (not base64):", err)
				continue
			}

			// 2. Unmarshal JSON
			var inv Invite
			if err := json.Unmarshal(jsonBytes, &inv); err != nil {
				fmt.Println("invalid token content (not json):", err)
				continue
			}

			// 3. Decode the PeerID string into a proper ID object
			targetPeerID, err := peer.Decode(inv.PeerID)
			if err != nil {
				fmt.Println("invalid peer ID in token:", err)
				continue
			}

			// 4. Construct AddrInfo (PeerID + List of Multiaddrs)
			var addrInfo peer.AddrInfo
			addrInfo.ID = targetPeerID

			for _, addrStr := range inv.Addrs {
				maddr, err := ma.NewMultiaddr(addrStr)
				if err != nil {
					fmt.Println("skipping invalid addr:", addrStr)
					continue
				}
				addrInfo.Addrs = append(addrInfo.Addrs, maddr)
			}

			// 5. Add these addresses to the PeerStore so libp2p knows how to reach them
			//    This effectively "shortens" the dial command for the user.
			host.Peerstore().AddAddrs(targetPeerID, addrInfo.Addrs, peerstore.PermanentAddrTTL)

			fmt.Printf("Attempting to connect to %s using %d addresses...\n", targetPeerID, len(addrInfo.Addrs))

			// 6. Connect!
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
			defer cancel()

			if err := host.Connect(ctx, addrInfo); err != nil {
				fmt.Println("Connection failed:", err)
			} else {
				fmt.Println("SUCCESS! Connected to:", targetPeerID)
			}
		case "send":
			if len(parts) < 3 {
				fmt.Println("usage: send <peerID> <message>")
				continue
			}
			peeridStr := parts[1]
			msg := parts[2]
			pid, err := peer.Decode(peeridStr)
			if err != nil {
				fmt.Println("invalid peer id")
				continue
			}
			s, err := host.NewStream(ctx, pid, ProtocolID)
			if err != nil {
				fmt.Println("open stream error:", err)
				continue
			}
			_, _ = s.Write([]byte(msg + "\n"))
			s.Close()
		case "quit", "exit":
			fmt.Println("shutting down...")
			return
		default:
			fmt.Println("unknown command; type 'help'")
		}
	}
}
func printHelp() {
	fmt.Println("Commands:")
	fmt.Println(" help - show this help")
	fmt.Println(" peers - list discovered peers (mDNS)")
	fmt.Println(" invite - print an invite token with your peer ID & addresses")
	fmt.Println(" dial <multiaddr> - dial a peer using a multiaddr (copy from someone's addresses)")
	fmt.Println(" send <peerID> <message> - send a single-line chat message to peer")
	fmt.Println(" quit - exit")
}

func handleIncomingStream(s network.Stream) {
	defer s.Close()
	r := bufio.NewReader(s)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		fmt.Printf("<%s> %s", s.Conn().RemotePeer(), line)
	}
}

func newIdentity() utils.Identity {
	priv, _, _ := crypto.GenerateEd25519Key(rand.Reader)
	var output utils.Identity
	output.PeerID = priv
	output.Alias = "OZUMA AlABAMA"
	output.Birth = time.Now().Unix()
	return output
}
