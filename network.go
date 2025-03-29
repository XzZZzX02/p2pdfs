package p2pdf

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/XzZZzX02/p2pdfs/crypto"
	"github.com/XzZZzX02/p2pdfs/database"

	"github.com/libp2p/go-libp2p"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	libp2pCrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
)

const (
	commitBodyProtocolID = "p2pdfs/commit-body/0.1"
	pubsubTopicPrefix    = "p2pdfs/commits"
	discoveryServiceTag  = "p2pdfs-discovery"
)

// nFS wraps IFS and implements network operations
type NetworkedFS struct {
	IFS
	localFS *fileSystem

	host   host.Host
	pubsub *pubsub.PubSub
	topic  *pubsub.Topic
	sub    *pubsub.Subscription
	dht    *dht.IpfsDHT

	fsID string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NetworkOptions
type NetworkOptions struct {
	ListionAddrs   []string
	BootstrapPeers []peer.AddrInfo
	UesDHT         bool
	PrivateKey     crypto.PrivateKey
}

// Creates or opens networkFS
func OpenNetworkFS(ctx context.Context, pub crypto.PublicKey, db database.Storage, opts NetworkOptions) (*NetworkedFS, error) {
	// 1. Open the local file system
	localFS, err := OpenFS(pub, db)
	if err != nil {
		return nil, err
	}

	fsImpl, ok := localFS.(*fileSystem)
	if !ok {
		return nil, fmt.Errorf("underlying IFS implementation is not *fileSystem")
	}

	fsID := hex.EncodeToString(pub)
	log.Printf("Initializing NetworkedFS for FS ID: %s\n", fsID)

	// 2. Setup libp2p Host
	libp2pOpts := []libp2p.Option{
		libp2p.ListenAddrStrings(opts.ListionAddrs...),
		libp2p.DefaultSecurity,
		libp2p.DefaultMuxers,
	}

	if opts.PrivateKey != nil {
		libp2pPrivKey, err := libp2pCrypto.UnmarshalEd25519PrivateKey(opts.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal private key for libp2p identity: %w", err)
		}
		log.Println("Using provided private key for libp2p host identity.")
		libp2pOpts = append(libp2pOpts, libp2p.Identity(libp2pPrivKey))
	} else {
		log.Println("No private key provided for libp2p host, generating a new one.")
		// Let libp2p generate a default identity if none is provided
	}
	host, err := libp2p.New(libp2pOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}
	log.Printf("Libp2p Host created with ID: %s\n", host.ID())
	log.Printf("Listening on: %v\n", host.Addrs())

	// 3. Setup Context and NetworkedFS struct
	nfsCtx, cancel := context.WithCancel(ctx)
	nfs := &NetworkedFS{
		IFS:     localFS,
		localFS: fsImpl,
		host:    host,
		fsID:    fsID,
		ctx:     nfsCtx,
		cancel:  cancel,
	}

	// 4. Setup PubSub
	ps, err := pubsub.NewGossipSub(nfsCtx, host)
	if err != nil {
		nfs.Close()
		return nil, fmt.Errorf("failed to create PubSub: %w", err)
	}
	nfs.pubsub = ps

	// 5. Join the topic
	topicName := pubsubTopicPrefix + "/" + nfs.fsID
	topic, err := ps.Join(topicName)
	if err != nil {
		nfs.Close()
		return nil, fmt.Errorf("failed to join PubSub topic: %w", err)
	}
	nfs.topic = topic
	log.Printf("Joined PubSub topic: %s\n", topicName)

	// 6. Subscribe to the topic
	sub, err := topic.Subscribe()
	if err != nil {
		nfs.Close()
		return nil, fmt.Errorf("failed to subscribe to PubSub topic: %w", err)
	}
	nfs.sub = sub

	// Start background goroutine to handle incoming pubsub messages
	nfs.wg.Add(1)
	go nfs.pubsubHandler()

	// 7. Set stream handler
	host.SetStreamHandler(commitBodyProtocolID, nfs.commitBodyStreamHandler)
	log.Printf("Stream handler set for protocol: %s\n", commitBodyProtocolID)

	// 8. Setup Discovery
	if opts.UesDHT || len(opts.BootstrapPeers) > 0 {
		if err := nfs.setupDHTAndBootstrap(opts.BootstrapPeers); err != nil {
			nfs.Close()
			return nil, fmt.Errorf("failed to setup DHT and bootstrap: %w", err)
		}
	}

	// Setup mDNS
	if err := nfs.setupMDNS(); err != nil {
		log.Printf("Warning: Failed to set up mDNS discovery: %v\n", err)
	}

	return nfs, nil
}

func (nfs *NetworkedFS) setupDHTAndBootstrap(BootstrapPeers []peer.AddrInfo) error {
	log.Printf("Setting up DHT and Bootstrap...")
	// Start a DHT
	kademliaDHT, err := dht.New(nfs.ctx, nfs.host)
	if err != nil {
		return fmt.Errorf("failed to create DHT: %w", err)
	}
	nfs.dht = kademliaDHT

	// Bootstrap the DHT. In the default configuration, this spawns a Background
	// thread that will refresh the peer table every five minutes.
	log.Println("Bootstrapping DHT...")
	if err = kademliaDHT.Bootstrap(nfs.ctx); err != nil {
		return fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// Connect to Bootstrap peers
	if len(BootstrapPeers) > 0 {
		log.Printf("Connecting to %d bootstrap peers...\n", len(BootstrapPeers))
		var wg sync.WaitGroup
		for _, pinfo := range BootstrapPeers {
			wg.Add(1)
			go func(pi peer.AddrInfo) {
				defer wg.Done()
				err := nfs.host.Connect(nfs.ctx, pi)
				if err != nil {
					log.Printf("Failed to connect to bootstrap peer %s: %v\n", pi.ID, err)
				} else {
					log.Printf("Connected to bootstrap peer %s\n", pi.ID)
				}
			}(pinfo)
		}
		wg.Wait()
	} else {
		log.Println("No bootstrap peers provided.")
	}
	return nil
}

func (nfs *NetworkedFS) setupMDNS() error {
	log.Printf("Setting up mDNS discovery...")
	s := mdns.NewMdnsService(nfs.host, discoveryServiceTag, nfs)
	return s.Start()
}

func (nfs *NetworkedFS) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == nfs.host.ID() {
		return
	}
	log.Printf("Found peer: %s\n", pi.ID)
	err := nfs.host.Connect(nfs.ctx, pi)
	if err != nil {
		log.Printf("Failed to connect to peer %s: %v\n", pi.ID, err)
	} else {
		log.Printf("Connected to peer %s\n", pi.ID)
	}
}

func (nfs *NetworkedFS) Close() error {
	log.Printf("Closing NetworkedFS...")
	nfs.cancel()

	if nfs.sub != nil {
		nfs.sub.Cancel()
	}

	if nfs.topic != nil {
		nfs.topic.Close()
	}

	// Wait for background goroutines to finish
	// Add a timeout to prevent hanging indefinitely
	waitChan := make(chan struct{})
	go func() {
		nfs.wg.Wait()
		close(waitChan)
	}()
	select {
	case <-waitChan:
		log.Printf("All background goroutines finished.")
	case <-time.After(5 * time.Second):
		log.Println("Warning: Timeout waiting for background goroutines to finish.")
	}

	if nfs.dht != nil {
		if err := nfs.dht.Close(); err != nil {
			log.Printf("Warning: Error closing DHT: %v\n", err)
		}
	}

	if closer, ok := nfs.IFS.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			log.Printf("Warning: Error closing IFS: %v\n", err)
		}
	}

	err := nfs.host.Close()
	log.Printf("NetworkedFS closed: %v\n", err)
	return err
}

func (nfs *NetworkedFS) Commit(commit *Commit) error {
	// 1. Apply the commit locally first
	// Need to read the body for local commit, but keep it available for potential network requests later.
	// This is tricky because the original commit.Body is an io.ReadCloser.
	// Maybe the local Commit should handle reading/storing the data,
	// and the network part retrieves it from the DB when needed.

	// Let's assume the embedded IFS.Commit handles consuming the body and storing files.
	log.Printf("NetworkedFS: Attempting to apply local commit Ver %d\n", commit.Ver())
	err := nfs.IFS.Commit(commit) // This will consume commit.Body
	if err != nil {
		log.Printf("NetworkedFS: Failed to apply commit locally: %v\n", err)
		return fmt.Errorf("local commit failed: %w", err)
	}
	log.Printf("NetworkedFS: Successfully applied local commit Ver %d\n", commit.Ver())

	// 2. If local commit succeeded, publish headers
	// We need to re-create a commit structure *just* with headers for publishing.
	// The original commit.Body has been consumed by the local Commit call.
	// Important: Clone headers to avoid race conditions if original commit struct is modified.
	publishHeaders := make([]Header, len(commit.Headers))
	for i, h := range commit.Headers {
		publishHeaders[i] = h.Copy() // Ensure we have copies
	}

	if err := nfs.publishCommitHeaders(publishHeaders); err != nil {
		// Log the error, but don't fail the whole operation if publishing fails
		log.Printf("Warning: Failed to publish commit headers (Ver %d): %v\n", commit.Ver(), err)
	} else {
		log.Printf("NetworkedFS: Published commit headers Ver %d to topic %s\n", commit.Ver(), nfs.topic.String())
	}

	return nil
}

// publishCommitHeaders serializes and publishes commit headers via pubsub.
func (nfs *NetworkedFS) publishCommitHeaders(headers []Header) error {
	// Check context before proceeding
	select {
	case <-nfs.ctx.Done():
		return nfs.ctx.Err()
	default:
	}

	data, err := json.Marshal(headers)
	if err != nil {
		return fmt.Errorf("failed to marshal commit headers: %w", err)
	}

	// Add a small delay before publishing, can help with network propagation in some cases
	// time.Sleep(100 * time.Millisecond)

	err = nfs.topic.Publish(nfs.ctx, data)
	if err != nil {
		return fmt.Errorf("failed to publish to topic %s: %w", nfs.topic.String(), err)
	}
	return nil
}

// pubsubHandler runs in a background goroutine, handling incoming messages.
func (nfs *NetworkedFS) pubsubHandler() {
	defer nfs.wg.Done()
	log.Println("PubSub handler started.")
	defer log.Println("PubSub handler stopped.")

	for {
		select {
		case <-nfs.ctx.Done():
			return
		default:
			msg, err := nfs.sub.Next(nfs.ctx)
			if err != nil {
				if nfs.ctx.Err() != nil {
					return
				}
				log.Printf("Error receiving pubsub message: %v\n", err)
				// If error is severe (e.g., subscription cancelled externally), maybe break?
				// For now, just log and continue.
				time.Sleep(1 * time.Second) // Avoid busy loop
				continue
			}

			if msg.ReceivedFrom == nfs.host.ID() {
				continue // Ignore messages from self
			}
			log.Printf("PubSub: Received message from %s on topic %s\n", msg.ReceivedFrom, *msg.Topic)

			var headers []Header
			if err := json.Unmarshal(msg.Data, &headers); err != nil {
				log.Printf("Error unmarshalling commit headers: %v\n", err)
				continue
			}

			if len(headers) == 0 || !headers[0].IsRoot() {
				log.Printf("Received invalid/empty headers from %s\n", msg.ReceivedFrom)
				continue
			}

			remoteCommitVer := headers[0].Ver()
			remoteCommitHash := headers[0].Hash()
			log.Printf("Received commit headers Ver %d (Hash: %x) from %s\n", remoteCommitVer, remoteCommitHash, msg.ReceivedFrom)

			// Check if this commit is newer than our current root
			currentRoot := nfs.Root()
			if !VersionIsGreater(headers[0], currentRoot) {
				log.Printf("Received commit is not newer than current root (Ver %d)\n", currentRoot.Ver())
				continue
			}

			log.Printf("Commit Ver %d from %s is newer. Requesting body...\n", remoteCommitVer, msg.ReceivedFrom)

			// Commit is new, request the body
			nfs.wg.Add(1)
			go func(peerID peer.ID, hdrs []Header, ver int64, hash []byte) {
				defer nfs.wg.Done()
				nfs.requestAndApplyCommit(peerID, hdrs, ver, hash)
			}(msg.ReceivedFrom, headers, remoteCommitVer, remoteCommitHash)
		}
	}
}

func (nfs *NetworkedFS) requestAndApplyCommit(peerID peer.ID, headers []Header, ver int64, hash []byte) {
	log.Printf("Requesting commit body from peer %s for commit Ver %d (Hash: %x)\n", peerID, ver, hash)

	commitBody, err := nfs.requestCommitBody(peerID, ver, hash)
	if err != nil {
		log.Printf("Error requesting commit body from peer %s: %v\n", peerID, err)
		return
	}
	defer commitBody.Close()

	// Reconstruct the commit
	commit := &Commit{
		Headers: headers,
		Body:    commitBody,
	}

	// *** CRITICAL SECTION ***
	// Need to lock the filesystem during commit application to prevent races
	// between local operations and applying remote commits. The fileSystem uses
	// a sync.RWMutex (f.mx), but NetworkedFS doesn't expose it directly.
	// We might need to add locking here or within the fileSystem.Commit method.
	// For now, assume fileSystem.Commit handles its internal locking correctly.

	log.Printf("Attempting to apply remote commit Ver %d from %s\n", ver, peerID)
	err = nfs.localFS.Commit(commit)
	if err != nil {
		log.Printf("Error applying remote commit Ver %d: %v\n", ver, err)
		// TODO: Handle commit conflicts more gracefully (e.g., request newer commits)
	} else {
		log.Printf("Successfully applied remote commit Ver %d from %s\n", ver, peerID)
	}
}

// requestCommitBody opens a stream to a peer and requests the commit body.
func (nfs *NetworkedFS) requestCommitBody(peerID peer.ID, version int64, hash []byte) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(nfs.ctx, 30*time.Second) // Timeout for the request
	defer cancel()

	stream, err := nfs.host.NewStream(ctx, peerID, commitBodyProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream to %s for protocol %s: %w", peerID, commitBodyProtocolID, err)
	}

	log.Printf("Opened stream to %s for commit body request (Ver %d)\n", peerID, version)

	// Send request (e.g., version and hash)
	req := fmt.Sprintf("%d\n%x\n", version, hash) // Simple text-based request
	writer := bufio.NewWriter(stream)
	if _, err := writer.WriteString(req); err != nil {
		_ = stream.Reset()
		return nil, fmt.Errorf("failed to write commit request to %s: %w", peerID, err)
	}
	if err := writer.Flush(); err != nil {
		_ = stream.Reset()
		return nil, fmt.Errorf("failed to flush commit request to %s: %w", peerID, err)
	}

	// The stream itself is the ReadCloser for the body
	// We return the stream directly. The caller is responsible for closing it.
	// Add a wrapper to ensure stream.Close() is called, potentially resetting on error during read.
	return &commitBodyReader{stream: stream}, nil
}

// commitBodyReader wraps the network stream for reading commit body data.
// It ensures the stream is properly closed or reset.
type commitBodyReader struct {
	stream network.Stream
	closed bool
}

func (cbr *commitBodyReader) Read(p []byte) (n int, err error) {
	if cbr.closed {
		return 0, io.EOF
	}
	n, err = cbr.stream.Read(p)
	if err != nil {
		if err != io.EOF {
			log.Printf("Error reading from commit body stream %s: %v. Resetting stream.", cbr.stream.Conn().RemotePeer(), err)
			_ = cbr.stream.Reset() // Reset on error other than EOF
		} else {
			// Clean EOF, just close normally later
		}
		cbr.closed = true // Mark as closed on any error/EOF
	}
	return n, err
}

func (cbr *commitBodyReader) Close() error {
	if cbr.closed {
		return nil // Already closed
	}
	cbr.closed = true
	return cbr.stream.Close()
}

// commitBodyStreamHandler handles incoming requests for commit bodies.
func (nfs *NetworkedFS) commitBodyStreamHandler(stream network.Stream) {
	peerID := stream.Conn().RemotePeer()
	log.Printf("Received commit body request stream from %s\n", peerID)

	// It's crucial to close or reset the stream when done.
	defer stream.Close() // Use Close for graceful termination

	// Read the request (version and hash)
	reader := bufio.NewReader(stream)
	verStr, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading version from commit body request from %s: %v\n", peerID, err)
		_ = stream.Reset() // Reset on error
		return
	}
	hashStr, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading hash from commit body request from %s: %v\n", peerID, err)
		_ = stream.Reset()
		return
	}

	var version int64
	if _, err := fmt.Sscan(verStr, &version); err != nil {
		log.Printf("Error parsing version '%s' from %s: %v\n", verStr, peerID, err)
		_ = stream.Reset()
		return
	}
	hashStr = strings.TrimSpace(hashStr)
	// hash, err := hex.DecodeString(hashStr) // Decode if needed for lookup
	// if err != nil {
	//  log.Printf("Error decoding hash '%s' from %s: %v\n", hashStr, peerID, err)
	//	_ = stream.Reset()
	//	return
	// }

	log.Printf("Processing request from %s for commit Ver %d (Hash: %s)\n", peerID, version, hashStr)

	// --- Retrieve commit data from local storage ---
	// This is the complex part: We don't have the original `Commit` object's Body anymore.
	// We need to find the *headers* associated with the requested version/hash (maybe GetCommit can help?)
	// and then stream the *actual file content* from the database for files included in that commit delta.

	// Simplification for now: Use GetCommit to find the delta since the *previous* version.
	// This might send more data than strictly necessary if the remote peer already has some intermediate commits,
	// but it's easier than calculating the exact delta for the requested version hash.
	prevVersion := version - 1                             // Assuming linear versions for simplicity
	commitDelta, err := nfs.localFS.GetCommit(prevVersion) // Use localFs directly
	if err != nil {
		log.Printf("Error getting commit delta for Ver > %d (requested %d) for %s: %v\n", prevVersion, version, peerID, err)
		_ = stream.Reset()
		return
	}
	defer commitDelta.Body.Close()

	// Verify the retrieved delta actually corresponds to the requested commit root
	// This check is important but omitted here for brevity. We should compare
	// commitDelta.Root().Ver() and commitDelta.Root().Hash() with the request.
	if commitDelta.Root().Ver() != version /* || !bytes.Equal(commitDelta.Root().Hash(), hash) */ {
		log.Printf("Retrieved commit delta (Ver %d) does not match requested Ver %d for %s\n", commitDelta.Root().Ver(), version, peerID)
		// We could try GetCommit(0) to send everything, or just fail.
		_ = stream.Reset()
		return
	}

	log.Printf("Streaming commit body Ver %d (%d bytes) to %s\n", version, commitDelta.BodySize(), peerID)

	// Stream the body content
	writer := bufio.NewWriter(stream)
	bytesSent, err := io.Copy(writer, commitDelta.Body)
	if err != nil {
		log.Printf("Error streaming commit body Ver %d to %s after %d bytes: %v\n", version, peerID, bytesSent, err)
		// Don't reset here, Close() will handle signaling the end (possibly broken)
		return
	}
	if err := writer.Flush(); err != nil {
		log.Printf("Error flushing commit body stream Ver %d to %s: %v\n", version, peerID, err)
		return
	}

	log.Printf("Finished streaming commit body Ver %d (%d bytes) to %s\n", version, bytesSent, peerID)
	// Stream will be closed by the defer statement
}

// MakeAndCommit creates a new commit from the given source filesystem and applies it locally,
// triggering network publication.
func (nfs *NetworkedFS) MakeAndCommit(prv crypto.PrivateKey, src fs.FS, ts time.Time) (*Commit, error) {
	log.Printf("NetworkedFS: Making new commit...\n")
	// Use the underlying IFS to make the commit struct
	commit, err := MakeCommit(nfs.IFS, prv, src, ts)
	if err != nil {
		return nil, fmt.Errorf("failed to make commit: %w", err)
	}
	if len(commit.Headers) <= 1 { // Only root header means no changes
		log.Println("NetworkedFS: No changes detected, commit not applied.")
		// Close the potentially empty body reader
		if commit.Body != nil {
			_ = commit.Body.Close()
		}
		return commit, nil // Return the (empty) commit struct anyway
	}

	log.Printf("NetworkedFS: Applying new commit Ver %d locally and publishing...\n", commit.Ver())
	// Use the NetworkedFS Commit wrapper which handles local apply + network publish
	err = nfs.Commit(commit) // This consumes commit.Body and publishes headers
	if err != nil {
		// Rollback isn't easily possible here, but the local commit might have failed partially.
		// The error from nfs.Commit reflects the local application result.
		return commit, fmt.Errorf("failed to apply/publish commit: %w", err)
	}

	// Important: The commit.Body in the *returned* struct is likely closed/consumed now.
	// The caller should not attempt to read from it.
	log.Printf("NetworkedFS: Successfully applied and published commit Ver %d\n", commit.Ver())
	return commit, nil
}
