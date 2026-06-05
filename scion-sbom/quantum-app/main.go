package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/spf13/cobra"
)

var (
	daemonAddr string
	demoMode   bool
	requireQKD bool
	requirePQC bool
	pathCount  int
)

// main, use as server or client:
//
// Server at ff00:0:111 :
// ./bin/quantum-app  --daemon 127.0.0.29:30255 listen 12345
//
// Client at ff00:0:112 :
// ./bin/quantum-app --daemon 127.0.0.53:30255 connect 1-ff00:0:111,127.0.0.29:12345
func main() {
	executable := filepath.Base(os.Args[0])
	cmd := &cobra.Command{
		Use:   executable,
		Short: "Quantum Security SCION test application",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "listen",
		Short: "port to listen to",
		Args:  cobra.ExactArgs(1), // Port
		RunE:  serverCmd,
	})
	clientCmd := &cobra.Command{
		Use:   "connect",
		Short: "udp address where the server is",
		Args:  cobra.ExactArgs(1),
		RunE:  clientCmd,
	}
	cmd.AddCommand(clientCmd)

	// Flags for all commands:
	for _, cmd := range cmd.Commands() {
		cmd.Flags().StringVar(&daemonAddr, "daemon", "127.0.0.1:30255", "connect to this daemon")
		cmd.Flags().BoolVar(&demoMode, "demomode", false, "set to true to create artificial pauses")
	}
	// Flags for client:
	clientCmd.Flags().BoolVar(&requireQKD, "qkd", false, "require QKD DRKey to encrypt the message")
	clientCmd.Flags().BoolVar(&requirePQC, "pqc", false, "require QQC paths for communication")
	clientCmd.Flags().IntVar(&pathCount, "pathcount", 1, "number of paths to use to send message")

	checkErr(cmd.Execute())
}

func serverCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	daemonConn := connectToDaemon(ctx)
	defer daemonConn.Close()

	portNum, err := strconv.Atoi(args[0])
	checkErr(err)

	// Local address will be the same as the sciond, without the port.
	hostAddr, err := net.ResolveUDPAddr("udp", daemonAddr)
	checkErr(err)
	hostAddr.Port = portNum

	// Start listening.
	sn := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: daemonConn},
		},
		Topology: daemonConn,
	}
	conn, err := sn.Listen(ctx, "udp", hostAddr)
	checkErr(err)
	localAddr := conn.LocalAddr().(*snet.UDPAddr)
	fmt.Println()

	type Message struct {
		gotChunks int      // How many chunks we got already .
		chunks    [][]byte // The indexed chunks, as many as total chunks, nil if not seen yet.
	}
	chunksToMessages := make(map[string]*Message)
	buff := make([]byte, 10000)
	for {
		fmt.Printf("\t--> Server listening at: %s\n", localAddr)
		n, remote, err := conn.ReadFrom(buff)
		checkErr(err)

		// The chunk is as long as what we have read.
		chunk := buff[:n]
		// The remote address is a SCION address, and we want the port to be erased, to use it
		// as the key to identify the sender, to reassemble the message.
		remoteAddr := remote.(*snet.UDPAddr)
		remoteAddr.Host.Port = -1

		// We have a packet.
		fmt.Printf("\tgot %d bytes from %s\n\t%s\n", n, remoteAddr, hex.EncodeToString(chunk))
		sleep()

		// Try to reassemble the message.
		index := bytes.IndexByte(chunk, '\n')
		if index <= 0 {
			checkErr(fmt.Errorf("header message to reassemble message got wrong \\n at %d", index))
		}
		header := string(chunk[:index])
		fields := strings.Split(header, ",")
		if len(fields) != 2 {
			checkErr(fmt.Errorf("wrong header: %s", header))
		}
		chunkIndex, err := strconv.Atoi(fields[0])
		checkErr(err)
		N, err := strconv.Atoi(fields[1])
		checkErr(err)

		// Restructure the chunk bounds to contain only the raw chunk.
		index++ // index pointed to the \n separator.
		chunk = chunk[index:]

		chunks, ok := chunksToMessages[remoteAddr.String()]
		if !ok {
			fmt.Printf("\t\tthis is the first chunk of the message from %s\n", remoteAddr)
			sleep()
			// This is the first chunk we see, create struct.
			chunks = &Message{
				chunks: make([][]byte, N),
			}
			chunksToMessages[remoteAddr.String()] = chunks
		}
		fmt.Printf("\tgot chunk %d to message structure to reassemble\n", chunkIndex)
		sleep()

		if chunks.chunks[chunkIndex] != nil {
			checkErr(fmt.Errorf("repeated chunk index %d", chunkIndex))
		}
		chunks.chunks[chunkIndex] = make([]byte, len(chunk))
		copy(chunks.chunks[chunkIndex], chunk)
		chunks.gotChunks++

		// Check if we have a complete message:
		if chunks.gotChunks != len(chunks.chunks) {
			continue
		}
		fmt.Printf("REASSEMBLING complete message for sender %s\n", remoteAddr)
		sleep()
		var message []byte
		for _, chunk := range chunks.chunks {
			message = append(message, chunk...)
		}
		delete(chunksToMessages, remoteAddr.String()) // remove after message is complete.
		fmt.Printf("REASSEMBLED raw message is:\n"+
			"---------------------------\n"+
			"%s\n ---\n%s\n"+
			"---------------------------\n",
			hex.EncodeToString(message), string(message))
		sleep()

		// Split the message into the two parts.
		index = bytes.IndexByte(message, '\n')
		if index <= 0 {
			checkErr(fmt.Errorf("message '%s' does not contain a \\n", hex.EncodeToString(message)))
		}
		index++
		plaintext := string(message[:index])
		// Find the encryption indicator.
		if message[index] == '1' {
			fmt.Printf("\tmessage is encrypted, requesting drkey for slow side %s,%s...\n",
				remoteAddr.IA, remoteAddr.Host.IP)

			// Get the DRKey.
			host2hostMeta := drkey.HostHostMeta{
				ProtoId:  drkey.Generic,
				Validity: time.Now(),
				SrcIA:    localAddr.IA, // Us, fast path.
				SrcHost:  localAddr.Host.IP.String(),
				DstIA:    remoteAddr.IA,
				DstHost:  remoteAddr.Host.IP.String(),
			}
			host2hostKey, err := daemonConn.DRKeyGetHostHostKey(ctx, host2hostMeta)
			checkErr(err)
			fmt.Printf("\tGot drkey: %s\n", hex.EncodeToString(host2hostKey.Key[:]))
			sleep()

			index += 2
			plaintext = plaintext + decryptMessage(host2hostKey.Key[:], message[index:])
		} else {
			index += 2
			plaintext += string(message[index:])
		}
		// Decrypt.
		fmt.Printf("The real message follows:\n"+
			"---------------------------\n"+
			"%s\n"+
			"---------------------------\n",
			plaintext)
		sleep()
	}
}

func clientCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	daemonConn := connectToDaemon(ctx)
	defer daemonConn.Close()

	remoteAddr, err := snet.ParseUDPAddr(args[0])
	checkErr(err)

	sn := &snet.SCIONNetwork{
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: daemonConn},
		},
		Topology: daemonConn,
	}

	// Get paths to destination.
	fmt.Printf("paths to %s\n", remoteAddr)
	paths, err := daemonConn.Paths(ctx, remoteAddr.IA, 0, daemon.PathReqFlags{})
	checkErr(err)
	for i, p := range paths {
		pqc := "std"
		if p.Metadata().PQsecure {
			pqc = "PQC"
		}
		fmt.Printf("[%2d] {%s} %s\n", i, pqc, p)
	}
	sleep()

	// Choose one path.
	selected, err := selectPaths(pathCount, paths, requirePQC)
	checkErr(err)
	for _, path := range selected {
		fmt.Printf("\tusing path: %s\n", path)
	}
	sleep()

	// Get our local IA.
	localIA, err := daemonConn.LocalIA(ctx)
	checkErr(err)

	// Local address will be the same as the sciond, without the port.
	localUdpAddr, err := net.ResolveUDPAddr("udp", daemonAddr)
	checkErr(err)
	localUdpAddr.Port = 0

	fmt.Printf("using local address: %s\n", localUdpAddr)

	// The message has three parts: plain text, encryption indicator and possibly encrypted text.
	// They are separated by \n
	var message []byte
	plainText := []byte("hello server\n")
	if requireQKD {
		// Obtain the corresponding DRKey.
		host2hostMeta := drkey.HostHostMeta{
			ProtoId:  drkey.Generic,
			Validity: time.Now(),
			SrcIA:    remoteAddr.IA,
			SrcHost:  remoteAddr.Host.IP.String(),
			DstIA:    localIA, // Us, slow path.
			DstHost:  localUdpAddr.IP.String(),
		}
		host2hostKey, err := daemonConn.DRKeyGetHostHostKey(ctx, host2hostMeta)
		checkErr(err)
		fmt.Printf("Got drkey (quantum? %v): %s\n",
			host2hostKey.IsQKD,
			hex.EncodeToString(host2hostKey.Key[:]),
		)
		sleep()

		plainText = append(plainText, []byte("1\n")...)
		enc := encryptMessage(host2hostKey.Key[:], "this is very secret")
		message = make([]byte, len(plainText)+len(enc))
		copy(message, plainText)
		copy(message[len(plainText):], enc)
	} else {
		plainText = append(plainText, []byte("0\n")...)
		message = append(plainText, []byte("not secret at all")...)
	}

	sendMessage(ctx, sn, message, localUdpAddr, selected, remoteAddr)

	return nil
}

func encryptMessage(key []byte, plainMessage string) []byte {
	block, err := aes.NewCipher(key)
	checkErr(err)

	// Authenticated encryption:
	gcm, err := cipher.NewGCM(block)
	checkErr(err)

	// Create a nonce.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	checkErr(err)
	fmt.Printf("nonce: %s\n", hex.EncodeToString(nonce))

	// Encrypt and append to the nonce. Return the collated message.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plainMessage), nil)
	fmt.Printf("encrypted message: %s\n", hex.EncodeToString(ciphertext))
	return ciphertext
}

func decryptMessage(key []byte, ciphertext []byte) string {
	block, err := aes.NewCipher(key)
	checkErr(err)

	gcm, err := cipher.NewGCM(block)
	checkErr(err)

	nonceSize := gcm.NonceSize()
	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	// nonce := ciphertext[:gcm.NonceSize()]
	// encrypted := ciphertext[gcm.NonceSize():]
	fmt.Printf("\t\tnonce: %s\n", hex.EncodeToString(nonce))
	fmt.Printf("\t\tencrypted message: %s\n", hex.EncodeToString(encrypted))

	msg, err := gcm.Open(nil, nonce, encrypted, nil)
	checkErr(err)

	return string(msg)
}

func connectToDaemon(ctx context.Context) daemon.Connector {
	fmt.Printf("connecting to scion daemon at %s ... ", daemonAddr)
	conn, err := daemon.Service{
		Address: daemonAddr,
	}.Connect(ctx)
	checkErr(err)
	fmt.Println("connected.")

	return conn
}

func selectPaths(path_count int, paths []snet.Path, requirePQC bool) ([]snet.Path, error) {
	selected_paths := make([]snet.Path, 0, path_count)
	for _, p := range paths {
		if p.Metadata().PQsecure == requirePQC {
			selected_paths = append(selected_paths, p)
			if len(selected_paths) == path_count {
				break
			}
		}
	}
	if len(selected_paths) != path_count {
		return nil, fmt.Errorf("only %d paths found", len(selected_paths))
	}
	return selected_paths, nil
}

// sendMessage splits message into len(paths) chunks, and sends the chunks using paths.
// Each path will send a message with content: `path_index,total_paths\nchunk`, for the receiver
// to be able to reconstruct the full message.
func sendMessage(
	ctx context.Context,
	sn *snet.SCIONNetwork,
	message []byte,
	localUdpAddr *net.UDPAddr,
	paths []snet.Path,
	remoteAddr *snet.UDPAddr,
) {
	N := len(paths)
	chunkSize := len(message) / N
	for i, path := range paths {
		remoteAddr.Path = path.Dataplane()
		remoteAddr.NextHop = path.UnderlayNextHop()

		// Dial the remote endpoint.
		conn, err := sn.Dial(ctx, "udp", localUdpAddr, remoteAddr)
		checkErr(err)

		// Compute the chunk for this path.
		chunk := ([]byte)(fmt.Sprintf("%d,%d\n", i, N))
		begin := i * chunkSize
		end := min((i+1)*chunkSize, len(message))
		chunk = append(chunk, message[begin:end]...)

		// And send the chunk.
		fmt.Printf("Sending chunk %d through path %s:\n\"%s\" | %s\n",
			i,
			path,
			hex.EncodeToString(chunk),
			string(chunk))
		_, err = conn.Write(chunk)
		checkErr(err)
	}
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		// Print stack info.
		_, file, line, ok := runtime.Caller(1)
		if ok {
			fmt.Fprintf(os.Stderr, "\t ----> at %s:%d\n", file, line)
		}
		// debug.PrintStack()

		os.Exit(1)
	}

}

func sleep() {
	if demoMode {
		time.Sleep(time.Second)
	}
}
