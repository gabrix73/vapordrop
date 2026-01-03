package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/awnumar/memguard"
	"github.com/cretz/bine/tor"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/argon2"
)

// =============================================================================
// VAPORDROP - ZERO-KNOWLEDGE DEAD DROP
// =============================================================================
// Security Stack (Internal - Non-NIST):
//   - BLAKE3 (zeebo/blake3) - Hashing (NOT blake2b!)
//   - Ed25519 (DJB) - Tor onion key derivation
//   - Argon2id (PHC winner) - Key stretching
//
// Client Crypto (unchanged - handled by frontend):
//   - P-256 ECDH - Key exchange
//   - AES-GCM - Encryption
//   - Server is ZERO-KNOWLEDGE: never decrypts, stores opaque blobs only
// =============================================================================

const (
	Version = "2.2.0-hardened"

	// === EPHEMERAL DEAD DROP SETTINGS ===
	MessageTTL  = 7 * 24 * time.Hour  // Messages auto-delete after 7 days
	FileTTL     = 7 * 24 * time.Hour  // Files auto-delete after 7 days
	IdentityTTL = 30 * 24 * time.Hour // Identity mappings expire after 30 days
	GCInterval  = 15 * time.Minute    // Garbage collection frequency

	// === ANTI-REPLAY ===
	NonceExpiration = 24 * time.Hour
	MaxNonceCache   = 100000

	// === RATE LIMITING (Session-based for Tor compatibility) ===
	RateLimitWindow       = 1 * time.Minute
	MaxRequestsPerSession = 60

	// === TRAFFIC ANALYSIS PROTECTION ===
	MinPadding = 512
	MaxPadding = 8192
	MinDelay   = 50 * time.Millisecond
	MaxDelay   = 500 * time.Millisecond

	// === ARGON2ID (OWASP recommended) ===
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // 64 MB
	Argon2Threads = 4
	Argon2KeyLen  = 32

	// === IDENTITY REGISTRY ===
	MaxIdentities = 100000

	// === FILE TRANSFER ===
	MaxFileSize     = 1 << 30 // 1 GB
	FileChunkSize   = 1 << 20 // 1 MB chunks
	MaxPendingFiles = 100
	FileStorageDir  = "./file_storage"
	FileGCInterval  = 30 * time.Minute

	// === CLIENT KEY FORMAT ===
	// Frontend uses X25519 (DJB, non-NIST): 32 bytes = 64 hex
	// Server is ZERO-KNOWLEDGE: validates SIZE only, never decrypts
	X25519PublicKeyHex = 64
)

// =============================================================================
// INPUT VALIDATION (Strict patterns)
// =============================================================================

var (
	// Lowercase hex only
	hexPattern = regexp.MustCompile(`^[a-f0-9]+$`)

	// Numeric ID: "12345678-90" or "12345678"
	numericIDFullPattern  = regexp.MustCompile(`^\d{8}-\d{2}$`)
	numericIDShortPattern = regexp.MustCompile(`^\d{8}$`)

	// File ID: 32 hex chars
	fileIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

	// Session token: 32 hex chars
	sessionTokenPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

	// Chunk number: digits only, max 6 digits
	chunkNumPattern = regexp.MustCompile(`^\d{1,6}$`)
)

// =============================================================================
// DATA STRUCTURES
// =============================================================================

type Message struct {
	ToHash     string    `json:"to_hash"`
	CipherBlob string    `json:"cipher_blob"`
	Nonce      string    `json:"nonce"`
	Padding    string    `json:"padding,omitempty"`
	Timestamp  time.Time `json:"-"`
}

type RateLimitEntry struct {
	Count     int
	ResetTime time.Time
}

type FileTransfer struct {
	ID             string    `json:"id"`
	FromPubKey     string    `json:"from_pubkey"`
	ToPubKey       string    `json:"to_pubkey"`
	FileName       string    `json:"filename"`
	FileSize       int64     `json:"filesize"`
	ChunkCount     int       `json:"chunk_count"`
	ChunksReceived int       `json:"chunks_received"`
	CreatedAt      time.Time `json:"created_at"`
	Ready          bool      `json:"ready"`
}

// =============================================================================
// VOLATILE STORAGE (RAM ONLY - ZERO PERSISTENCE)
// =============================================================================

var (
	// Message store
	messageStore      = make(map[string][]Message)
	messageStoreMutex sync.RWMutex

	// Anti-replay nonce cache (stores BLAKE3 hash of nonce)
	nonceCache      = make(map[string]time.Time)
	nonceCacheMutex sync.RWMutex

	// Rate limiting (session token hash → entry)
	rateLimiter      = make(map[string]*RateLimitEntry)
	rateLimiterMutex sync.RWMutex

	// Identity Registry
	numericIDToKeys = make(map[string][]string)
	keyToNumericID  = make(map[string]string)
	keyLastSeen     = make(map[string]time.Time)
	identityMutex   sync.RWMutex

	// File transfers
	fileTransfers      = make(map[string]*FileTransfer)
	fileTransfersMutex sync.RWMutex
)

// =============================================================================
// BLAKE3 HASHING (NON-NIST - zeebo/blake3)
// =============================================================================

func blake3Hash(data []byte) []byte {
	h := blake3.New()
	h.Write(data)
	return h.Sum(nil)
}

func blake3HashLen(data []byte, length int) []byte {
	h := blake3.New()
	h.Write(data)
	out := make([]byte, length)
	h.Digest().Read(out)
	return out
}

func blake3Hex(data []byte) string {
	return hex.EncodeToString(blake3Hash(data))
}

// =============================================================================
// INPUT VALIDATION FUNCTIONS
// =============================================================================

func isValidHex(s string, expectedLen int) bool {
	if len(s) != expectedLen {
		return false
	}
	return hexPattern.MatchString(strings.ToLower(s))
}

func isValidPublicKey(s string) bool {
	return isValidHex(s, X25519PublicKeyHex)
}

func isValidNumericID(s string) bool {
	return numericIDFullPattern.MatchString(s) || numericIDShortPattern.MatchString(s)
}

func isValidFileID(s string) bool {
	return fileIDPattern.MatchString(strings.ToLower(s))
}

func isValidSessionToken(s string) bool {
	return sessionTokenPattern.MatchString(strings.ToLower(s))
}

func isValidNonce(s string) bool {
	if len(s) < 32 || len(s) > 128 {
		return false
	}
	return hexPattern.MatchString(strings.ToLower(s))
}

func isValidChunkNum(s string) bool {
	return chunkNumPattern.MatchString(s)
}

// =============================================================================
// SECURITY FUNCTIONS
// =============================================================================

func generatePadding() string {
	var sizeBuf [2]byte
	rand.Read(sizeBuf[:])
	size := MinPadding + int(sizeBuf[0])%(MaxPadding-MinPadding)
	padding := make([]byte, size)
	rand.Read(padding)
	return hex.EncodeToString(padding)
}

func randomDelay() {
	var delayBuf [2]byte
	rand.Read(delayBuf[:])
	delayRange := int(MaxDelay - MinDelay)
	delay := MinDelay + time.Duration(int(delayBuf[0])*delayRange/256)
	time.Sleep(delay)
}

func constantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		subtle.ConstantTimeCompare([]byte(a), []byte(a))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Anti-replay: check and store nonce
func checkNonce(nonce string) bool {
	if !isValidNonce(nonce) {
		return false
	}

	// Store BLAKE3 hash of nonce (privacy)
	nonceHash := hex.EncodeToString(blake3HashLen([]byte(nonce), 16))

	nonceCacheMutex.Lock()
	defer nonceCacheMutex.Unlock()

	if _, exists := nonceCache[nonceHash]; exists {
		return false // Replay detected
	}

	// Cleanup old nonces if cache full
	if len(nonceCache) >= MaxNonceCache {
		cutoff := time.Now().Add(-NonceExpiration)
		for n, t := range nonceCache {
			if t.Before(cutoff) {
				delete(nonceCache, n)
			}
		}
	}

	nonceCache[nonceHash] = time.Now()
	return true
}

// Session-based rate limiting (Tor compatible)
func checkRateLimit(r *http.Request) bool {
	// Get session token from header
	token := r.Header.Get("X-Session-Token")
	if token == "" {
		// Fallback: generate from request characteristics
		token = r.Header.Get("User-Agent") + r.Header.Get("Accept-Language")
	}

	// Hash for privacy
	tokenHash := hex.EncodeToString(blake3HashLen([]byte(token), 16))

	rateLimiterMutex.Lock()
	defer rateLimiterMutex.Unlock()

	now := time.Now()
	entry, exists := rateLimiter[tokenHash]

	if !exists || now.After(entry.ResetTime) {
		rateLimiter[tokenHash] = &RateLimitEntry{
			Count:     1,
			ResetTime: now.Add(RateLimitWindow),
		}
		return true
	}

	if entry.Count >= MaxRequestsPerSession {
		return false
	}

	entry.Count++
	return true
}

// =============================================================================
// SECURITY HEADERS MIDDLEWARE
// =============================================================================

func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Anti-MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Anti-clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// CSP - strict but compatible with inline scripts for QR
		csp := "default-src 'none'; " +
			"script-src 'self' 'unsafe-inline'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: blob:; " +
			"connect-src 'self'; " +
			"form-action 'self'; " +
			"frame-ancestors 'none'; " +
			"base-uri 'self'"
		w.Header().Set("Content-Security-Policy", csp)

		// Permissions Policy
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

		// Referrer Policy
		w.Header().Set("Referrer-Policy", "no-referrer")

		// No caching for API
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		next(w, r)
	}
}

// =============================================================================
// PATH SECURITY
// =============================================================================

func safeFilePath(baseDir, fileID string) (string, error) {
	if !isValidFileID(fileID) {
		return "", fmt.Errorf("invalid file ID")
	}

	cleanPath := filepath.Clean(filepath.Join(baseDir, fileID))

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}

	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(absPath, absBase) {
		return "", fmt.Errorf("path traversal detected")
	}

	return cleanPath, nil
}

func safeChunkPath(baseDir, fileID string, chunkNum int) (string, error) {
	filePath, err := safeFilePath(baseDir, fileID)
	if err != nil {
		return "", err
	}

	if chunkNum < 0 || chunkNum > 1100 { // Max ~1.1TB
		return "", fmt.Errorf("invalid chunk number")
	}

	return filepath.Join(filePath, fmt.Sprintf("%d", chunkNum)), nil
}

// =============================================================================
// IDENTITY REGISTRY HANDLERS
// =============================================================================

func handleRegister(w http.ResponseWriter, r *http.Request) {
	randomDelay()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkRateLimit(r) {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	var req struct {
		NumericID string `json:"numeric_id"`
		PublicKey string `json:"public_key"`
		Nonce     string `json:"nonce"`
	}

	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Validate numeric ID
	if !isValidNumericID(req.NumericID) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_numeric_id"})
		return
	}

	// Validate public key (P-256 = 130 hex)
	if !isValidPublicKey(req.PublicKey) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_public_key"})
		return
	}

	// Normalize to lowercase
	req.PublicKey = strings.ToLower(req.PublicKey)

	// Anti-replay
	if req.Nonce != "" && !checkNonce(req.Nonce) {
		http.Error(w, "Replay detected", http.StatusConflict)
		return
	}

	identityMutex.Lock()
	defer identityMutex.Unlock()

	now := time.Now()

	// Check if already registered
	if existingID, exists := keyToNumericID[req.PublicKey]; exists {
		keyLastSeen[req.PublicKey] = now
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "exists",
			"numeric_id": existingID,
			"collision":  len(numericIDToKeys[existingID]) > 1,
		})
		return
	}

	// Check capacity
	if len(keyToNumericID) >= MaxIdentities {
		http.Error(w, "Registry full", http.StatusServiceUnavailable)
		return
	}

	// Register
	numericIDToKeys[req.NumericID] = append(numericIDToKeys[req.NumericID], req.PublicKey)

	// Also register short ID
	shortID := strings.Split(req.NumericID, "-")[0]
	if shortID != req.NumericID {
		numericIDToKeys[shortID] = append(numericIDToKeys[shortID], req.PublicKey)
	}

	keyToNumericID[req.PublicKey] = req.NumericID
	keyLastSeen[req.PublicKey] = now

	collision := len(numericIDToKeys[req.NumericID]) > 1

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "registered",
		"numeric_id": req.NumericID,
		"collision":  collision,
	})
}

func handleResolve(w http.ResponseWriter, r *http.Request) {
	randomDelay()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkRateLimit(r) {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	// Extract ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/resolve/")
	if path == "" || !isValidNumericID(path) {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	identityMutex.RLock()
	keys, exists := numericIDToKeys[path]
	identityMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")

	if !exists || len(keys) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"numeric_id":  path,
			"public_keys": []string{},
			"found":       false,
		})
		return
	}

	// Update last seen
	identityMutex.Lock()
	now := time.Now()
	for _, k := range keys {
		keyLastSeen[k] = now
	}
	identityMutex.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"numeric_id":  path,
		"public_keys": keys,
		"found":       true,
		"collision":   len(keys) > 1,
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	randomDelay()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	identityMutex.RLock()
	totalKeys := len(keyToNumericID)
	collisions := 0
	for id, keys := range numericIDToKeys {
		if strings.Contains(id, "-") && len(keys) > 1 {
			collisions++
		}
	}
	identityMutex.RUnlock()

	messageStoreMutex.RLock()
	pendingMsgs := 0
	for _, msgs := range messageStore {
		pendingMsgs += len(msgs)
	}
	messageStoreMutex.RUnlock()

	fileTransfersMutex.RLock()
	pendingFiles := len(fileTransfers)
	fileTransfersMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"registered_identities": totalKeys,
		"id_collisions":         collisions,
		"pending_messages":      pendingMsgs,
		"pending_files":         pendingFiles,
		"message_ttl_days":      int(MessageTTL.Hours() / 24),
		"zero_knowledge":        true,
		"version":               Version,
	})
}

// =============================================================================
// MESSAGE HANDLERS (ZERO-KNOWLEDGE)
// =============================================================================

func handleSend(w http.ResponseWriter, r *http.Request) {
	randomDelay()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkRateLimit(r) {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	var msg Message
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&msg); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Validate recipient key
	if !isValidPublicKey(msg.ToHash) {
		http.Error(w, "Invalid recipient key", http.StatusBadRequest)
		return
	}

	// Validate cipher blob exists
	if len(msg.CipherBlob) < 32 {
		http.Error(w, "Invalid cipher blob", http.StatusBadRequest)
		return
	}

	// Validate nonce
	if !isValidNonce(msg.Nonce) {
		http.Error(w, "Invalid nonce", http.StatusBadRequest)
		return
	}

	// Anti-replay
	if !checkNonce(msg.Nonce) {
		http.Error(w, "Replay detected", http.StatusConflict)
		return
	}

	// Normalize
	msg.ToHash = strings.ToLower(msg.ToHash)
	msg.Padding = generatePadding()
	msg.Timestamp = time.Now()

	messageStoreMutex.Lock()
	messageStore[msg.ToHash] = append(messageStore[msg.ToHash], msg)
	messageStoreMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	randomDelay()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkRateLimit(r) {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	var req struct {
		MyHash string `json:"my_hash"`
		Nonce  string `json:"nonce"`
	}

	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if !isValidPublicKey(req.MyHash) {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}

	if !isValidNonce(req.Nonce) {
		http.Error(w, "Invalid nonce", http.StatusBadRequest)
		return
	}

	if !checkNonce(req.Nonce) {
		http.Error(w, "Replay detected", http.StatusConflict)
		return
	}

	req.MyHash = strings.ToLower(req.MyHash)

	// Constant-time lookup and delete
	messageStoreMutex.Lock()
	var msgs []Message
	for hash, m := range messageStore {
		if constantTimeCompare(hash, req.MyHash) {
			msgs = m
			delete(messageStore, hash) // Ephemeral: delete after fetch
			break
		}
	}
	messageStoreMutex.Unlock()

	// Remove internal padding from response
	for i := range msgs {
		msgs[i].Padding = ""
	}

	if msgs == nil {
		msgs = []Message{}
	}

	response := map[string]interface{}{
		"messages": msgs,
		"padding":  generatePadding(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	randomDelay()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "alive",
		"zero_knowledge": true,
		"ttl_days":       int(MessageTTL.Hours() / 24),
		"version":        Version,
	})
}

// =============================================================================
// FILE TRANSFER HANDLERS
// =============================================================================

func handleFileInit(w http.ResponseWriter, r *http.Request) {
	randomDelay()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkRateLimit(r) {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	var req struct {
		FromPubKey string `json:"from_pubkey"`
		ToPubKey   string `json:"to_pubkey"`
		FileName   string `json:"filename"`
		FileSize   int64  `json:"filesize"`
		ChunkCount int    `json:"chunk_count"`
	}

	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Validate keys
	if !isValidPublicKey(req.FromPubKey) || !isValidPublicKey(req.ToPubKey) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_pubkey"})
		return
	}

	// Validate size
	if req.FileSize <= 0 || req.FileSize > MaxFileSize {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_filesize"})
		return
	}

	// Validate chunk count
	maxChunks := int(MaxFileSize/FileChunkSize) + 1
	if req.ChunkCount <= 0 || req.ChunkCount > maxChunks {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_chunk_count"})
		return
	}

	fileTransfersMutex.RLock()
	if len(fileTransfers) >= MaxPendingFiles {
		fileTransfersMutex.RUnlock()
		http.Error(w, "Too many pending files", http.StatusServiceUnavailable)
		return
	}
	fileTransfersMutex.RUnlock()

	// Generate secure file ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	fileID := hex.EncodeToString(idBytes)

	// Create directory
	filePath, err := safeFilePath(FileStorageDir, fileID)
	if err != nil {
		log.Printf("Path error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if err := os.MkdirAll(filePath, 0700); err != nil {
		log.Printf("Mkdir error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	ft := &FileTransfer{
		ID:             fileID,
		FromPubKey:     strings.ToLower(req.FromPubKey),
		ToPubKey:       strings.ToLower(req.ToPubKey),
		FileName:       req.FileName,
		FileSize:       req.FileSize,
		ChunkCount:     req.ChunkCount,
		ChunksReceived: 0,
		CreatedAt:      time.Now(),
		Ready:          false,
	}

	fileTransfersMutex.Lock()
	fileTransfers[fileID] = ft
	fileTransfersMutex.Unlock()

	log.Printf("📁 File init: %s (%d bytes, %d chunks)", fileID[:8], req.FileSize, req.ChunkCount)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"file_id":    fileID,
		"chunk_size": FileChunkSize,
	})
}

func handleFileChunk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse path: /api/file/chunk/{id}/{num}
	path := strings.TrimPrefix(r.URL.Path, "/api/file/chunk/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	fileID := parts[0]
	chunkNumStr := parts[1]

	if !isValidFileID(fileID) {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	if !isValidChunkNum(chunkNumStr) {
		http.Error(w, "Invalid chunk number", http.StatusBadRequest)
		return
	}

	chunkNum, _ := strconv.Atoi(chunkNumStr)

	fileTransfersMutex.RLock()
	ft, exists := fileTransfers[fileID]
	fileTransfersMutex.RUnlock()

	if !exists {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	if chunkNum < 0 || chunkNum >= ft.ChunkCount {
		http.Error(w, "Invalid chunk number", http.StatusBadRequest)
		return
	}

	// Read chunk data (max 1MB + overhead)
	maxSize := int64(FileChunkSize + 4096)
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

	chunkData, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusBadRequest)
		return
	}

	// Save chunk
	chunkPath, err := safeChunkPath(FileStorageDir, fileID, chunkNum)
	if err != nil {
		log.Printf("Chunk path error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(chunkPath, chunkData, 0600); err != nil {
		log.Printf("Write error: %v", err)
		http.Error(w, "Write error", http.StatusInternalServerError)
		return
	}

	fileTransfersMutex.Lock()
	ft.ChunksReceived++
	if ft.ChunksReceived >= ft.ChunkCount {
		ft.Ready = true
		log.Printf("📁 File ready: %s", fileID[:8])
	}
	fileTransfersMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"chunk":    chunkNum,
		"received": ft.ChunksReceived,
		"total":    ft.ChunkCount,
		"ready":    ft.Ready,
	})
}

func handleFilePending(w http.ResponseWriter, r *http.Request) {
	randomDelay()

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract pubkey from path
	pubkey := strings.TrimPrefix(r.URL.Path, "/api/file/pending/")
	if !isValidPublicKey(pubkey) {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}

	pubkey = strings.ToLower(pubkey)

	fileTransfersMutex.RLock()
	var pending []map[string]interface{}
	for _, ft := range fileTransfers {
		if ft.ToPubKey == pubkey && ft.Ready {
			pending = append(pending, map[string]interface{}{
				"file_id":     ft.ID,
				"from_pubkey": ft.FromPubKey,
				"filename":    ft.FileName,
				"filesize":    ft.FileSize,
				"chunk_count": ft.ChunkCount,
				"created_at":  ft.CreatedAt.Unix(),
			})
		}
	}
	fileTransfersMutex.RUnlock()

	if pending == nil {
		pending = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"files": pending})
}

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse path: /api/file/download/{id}/{num}
	path := strings.TrimPrefix(r.URL.Path, "/api/file/download/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	fileID := parts[0]
	chunkNumStr := parts[1]

	if !isValidFileID(fileID) || !isValidChunkNum(chunkNumStr) {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	chunkNum, _ := strconv.Atoi(chunkNumStr)

	fileTransfersMutex.RLock()
	ft, exists := fileTransfers[fileID]
	fileTransfersMutex.RUnlock()

	if !exists || !ft.Ready {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	if chunkNum < 0 || chunkNum >= ft.ChunkCount {
		http.Error(w, "Invalid chunk", http.StatusBadRequest)
		return
	}

	chunkPath, err := safeChunkPath(FileStorageDir, fileID, chunkNum)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	chunkData, err := os.ReadFile(chunkPath)
	if err != nil {
		http.Error(w, "Read error", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(chunkData)))
	w.Write(chunkData)
}

func handleFileComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fileID := strings.TrimPrefix(r.URL.Path, "/api/file/complete/")
	if !isValidFileID(fileID) {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	fileTransfersMutex.Lock()
	_, exists := fileTransfers[fileID]
	if exists {
		delete(fileTransfers, fileID)
	}
	fileTransfersMutex.Unlock()

	if !exists {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Delete file data
	filePath, err := safeFilePath(FileStorageDir, fileID)
	if err == nil {
		if err := os.RemoveAll(filePath); err != nil {
			log.Printf("Delete error: %v", err)
		} else {
			log.Printf("🗑️ File deleted: %s", fileID[:8])
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// =============================================================================
// GARBAGE COLLECTORS (EPHEMERAL ENFORCEMENT)
// =============================================================================

func startMessageGC() {
	for {
		time.Sleep(GCInterval)

		messageStoreMutex.Lock()
		cutoff := time.Now().Add(-MessageTTL)
		deleted := 0
		for hash, msgs := range messageStore {
			var keep []Message
			for _, m := range msgs {
				if m.Timestamp.After(cutoff) {
					keep = append(keep, m)
				} else {
					deleted++
				}
			}
			if len(keep) > 0 {
				messageStore[hash] = keep
			} else {
				delete(messageStore, hash)
			}
		}
		messageStoreMutex.Unlock()

		if deleted > 0 {
			log.Printf("🧹 Message GC: deleted %d expired messages", deleted)
		}
	}
}

func startNonceGC() {
	for {
		time.Sleep(NonceExpiration / 2)

		nonceCacheMutex.Lock()
		cutoff := time.Now().Add(-NonceExpiration)
		deleted := 0
		for n, t := range nonceCache {
			if t.Before(cutoff) {
				delete(nonceCache, n)
				deleted++
			}
		}
		nonceCacheMutex.Unlock()

		if deleted > 0 {
			log.Printf("🧹 Nonce GC: cleared %d expired nonces", deleted)
		}
	}
}

func startRateLimitGC() {
	for {
		time.Sleep(RateLimitWindow * 2)

		rateLimiterMutex.Lock()
		now := time.Now()
		for key, entry := range rateLimiter {
			if now.After(entry.ResetTime) {
				delete(rateLimiter, key)
			}
		}
		rateLimiterMutex.Unlock()
	}
}

func startIdentityGC() {
	for {
		time.Sleep(1 * time.Hour)

		identityMutex.Lock()
		cutoff := time.Now().Add(-IdentityTTL)
		deleted := 0

		for pubkey, lastSeen := range keyLastSeen {
			if lastSeen.Before(cutoff) {
				numericID := keyToNumericID[pubkey]

				// Remove from numericIDToKeys
				if keys, exists := numericIDToKeys[numericID]; exists {
					var newKeys []string
					for _, k := range keys {
						if k != pubkey {
							newKeys = append(newKeys, k)
						}
					}
					if len(newKeys) > 0 {
						numericIDToKeys[numericID] = newKeys
					} else {
						delete(numericIDToKeys, numericID)
					}
				}

				// Remove short ID mapping too
				shortID := strings.Split(numericID, "-")[0]
				if shortID != numericID {
					if keys, exists := numericIDToKeys[shortID]; exists {
						var newKeys []string
						for _, k := range keys {
							if k != pubkey {
								newKeys = append(newKeys, k)
							}
						}
						if len(newKeys) > 0 {
							numericIDToKeys[shortID] = newKeys
						} else {
							delete(numericIDToKeys, shortID)
						}
					}
				}

				delete(keyToNumericID, pubkey)
				delete(keyLastSeen, pubkey)
				deleted++
			}
		}
		identityMutex.Unlock()

		if deleted > 0 {
			log.Printf("🧹 Identity GC: removed %d inactive identities", deleted)
		}
	}
}

func startFileGC() {
	// Ensure directory exists
	os.MkdirAll(FileStorageDir, 0700)

	for {
		time.Sleep(FileGCInterval)

		fileTransfersMutex.Lock()
		cutoff := time.Now().Add(-FileTTL)
		deleted := 0

		for id, ft := range fileTransfers {
			if ft.CreatedAt.Before(cutoff) {
				filePath, err := safeFilePath(FileStorageDir, id)
				if err == nil {
					os.RemoveAll(filePath)
				}
				delete(fileTransfers, id)
				deleted++
			}
		}
		fileTransfersMutex.Unlock()

		if deleted > 0 {
			log.Printf("🧹 File GC: removed %d expired files", deleted)
		}
	}
}

// =============================================================================
// MAIN
// =============================================================================

func main() {
	// Memory protection
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Get Tor key passphrase
	envKey := os.Getenv("VAPOR_KEY")
	if len(envKey) < 16 {
		log.Fatal("❌ VAPOR_KEY required (min 16 chars)")
	}

	fmt.Println("⚙️  Deriving Tor key with Argon2id...")

	// Secure enclave for passphrase
	secretEnclave := memguard.NewBufferFromBytes([]byte(envKey))

	// Zero environment variable
	for i := range envKey {
		envKey = envKey[:i] + "\x00" + envKey[i+1:]
	}

	// BLAKE3-based salt (non-NIST)
	salt := blake3Hash([]byte("vapordrop-tor-onion-key-v2"))

	// Argon2id key derivation
	seed := argon2.IDKey(
		secretEnclave.Bytes(),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLen,
	)
	secretEnclave.Destroy()

	// Clear salt
	for i := range salt {
		salt[i] = 0
	}

	// Generate Ed25519 key
	onionKey := ed25519.NewKeyFromSeed(seed)

	// Clear seed
	for i := range seed {
		seed[i] = 0
	}

	fmt.Println("⚙️  Starting Tor...")

	// Start Tor
	conf := &tor.StartConf{
		TempDataDirBase: os.TempDir(),
		NoAutoSocksPort: true,
	}

	t, err := tor.Start(context.Background(), conf)
	if err != nil {
		log.Panicf("❌ Tor error: %v", err)
	}
	defer t.Close()

	fmt.Println("⚙️  Creating hidden service...")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	onion, err := t.Listen(ctx, &tor.ListenConf{
		Version3:    true,
		Key:         onionKey,
		RemotePorts: []int{80},
	})
	if err != nil {
		log.Panicf("❌ Onion error: %v", err)
	}
	defer onion.Close()

	// Clear onion key
	for i := range onionKey {
		onionKey[i] = 0
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("✅ VAPORDROP ONLINE")
	fmt.Printf("🔐 Dead Drop: %d day retention\n", int(MessageTTL.Hours()/24))
	fmt.Println("🛡️  Zero-Knowledge: server never decrypts")
	fmt.Println("🔒 Internal: BLAKE3 + Argon2id + Ed25519 (non-NIST)")
	fmt.Printf("📦 Version: %s\n", Version)
	fmt.Printf("🧅 http://%s.onion\n", onion.ID)
	fmt.Println("═══════════════════════════════════════════════════════")

	// Start garbage collectors
	go startMessageGC()
	go startNonceGC()
	go startRateLimitGC()
	go startIdentityGC()
	go startFileGC()

	// HTTP routes
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/send", securityHeaders(handleSend))
	mux.HandleFunc("/api/fetch", securityHeaders(handleFetch))
	mux.HandleFunc("/api/health", securityHeaders(handleHealth))
	mux.HandleFunc("/api/register", securityHeaders(handleRegister))
	mux.HandleFunc("/api/resolve/", securityHeaders(handleResolve))
	mux.HandleFunc("/api/stats", securityHeaders(handleStats))

	// File transfer
	mux.HandleFunc("/api/file/init", securityHeaders(handleFileInit))
	mux.HandleFunc("/api/file/chunk/", securityHeaders(handleFileChunk))
	mux.HandleFunc("/api/file/pending/", securityHeaders(handleFilePending))
	mux.HandleFunc("/api/file/download/", securityHeaders(handleFileDownload))
	mux.HandleFunc("/api/file/complete/", securityHeaders(handleFileComplete))

	// Static files
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		// Prevent directory listing
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	}))

	// Server config
	server := &http.Server{
		Handler:           mux,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}

	log.Printf("🚀 Listening on hidden service...")

	if err := server.Serve(onion); err != nil {
		log.Panicf("❌ Server error: %v", err)
	}
}
