package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/awnumar/memguard"
	"github.com/cretz/bine/tor"
	"golang.org/x/crypto/argon2"
)

// =============================================================================
// COSTANTI DI SICUREZZA
// =============================================================================

const (
	// Message retention - 7 giorni per dead drop
	MessageTTL = 7 * 24 * time.Hour
	GCInterval = 30 * time.Minute

	// Anti-replay
	NonceExpiration = 24 * time.Hour
	MaxNonceCache   = 100000

	// Rate limiting per session token (Tor-compatible)
	RateLimitWindow  = 1 * time.Minute
	MaxRequestsPerIP = 60

	// Padding
	MinPadding = 256
	MaxPadding = 4096

	// Timing jitter
	MinDelay = 50 * time.Millisecond
	MaxDelay = 500 * time.Millisecond

	// Argon2id parameters
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32

	// Identity Registry
	MaxIdentities = 100000
	IdentityTTL   = 7 * 24 * time.Hour // 7 giorni come i messaggi

	// File Transfer
	MaxFileSize     = 1 << 30
	FileChunkSize   = 1 << 20
	FileTTL         = 7 * 24 * time.Hour
	FileGCInterval  = 1 * time.Hour
	MaxPendingFiles = 1000
	FileStorageDir  = "./file_storage"
)

// =============================================================================
// STRUTTURE DATI
// =============================================================================

type Message struct {
	ToHash     string    `json:"to_hash"`
	CipherBlob string    `json:"cipher_blob"`
	Nonce      string    `json:"nonce"`
	Padding    string    `json:"padding"`
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
// STORAGE VOLATILI (SOLO RAM)
// =============================================================================

var (
	store           = make(map[string][]Message)
	storeMutex      sync.RWMutex
	nonceCache      = make(map[string]time.Time)
	nonceCacheMutex sync.RWMutex
	rateLimiter     = make(map[string]*RateLimitEntry)
	rateLimiterMutex sync.RWMutex
	numericIdToKeys = make(map[string][]string)
	keyToNumericId  = make(map[string]string)
	keyLastSeen     = make(map[string]time.Time)
	identityMutex   sync.RWMutex
	fileTransfers   = make(map[string]*FileTransfer)
	fileTransfersMutex sync.RWMutex
)

// =============================================================================
// FUNZIONI DI SICUREZZA
// =============================================================================

func generatePadding(minSize, maxSize int) string {
	size := minSize
	if maxSize > minSize {
		var sizeBuf [2]byte
		rand.Read(sizeBuf[:])
		size = minSize + int(sizeBuf[0])%(maxSize-minSize)
	}
	padding := make([]byte, size)
	rand.Read(padding)
	return hex.EncodeToString(padding)
}

func randomDelay() {
	var delayBuf [2]byte
	rand.Read(delayBuf[:])
	delayRange := MaxDelay - MinDelay
	delay := MinDelay + time.Duration(int(delayBuf[0])*int(delayRange)/256)
	time.Sleep(delay)
}

func constantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		subtle.ConstantTimeCompare([]byte(a), []byte(a))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func checkNonce(nonce string) bool {
	if len(nonce) < 32 {
		return false
	}
	nonceCacheMutex.Lock()
	defer nonceCacheMutex.Unlock()
	if _, exists := nonceCache[nonce]; exists {
		return false
	}
	if len(nonceCache) >= MaxNonceCache {
		cutoff := time.Now().Add(-NonceExpiration)
		for n, t := range nonceCache {
			if t.Before(cutoff) {
				delete(nonceCache, n)
			}
		}
	}
	nonceCache[nonce] = time.Now()
	return true
}

func checkRateLimit(ip string) bool {
	rateLimiterMutex.Lock()
	defer rateLimiterMutex.Unlock()
	now := time.Now()
	entry, exists := rateLimiter[ip]
	if !exists || now.After(entry.ResetTime) {
		rateLimiter[ip] = &RateLimitEntry{Count: 1, ResetTime: now.Add(RateLimitWindow)}
		return true
	}
	if entry.Count >= MaxRequestsPerIP {
		return false
	}
	entry.Count++
	return true
}

func getClientIP(r *http.Request) string {
	return r.RemoteAddr
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
	if !checkRateLimit(getClientIP(r)) {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	var req struct {
		NumericID string `json:"numeric_id"`
		PublicKey string `json:"public_key"`
		Nonce     string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate numeric ID: 8 digits or 8-2 format
	if len(req.NumericID) != 11 && len(req.NumericID) != 8 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_numeric_id"}`))
		return
	}
	if len(req.NumericID) == 11 && req.NumericID[8] != '-' {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_numeric_id_format"}`))
		return
	}

	// Validate public key (130 hex = P-256 uncompressed)
	if len(req.PublicKey) != 130 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_public_key_length"}`))
		return
	}

	if len(req.Nonce) >= 32 && !checkNonce(req.Nonce) {
		http.Error(w, "Replay detected", http.StatusConflict)
		return
	}

	identityMutex.Lock()
	defer identityMutex.Unlock()

	now := time.Now()
	if existingId, exists := keyToNumericId[req.PublicKey]; exists {
		keyLastSeen[req.PublicKey] = now
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "exists",
			"numeric_id": existingId,
			"collision":  len(numericIdToKeys[existingId]) > 1,
		})
		return
	}

	if len(keyToNumericId) >= MaxIdentities {
		http.Error(w, "Max identities reached", http.StatusServiceUnavailable)
		return
	}

	numericIdToKeys[req.NumericID] = append(numericIdToKeys[req.NumericID], req.PublicKey)
	shortId := strings.Split(req.NumericID, "-")[0]
	if shortId != req.NumericID {
		numericIdToKeys[shortId] = append(numericIdToKeys[shortId], req.PublicKey)
	}
	keyToNumericId[req.PublicKey] = req.NumericID
	keyLastSeen[req.PublicKey] = now

	hasCollision := len(numericIdToKeys[req.NumericID]) > 1
	if hasCollision {
		log.Printf("⚠️  COLLISION: ID %s has %d keys", req.NumericID, len(numericIdToKeys[req.NumericID]))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "registered",
		"numeric_id": req.NumericID,
		"collision":  hasCollision,
	})
}

func handleResolve(w http.ResponseWriter, r *http.Request) {
	randomDelay()
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkRateLimit(getClientIP(r)) {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/resolve/")
	if path == "" {
		http.Error(w, "Missing ID", http.StatusBadRequest)
		return
	}

	identityMutex.RLock()
	keys, exists := numericIdToKeys[path]
	identityMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if !exists || len(keys) == 0 {
		w.Write([]byte(`{"numeric_id":"","public_keys":[],"found":false}`))
		return
	}

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
	totalKeys := len(keyToNumericId)
	collisions := 0
	for id, keys := range numericIdToKeys {
		if strings.Contains(id, "-") && len(keys) > 1 {
			collisions++
		}
	}
	identityMutex.RUnlock()

	storeMutex.RLock()
	pendingMsgs := 0
	for _, msgs := range store {
		pendingMsgs += len(msgs)
	}
	storeMutex.RUnlock()

	fileTransfersMutex.RLock()
	pendingFiles := len(fileTransfers)
	fileTransfersMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"registered_identities": totalKeys,
		"id_collisions":         collisions,
		"pending_messages":      pendingMsgs,
		"pending_files":         pendingFiles,
	})
}

// =============================================================================
// MESSAGE HANDLERS
// =============================================================================

func handleSend(w http.ResponseWriter, r *http.Request) {
	randomDelay()
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkRateLimit(getClientIP(r)) {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		log.Printf("❌ Send: Invalid JSON: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate P-256 uncompressed = 130 hex
	if len(msg.ToHash) != 130 {
		log.Printf("❌ Send: Invalid to_hash length: %d (expected 130)", len(msg.ToHash))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_to_hash","expected":130,"got":` + fmt.Sprintf("%d", len(msg.ToHash)) + `}`))
		return
	}

	if len(msg.CipherBlob) < 32 {
		log.Printf("❌ Send: CipherBlob too short: %d", len(msg.CipherBlob))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"cipher_blob_too_short"}`))
		return
	}

	if len(msg.Nonce) < 32 {
		log.Printf("❌ Send: Nonce too short: %d", len(msg.Nonce))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"nonce_too_short"}`))
		return
	}

	if !checkNonce(msg.Nonce) {
		log.Printf("❌ Send: Replay attack detected")
		http.Error(w, "Replay detected", http.StatusConflict)
		return
	}

	if len(msg.Padding) == 0 {
		msg.Padding = generatePadding(MinPadding, MaxPadding)
	}

	msg.Timestamp = time.Now()
	storeMutex.Lock()
	store[msg.ToHash] = append(store[msg.ToHash], msg)
	storeMutex.Unlock()

	log.Printf("✅ Message stored for %s...%s", msg.ToHash[:8], msg.ToHash[len(msg.ToHash)-8:])

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Write([]byte(`{"status":"ok"}`))
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	randomDelay()
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkRateLimit(getClientIP(r)) {
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
		return
	}

	var req struct {
		MyHash string `json:"my_hash"`
		Nonce  string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.MyHash) != 130 {
		log.Printf("❌ Fetch: Invalid my_hash length: %d", len(req.MyHash))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_my_hash"}`))
		return
	}

	if len(req.Nonce) < 32 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"nonce_too_short"}`))
		return
	}

	if !checkNonce(req.Nonce) {
		http.Error(w, "Replay detected", http.StatusConflict)
		return
	}

	storeMutex.Lock()
	var msgs []Message
	for hash, m := range store {
		if constantTimeCompare(hash, req.MyHash) {
			msgs = m
			delete(store, hash)
			break
		}
	}
	storeMutex.Unlock()

	response := struct {
		Messages []Message `json:"messages"`
		Padding  string    `json:"padding"`
	}{
		Messages: msgs,
		Padding:  generatePadding(MinPadding, MaxPadding),
	}

	if msgs == nil {
		response.Messages = []Message{}
	} else {
		log.Printf("📨 Delivered %d messages to %s...%s", len(msgs), req.MyHash[:8], req.MyHash[len(req.MyHash)-8:])
	}

	for i := range response.Messages {
		response.Messages[i].Padding = ""
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	randomDelay()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"alive"}`))
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
	if !checkRateLimit(getClientIP(r)) {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ FileInit: Invalid JSON: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_json"}`))
		return
	}

	// Validate public keys
	if len(req.FromPubKey) != 130 {
		log.Printf("❌ FileInit: Invalid from_pubkey length: %d", len(req.FromPubKey))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_from_pubkey","length":` + fmt.Sprintf("%d", len(req.FromPubKey)) + `}`))
		return
	}
	if len(req.ToPubKey) != 130 {
		log.Printf("❌ FileInit: Invalid to_pubkey length: %d", len(req.ToPubKey))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_to_pubkey","length":` + fmt.Sprintf("%d", len(req.ToPubKey)) + `}`))
		return
	}

	if req.FileSize <= 0 || req.FileSize > MaxFileSize {
		log.Printf("❌ FileInit: Invalid filesize: %d", req.FileSize)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_filesize"}`))
		return
	}

	if req.ChunkCount <= 0 || req.ChunkCount > int(MaxFileSize/FileChunkSize)+1 {
		log.Printf("❌ FileInit: Invalid chunk_count: %d", req.ChunkCount)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_chunk_count"}`))
		return
	}

	fileTransfersMutex.RLock()
	if len(fileTransfers) >= MaxPendingFiles {
		fileTransfersMutex.RUnlock()
		log.Printf("❌ FileInit: Too many pending files")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"too_many_pending_files"}`))
		return
	}
	fileTransfersMutex.RUnlock()

	// Generate unique file ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	fileID := hex.EncodeToString(idBytes)

	// Create file directory
	filePath := fmt.Sprintf("%s/%s", FileStorageDir, fileID)
	if err := os.MkdirAll(filePath, 0700); err != nil {
		log.Printf("❌ FileInit: Cannot create directory: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"storage_error"}`))
		return
	}

	ft := &FileTransfer{
		ID:             fileID,
		FromPubKey:     req.FromPubKey,
		ToPubKey:       req.ToPubKey,
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

	log.Printf("📁 File transfer initialized: %s (%d bytes, %d chunks)", fileID, req.FileSize, req.ChunkCount)

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

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/file/chunk/"), "/")
	if len(parts) != 2 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	fileID := parts[0]
	chunkNum := 0
	fmt.Sscanf(parts[1], "%d", &chunkNum)

	fileTransfersMutex.RLock()
	ft, exists := fileTransfers[fileID]
	fileTransfersMutex.RUnlock()

	if !exists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"file_not_found"}`))
		return
	}

	if chunkNum < 0 || chunkNum >= ft.ChunkCount {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_chunk_number"}`))
		return
	}

	maxChunkSize := FileChunkSize + 1024
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxChunkSize))
	chunkData, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("❌ FileChunk: Read error: %v", err)
		http.Error(w, "Read error", http.StatusBadRequest)
		return
	}

	chunkPath := fmt.Sprintf("%s/%s/%d", FileStorageDir, fileID, chunkNum)
	if err := os.WriteFile(chunkPath, chunkData, 0600); err != nil {
		log.Printf("❌ FileChunk: Write error: %v", err)
		http.Error(w, "Write error", http.StatusInternalServerError)
		return
	}

	fileTransfersMutex.Lock()
	ft.ChunksReceived++
	if ft.ChunksReceived >= ft.ChunkCount {
		ft.Ready = true
		log.Printf("📁 File ready: %s", fileID)
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
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pubkey := strings.TrimPrefix(r.URL.Path, "/api/file/pending/")
	if len(pubkey) != 130 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_pubkey"}`))
		return
	}

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

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/file/download/"), "/")
	if len(parts) != 2 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	fileID := parts[0]
	chunkNum := 0
	fmt.Sscanf(parts[1], "%d", &chunkNum)

	fileTransfersMutex.RLock()
	ft, exists := fileTransfers[fileID]
	fileTransfersMutex.RUnlock()

	if !exists || !ft.Ready {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if chunkNum < 0 || chunkNum >= ft.ChunkCount {
		http.Error(w, "Invalid chunk", http.StatusBadRequest)
		return
	}

	chunkPath := fmt.Sprintf("%s/%s/%d", FileStorageDir, fileID, chunkNum)
	chunkData, err := os.ReadFile(chunkPath)
	if err != nil {
		http.Error(w, "Read error", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(chunkData)
}

func handleFileComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fileID := strings.TrimPrefix(r.URL.Path, "/api/file/complete/")
	if fileID == "" {
		http.Error(w, "Missing file ID", http.StatusBadRequest)
		return
	}

	fileTransfersMutex.Lock()
	_, exists := fileTransfers[fileID]
	if exists {
		delete(fileTransfers, fileID)
	}
	fileTransfersMutex.Unlock()

	if !exists {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	filePath := fmt.Sprintf("%s/%s", FileStorageDir, fileID)
	if err := os.RemoveAll(filePath); err != nil {
		log.Printf("⚠️  FileComplete: Cleanup error: %v", err)
	} else {
		log.Printf("🗑️  File deleted: %s", fileID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"deleted"}`))
}

// =============================================================================
// GARBAGE COLLECTORS
// =============================================================================

func startMessageGC() {
	for {
		time.Sleep(GCInterval)
		storeMutex.Lock()
		cutoff := time.Now().Add(-MessageTTL)
		removed := 0
		for h, msgs := range store {
			var keep []Message
			for _, m := range msgs {
				if m.Timestamp.After(cutoff) {
					keep = append(keep, m)
				} else {
					removed++
				}
			}
			if len(keep) > 0 {
				store[h] = keep
			} else {
				delete(store, h)
			}
		}
		storeMutex.Unlock()
		if removed > 0 {
			log.Printf("🧹 Message GC: removed %d expired", removed)
		}
	}
}

func startNonceGC() {
	for {
		time.Sleep(NonceExpiration / 2)
		nonceCacheMutex.Lock()
		cutoff := time.Now().Add(-NonceExpiration)
		removed := 0
		for n, t := range nonceCache {
			if t.Before(cutoff) {
				delete(nonceCache, n)
				removed++
			}
		}
		nonceCacheMutex.Unlock()
		if removed > 0 {
			log.Printf("🧹 Nonce GC: removed %d expired", removed)
		}
	}
}

func startRateLimitGC() {
	for {
		time.Sleep(RateLimitWindow)
		rateLimiterMutex.Lock()
		now := time.Now()
		for ip, entry := range rateLimiter {
			if now.After(entry.ResetTime) {
				delete(rateLimiter, ip)
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
		removed := 0
		for pubkey, lastSeen := range keyLastSeen {
			if lastSeen.Before(cutoff) {
				numericId := keyToNumericId[pubkey]
				if keys, exists := numericIdToKeys[numericId]; exists {
					var newKeys []string
					for _, k := range keys {
						if k != pubkey {
							newKeys = append(newKeys, k)
						}
					}
					if len(newKeys) > 0 {
						numericIdToKeys[numericId] = newKeys
					} else {
						delete(numericIdToKeys, numericId)
					}
				}
				shortId := strings.Split(numericId, "-")[0]
				if keys, exists := numericIdToKeys[shortId]; exists {
					var newKeys []string
					for _, k := range keys {
						if k != pubkey {
							newKeys = append(newKeys, k)
						}
					}
					if len(newKeys) > 0 {
						numericIdToKeys[shortId] = newKeys
					} else {
						delete(numericIdToKeys, shortId)
					}
				}
				delete(keyToNumericId, pubkey)
				delete(keyLastSeen, pubkey)
				removed++
			}
		}
		identityMutex.Unlock()
		if removed > 0 {
			log.Printf("🧹 Identity GC: removed %d inactive", removed)
		}
	}
}

func startFileGC() {
	os.MkdirAll(FileStorageDir, 0700)
	for {
		time.Sleep(FileGCInterval)
		fileTransfersMutex.Lock()
		cutoff := time.Now().Add(-FileTTL)
		removed := 0
		for id, ft := range fileTransfers {
			if ft.CreatedAt.Before(cutoff) {
				filePath := fmt.Sprintf("%s/%s", FileStorageDir, id)
				os.RemoveAll(filePath)
				delete(fileTransfers, id)
				removed++
			}
		}
		fileTransfersMutex.Unlock()
		if removed > 0 {
			log.Printf("🧹 File GC: removed %d expired", removed)
		}
	}
}

// =============================================================================
// MAIN
// =============================================================================

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	envKey := os.Getenv("VAPOR_KEY")
	if len(envKey) < 16 {
		log.Fatal("❌ VAPOR_KEY missing or too short (min 16 chars)")
	}

	fmt.Println("⚙️  Key derivation with Argon2id (~64MB RAM, ~1 sec)...")

	secretEnclave := memguard.NewBufferFromBytes([]byte(envKey))
	for i := range envKey {
		envKey = envKey[:i] + "X" + envKey[i+1:]
	}
	envKey = ""

	saltInput := "vapordrop-v1-onion-key-derivation-salt"
	salt := sha256.Sum256([]byte(saltInput))

	seed := argon2.IDKey(
		secretEnclave.Bytes(),
		salt[:],
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLen,
	)
	secretEnclave.Destroy()

	for i := range salt {
		salt[i] = 0
	}

	onionKey := ed25519.NewKeyFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	seed = nil

	fmt.Println("⚙️  Starting VaporDrop Node...")

	conf := &tor.StartConf{
		TempDataDirBase: os.TempDir(),
		NoAutoSocksPort: true,
	}

	t, err := tor.Start(context.Background(), conf)
	if err != nil {
		log.Panicf("❌ Tor Start Error: %v", err)
	}
	defer t.Close()

	fmt.Println("⚙️  Creating Onion Service v3...")

	listenCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	onion, err := t.Listen(listenCtx, &tor.ListenConf{
		Version3:    true,
		Key:         onionKey,
		RemotePorts: []int{80},
	})
	if err != nil {
		log.Panicf("❌ Onion Listen Error: %v", err)
	}
	defer onion.Close()

	for i := range onionKey {
		onionKey[i] = 0
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf("✅ VAPORDROP ONLINE\n")
	fmt.Printf("🛡️  Key: Argon2id (64MB, 3 iter)\n")
	fmt.Printf("🛡️  Protections: RAM Lock, Anti-Replay, Rate Limit, Padding\n")
	fmt.Printf("📦 Message TTL: 7 days\n")
	fmt.Printf("📁 File TTL: 7 days\n")
	fmt.Printf("🔗 http://%v.onion\n", onion.ID)
	fmt.Println("═══════════════════════════════════════════════════════")

	go startMessageGC()
	go startNonceGC()
	go startRateLimitGC()
	go startIdentityGC()
	go startFileGC()

	mux := http.NewServeMux()

	// Message endpoints
	mux.HandleFunc("/api/send", handleSend)
	mux.HandleFunc("/api/fetch", handleFetch)
	mux.HandleFunc("/api/health", handleHealth)

	// Identity registry
	mux.HandleFunc("/api/register", handleRegister)
	mux.HandleFunc("/api/resolve/", handleResolve)
	mux.HandleFunc("/api/stats", handleStats)

	// File transfer
	mux.HandleFunc("/api/file/init", handleFileInit)
	mux.HandleFunc("/api/file/chunk/", handleFileChunk)
	mux.HandleFunc("/api/file/pending/", handleFilePending)
	mux.HandleFunc("/api/file/download/", handleFileDownload)
	mux.HandleFunc("/api/file/complete/", handleFileComplete)

	// Static files
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/", fs)

	server := &http.Server{
		Handler:           mux,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	if err := server.Serve(onion); err != nil {
		log.Panicf("❌ HTTP Error: %v", err)
	}
}
