# VaporDrop

**Ephemeral encrypted messaging over Tor. Zero logs. RAM only. Non-NIST cryptography.**

```
 _   _                       ____                  
| | | | __ _ _ __   ___  _ _|  _ \ _ __ ___  _ __  
| | | |/ _` | '_ \ / _ \| '_| | | | '__/ _ \| '_ \ 
| |_| | (_| | |_) | (_) | | | |_| | | | (_) | |_) |
 \___/ \__,_| .__/ \___/|_| |____/|_|  \___/| .__/ 
            |_|                             |_|    
```

## Features

- **Brain Key Login** - No accounts, no registration. Your identity derives from 6+ words you remember
- **Zero-Knowledge Architecture** - Server stores only encrypted blobs, never sees plaintext
- **End-to-End Encryption** - Messages encrypted client-side before transmission
- **File Transfer** - Drag & drop files up to 1 GB, chunked and encrypted
- **Numeric ID + QR Code** - Easy sharing via `12345678-90` format
- **Contact Book** - Save contacts locally (never sent to server)
- **Auto-Expiration** - Messages and files deleted after 7 days
- **Tor Hidden Service** - Accessible only via .onion address

## Cryptography

**We reject NIST standards.** All algorithms are designed by independent cryptographers:

| Function | Algorithm | Designer |
|----------|-----------|----------|
| Key Exchange | **X25519** | Daniel J. Bernstein |
| Encryption | **XChaCha20-Poly1305** | Daniel J. Bernstein |
| Hashing | **BLAKE3** | Aumasson, O'Connor, et al. |
| Key Derivation | **Argon2id** | PHC winner (2015) |
| Signatures | **Ed25519** | Daniel J. Bernstein |

Why no NIST? [NIST collaborated with NSA to weaken Dual_EC_DRBG](https://en.wikipedia.org/wiki/Dual_EC_DRBG). Trust is broken.

## Brain Key Security

Your identity is generated from common words you can easily remember:

| Words | Entropy | Crack Time* |
|-------|---------|-------------|
| 6 words | ~80 bits | ~16 million years |
| 8 words | ~106 bits | ~10¹⁵ years |
| 12 words | ~160 bits | ~10³¹ years |

*10,000 word dictionary, 1 billion attempts/sec (unrealistic for Argon2id). Universe age: 13.8 billion years.

**Example:** `house cat moon pizza sea sun` → unique cryptographic identity

- Same words = same identity, always, on any device
- Forget words = lose access forever (no recovery)
- Never store digitally - keep in your head

## Self-Hosting

### Requirements

- Docker + Docker Compose
- Linux server (VPS or dedicated)

### Quick Start

```bash
# Clone repository
git clone https://github.com/virebent/vapordrop.git
cd vapordrop

# Create environment file with your passphrase
echo "VAPOR_KEY=your-secret-passphrase-min-16-chars" > .env
chmod 600 .env

# Build and start
docker compose up -d --build

# View logs (wait for .onion address)
docker compose logs -f
```

Your .onion address will appear in the logs:

```
✅ VAPORDROP ONLINE
🧅 http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion
```

### Commands

```bash
# Start
docker compose up -d --build

# Stop
docker compose down

# View logs
docker compose logs -f

# Destroy everything (including volumes)
docker compose down -v
```

### VAPOR_KEY

The `VAPOR_KEY` passphrase:

- Derives the **Ed25519 key** for your Tor hidden service
- Determines your **.onion address**
- Same passphrase = same .onion address (reproducible)
- **Does NOT encrypt messages** (that's done client-side with user keys)

Store it in `.env` file with `chmod 600`. Never commit to git.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLIENT                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Brain Key  │→ │   X25519    │→ │ XChaCha20-Poly1305  │  │
│  │  (6+ words) │  │  Key Pair   │  │    Encryption       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Encrypted blob only
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     SERVER (Zero-Knowledge)                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Tor HS    │  │  RAM-only   │  │   Auto-expiration   │  │
│  │  (Ed25519)  │  │   Storage   │  │     (7 days)        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Server never sees:**
- Plaintext messages
- Encryption keys
- Brain keys
- Contact lists

## Security Features

### Traffic Analysis Protection
- Random padding on all messages
- Randomized response delays
- Constant-time comparisons

### Anti-Replay
- Nonce cache with 24h expiration
- BLAKE3 hashed nonces for privacy

### Rate Limiting
- Session-based (Tor-compatible, not IP-based)
- Prevents abuse without deanonymization

### Memory Protection
- Uses `memguard` for sensitive data
- Keys zeroed after use
- No swap, RAM only

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/register` | POST | Register numeric ID → public key mapping |
| `/api/resolve/{id}` | GET | Resolve numeric ID to public key(s) |
| `/api/send` | POST | Send encrypted message |
| `/api/fetch` | POST | Fetch and delete messages |
| `/api/file/init` | POST | Initialize file transfer |
| `/api/file/chunk/{id}/{n}` | POST | Upload encrypted chunk |
| `/api/file/pending/{pubkey}` | GET | List pending files |
| `/api/file/download/{id}/{n}` | GET | Download chunk |
| `/api/file/complete/{id}` | POST | Mark transfer complete, delete |
| `/api/health` | GET | Health check |
| `/api/stats` | GET | Public statistics |

## File Structure

```
vapordrop/
├── main.go              # Backend server
├── go.mod               # Go dependencies
├── Dockerfile           # Multi-stage build
├── docker-compose.yml   # Container orchestration
├── .env                 # VAPOR_KEY (create this, never commit)
├── .gitignore           # Excludes .env
├── .dockerignore        # Excludes .env from build
└── static/
    ├── index.html       # Application
    └── home.html        # Landing page
```

## Threat Model

### Protects Against

- ✅ Mass surveillance (Tor + E2E encryption)
- ✅ Server seizure (encrypted blobs without keys are useless)
- ✅ NIST backdoors (we don't use NIST algorithms)
- ✅ Metadata collection (no logs, no accounts, RAM only)
- ✅ Traffic analysis (random padding + timing delays)
- ✅ Replay attacks (nonce cache with expiration)

### Limitations

- ❌ Compromised endpoint (malware on your device)
- ❌ Screenshot by recipient
- ❌ State-level Tor correlation attacks
- ❌ Quantum computers (future threat to X25519)

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add feature'`)
4. Push branch (`git push origin feature/improvement`)
5. Open Pull Request

## License

MIT License - See [LICENSE](LICENSE) file.

## Acknowledgments

- [Daniel J. Bernstein](https://cr.yp.to/) - X25519, ChaCha20, Poly1305, Ed25519
- [BLAKE3 Team](https://github.com/BLAKE3-team/BLAKE3) - BLAKE3 hash function
- [Tor Project](https://www.torproject.org/) - Anonymous communication
- [bine](https://github.com/cretz/bine) - Go Tor library

---

**No logs. No traces. No NIST. No compromise.**
