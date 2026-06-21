# sml-chacha20

ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD in pure Standard ML (RFC 8439)

## Installation

```
smlpkg add github.com/sjqtentacles/sml-chacha20
smlpkg sync
```

## Usage

```sml
(* ChaCha20-Poly1305 AEAD encrypt *)
val key   = (* 32-byte key string *)
val nonce = (* 12-byte nonce string *)
val aad   = "additional data"
val pt    = "plaintext message"

val {ciphertext, tag} = ChaCha20Poly1305.encrypt key nonce aad pt

(* Decrypt — raises Fail on authentication failure *)
val recovered = ChaCha20Poly1305.decrypt key nonce aad ciphertext tag

(* XChaCha20-Poly1305 with a 24-byte nonce (safe for random nonces) *)
val nonce24 = (* 24-byte nonce *)
val {ciphertext = ct2, tag = tag2} =
  XChaCha20Poly1305.encrypt key nonce24 aad pt

(* Raw ChaCha20 stream cipher *)
val keystream = ChaCha20.encrypt key nonce pt
```

## Testing

```
make test       # MLton
make test-poly  # Poly/ML
```

## License

MIT
