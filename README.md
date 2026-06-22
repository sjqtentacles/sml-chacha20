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

## Example

`make example` builds and runs [`examples/demo.sml`](examples/demo.sml), which
runs ChaCha20, Poly1305, and the ChaCha20-Poly1305 AEAD on the fixed RFC 8439
test vectors and prints the results in hex:

```
$ make example
ChaCha20 stream cipher (RFC 8439 S2.4.2):
  plaintext (utf8) = Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.
  ciphertext  = 6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d
  decrypt ok  = true

Poly1305 one-time MAC (RFC 8439 S2.5.2):
  message = Cryptographic Forum Research Group
  tag     = a8061dc1305136c6c22b8baf0c0127a9

ChaCha20-Poly1305 AEAD seal (RFC 8439 S2.8.2, ciphertext||tag):
  sealed = d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691
  open   = verified, 114 bytes
```

## Testing

```
make test       # MLton
make test-poly  # Poly/ML
make example    # build + run the demo
```

## License

MIT
