(* demo.sml - exercise ChaCha20, Poly1305, and ChaCha20-Poly1305 AEAD on the
   fixed RFC 8439 test vectors, printing results in hex. Deterministic: same
   bytes out on every run and compiler (no RNG, no clock, hex output only). *)

fun hex s =
  let val d = "0123456789abcdef"
  in String.concat (List.map
       (fn c => let val b = Char.ord c
                in String.implode [String.sub (d, b div 16), String.sub (d, b mod 16)] end)
       (String.explode s))
  end

(* ChaCha20 stream cipher, RFC 8439 S2.4.2 *)
val key   = String.implode (List.tabulate (32, fn i => Char.chr i))
val nonce = String.implode
  [ Char.chr 0, Char.chr 0, Char.chr 0, Char.chr 0
  , Char.chr 0, Char.chr 0, Char.chr 0, Char.chr 74
  , Char.chr 0, Char.chr 0, Char.chr 0, Char.chr 0 ]
val pt = "Ladies and Gentlemen of the class of '99: If I could offer you \
         \only one tip for the future, sunscreen would be it."
val ct = ChaCha20.encrypt key nonce pt
val () = print "ChaCha20 stream cipher (RFC 8439 S2.4.2):\n"
val () = print ("  plaintext (utf8) = " ^ pt ^ "\n")
val () = print ("  ciphertext  = " ^ hex ct ^ "\n")
val () = print ("  decrypt ok  = " ^ Bool.toString (ChaCha20.decrypt key nonce ct = pt) ^ "\n")

(* Poly1305 one-time MAC, RFC 8439 S2.5.2 *)
val pkey = String.implode
  [ Char.chr 133, Char.chr 214, Char.chr 190, Char.chr 120
  , Char.chr 87,  Char.chr 85,  Char.chr 109, Char.chr 51
  , Char.chr 127, Char.chr 68,  Char.chr 82,  Char.chr 254
  , Char.chr 66,  Char.chr 213, Char.chr 6,   Char.chr 168
  , Char.chr 1,   Char.chr 3,   Char.chr 128, Char.chr 138
  , Char.chr 251, Char.chr 13,  Char.chr 178, Char.chr 253
  , Char.chr 74,  Char.chr 191, Char.chr 246, Char.chr 175
  , Char.chr 65,  Char.chr 73,  Char.chr 245, Char.chr 27 ]
val pmsg = "Cryptographic Forum Research Group"
val () = print "\nPoly1305 one-time MAC (RFC 8439 S2.5.2):\n"
val () = print ("  message = " ^ pmsg ^ "\n")
val () = print ("  tag     = " ^ Poly1305.macHex pkey pmsg ^ "\n")

(* ChaCha20-Poly1305 AEAD, RFC 8439 S2.8.2 *)
val akey   = String.implode (List.tabulate (32, fn i => Char.chr (128 + i)))
val anonce = String.implode
  [ Char.chr 7,   Char.chr 0,   Char.chr 0,   Char.chr 0
  , Char.chr 64,  Char.chr 65,  Char.chr 66,  Char.chr 67
  , Char.chr 68,  Char.chr 69,  Char.chr 70,  Char.chr 71 ]
val aad = String.implode
  [ Char.chr 80,  Char.chr 81,  Char.chr 82,  Char.chr 83
  , Char.chr 192, Char.chr 193, Char.chr 194, Char.chr 195
  , Char.chr 196, Char.chr 197, Char.chr 198, Char.chr 199 ]
val sealed = ChaCha20Poly1305.seal akey anonce aad pt
val () = print "\nChaCha20-Poly1305 AEAD seal (RFC 8439 S2.8.2, ciphertext||tag):\n"
val () = print ("  sealed = " ^ hex sealed ^ "\n")
val () = print ("  open   = "
                ^ (case ChaCha20Poly1305.open' akey anonce aad sealed
                     of SOME m => "verified, " ^ Int.toString (String.size m) ^ " bytes"
                      | NONE   => "FAILED") ^ "\n")
