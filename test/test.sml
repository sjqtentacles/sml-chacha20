(* test.sml — ChaCha20-Poly1305 test suite.
   All expected values from RFC 8439 test vectors.
   SML does not support \x escapes; bytes are built with Char.chr. *)

structure ChaCha20Tests =
struct
  open Harness

  (* ------------------------------------------------------------------ *)
  (* ChaCha20 block function                                              *)
  (* ------------------------------------------------------------------ *)
  fun runBlock () =
    let
      val () = section "ChaCha20 block"
      val key   = String.implode (List.tabulate (32, fn i => Char.chr i))
      val nonce = String.implode
        [ Char.chr 0, Char.chr 0, Char.chr 0, Char.chr 9
        , Char.chr 0, Char.chr 0, Char.chr 0, Char.chr 74
        , Char.chr 0, Char.chr 0, Char.chr 0, Char.chr 0 ]
      val blk = ChaCha20.block key nonce 0w1
      val () = check "block produces 64 bytes" (String.size blk = 64)
      (* RFC 8439 S2.3.2 first byte = 0x10 *)
      val () = check "first byte = 0x10" (Char.ord (String.sub (blk, 0)) = 16)
    in () end

  (* ------------------------------------------------------------------ *)
  (* ChaCha20 stream cipher                                              *)
  (* ------------------------------------------------------------------ *)
  fun runEncrypt () =
    let
      val () = section "ChaCha20 stream cipher"
      val key   = String.implode (List.tabulate (32, fn i => Char.chr i))
      val nonce = String.implode
        [ Char.chr 0, Char.chr 0, Char.chr 0, Char.chr 0
        , Char.chr 0, Char.chr 0, Char.chr 0, Char.chr 74
        , Char.chr 0, Char.chr 0, Char.chr 0, Char.chr 0 ]
      val pt = "Ladies and Gentlemen of the class of '99: If I could offer you \
               \only one tip for the future, sunscreen would be it."
      val ct = ChaCha20.encrypt key nonce pt
      val () = check "ciphertext length = plaintext length"
        (String.size ct = String.size pt)
      val () = check "decrypt reverses encrypt"
        (ChaCha20.decrypt key nonce ct = pt)
      val () = check "ciphertext differs from plaintext"
        (ct <> pt)
      (* RFC 8439 S2.4.2 — first ciphertext byte = 0x6e *)
      val () = check "first ciphertext byte = 0x6e"
        (Char.ord (String.sub (ct, 0)) = 110)
    in () end

  (* ------------------------------------------------------------------ *)
  (* Poly1305 MAC                                                        *)
  (* ------------------------------------------------------------------ *)
  fun runPoly1305 () =
    let
      val () = section "Poly1305"
      (* RFC 8439 S2.5.2 one-time key (hex: 85d6be78...) *)
      val key = String.implode
        [ Char.chr 133, Char.chr 214, Char.chr 190, Char.chr 120
        , Char.chr 87,  Char.chr 85,  Char.chr 109, Char.chr 51
        , Char.chr 127, Char.chr 68,  Char.chr 82,  Char.chr 254
        , Char.chr 66,  Char.chr 213, Char.chr 6,   Char.chr 168
        , Char.chr 1,   Char.chr 3,   Char.chr 128, Char.chr 138
        , Char.chr 251, Char.chr 13,  Char.chr 178, Char.chr 253
        , Char.chr 74,  Char.chr 191, Char.chr 246, Char.chr 175
        , Char.chr 65,  Char.chr 73,  Char.chr 245, Char.chr 27 ]
      val msg = "Cryptographic Forum Research Group"
      val () = checkString "Poly1305 RFC 8439 S2.5.2"
        ( "a8061dc1305136c6c22b8baf0c0127a9"
        , Poly1305.macHex key msg )
      val () = check "tag length = 16"
        (String.size (Poly1305.mac key msg) = 16)
    in () end

  (* ------------------------------------------------------------------ *)
  (* ChaCha20-Poly1305 AEAD                                              *)
  (* ------------------------------------------------------------------ *)
  fun runAead () =
    let
      val () = section "ChaCha20-Poly1305 AEAD"
      (* RFC 8439 S2.8.2 — key = 0x808182...9f *)
      val key = String.implode (List.tabulate (32, fn i => Char.chr (128 + i)))
      (* nonce = 07 00 00 00  40 41 42 43  44 45 46 47 *)
      val nonce = String.implode
        [ Char.chr 7,   Char.chr 0,   Char.chr 0,   Char.chr 0
        , Char.chr 64,  Char.chr 65,  Char.chr 66,  Char.chr 67
        , Char.chr 68,  Char.chr 69,  Char.chr 70,  Char.chr 71 ]
      (* aad = 50 51 52 53  c0 c1 c2 c3  c4 c5 c6 c7 *)
      val aad = String.implode
        [ Char.chr 80,  Char.chr 81,  Char.chr 82,  Char.chr 83
        , Char.chr 192, Char.chr 193, Char.chr 194, Char.chr 195
        , Char.chr 196, Char.chr 197, Char.chr 198, Char.chr 199 ]
      val pt = "Ladies and Gentlemen of the class of '99: If I could offer you \
               \only one tip for the future, sunscreen would be it."
      val sealed    = ChaCha20Poly1305.seal key nonce aad pt
      val opened    = ChaCha20Poly1305.open' key nonce aad sealed
      (* Tamper last byte of the sealed blob *)
      val tampered  = String.substring (sealed, 0, String.size sealed - 1) ^
                      String.str (Char.chr ((Char.ord (String.sub (sealed, String.size sealed - 1)) + 1) mod 256))
      val badOpened = ChaCha20Poly1305.open' key nonce aad tampered
      val () = check "sealed length = pt + 16"
        (String.size sealed = String.size pt + 16)
      val () = check "open' succeeds on authentic ciphertext"
        (opened = SOME pt)
      val () = check "open' fails on tampered ciphertext"
        (badOpened = NONE)
      (* RFC 8439 S2.8.2 — first ciphertext byte = 0xd3 = 211 *)
      val () = check "first ciphertext byte = 0xd3"
        (Char.ord (String.sub (sealed, 0)) = 211)
    in () end

  (* ------------------------------------------------------------------ *)
  (* XChaCha20-Poly1305                                                  *)
  (* ------------------------------------------------------------------ *)
  fun runXChacha () =
    let
      val () = section "XChaCha20-Poly1305"
      val key   = String.implode (List.tabulate (32, fn i => Char.chr i))
      val nonce = String.implode (List.tabulate (24, fn i => Char.chr i))
      val msg   = "Hello, XChaCha20-Poly1305!"
      val aad   = "authenticated header"
      val sealed = XChaCha20Poly1305.seal key nonce aad msg
      val opened = XChaCha20Poly1305.open' key nonce aad sealed
      val () = check "seal/open roundtrip succeeds"
        (opened = SOME msg)
      val () = check "sealed length = msg + 16"
        (String.size sealed = String.size msg + 16)
      val () = check "wrong key fails"
        let val k2 = String.implode (List.tabulate (32, fn i => Char.chr (i + 1)))
        in XChaCha20Poly1305.open' k2 nonce aad sealed = NONE end
    in () end

  fun run () =
    ( runBlock ()
    ; runEncrypt ()
    ; runPoly1305 ()
    ; runAead ()
    ; runXChacha () )
end
