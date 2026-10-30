# secret-manager-crypto-utils 

## Background
Starting with the [Secret Management](https://hackmd.io/PZjpRfzPSBCqS-8K54x2jA) the requirement of a set of specific cryptographic functions arose. 
This evolved to a neat cryptographic backbone based on Curve25519, AES and SHA-2.
Usable in the backend and the frontend.

It is:
- sha256
- sha512
- Sign/Verify via Ed25519 (native WebCrypto where available, noble fallback - same results everywhere)
- Asymmetric Encrypt/Decrypt in ElGamal style using X25519 (native WebCrypto where available, noble fallback)
- Symmetric Encrypt/Decrypt with AES-256-GCM ([format v1](#symmetric-format-v1)). Data of older versions is read by the separate [legacy entry point](#legacy-entry-point)
- Password based key derivation (PBKDF2-SHA256)
- DiffieHellman style sharedSecret as `privA * pubB = privB * pubA` in Raw and Hashed version
- ElGamal style sharedSecret using an ephemeral random `privA` and providing the referencePoint `pubA` in Raw and Hashed version


There is a convenience package around this - the [Thingy-Crypto-Node](https://www.npmjs.com/package/thingy-crypto-node)

## Usage
One implementation on WebCrypto for node (>= 20), deno, bun, browsers and workers. Every function returns a Promise.

Ed25519 and X25519 run natively in WebCrypto where the runtime has them (node, deno, bun, current browsers), and on [noble-ed25519](#noble-ed25519) otherwise. Both paths give the same bytes and the same verification answers, and the test suite runs on each of them. Exceptions: [WebKitGTK](#known-runtime-issues).

```js
import * as secUtl from "secret-manager-crypto-utils"

const { secretKeyHex, publicKeyHex } = await secUtl.createKeyPair()
const sig = await secUtl.createSignature("hello", secretKeyHex)
const err = await secUtl.verifySignature(sig, publicKeyHex, "hello")
if (err) throw new Error(err) // "Invalid signature!" or "Malformed input!"

const secrets = await secUtl.asymmetricEncrypt("my secret", publicKeyHex)
await secUtl.asymmetricDecrypt(secrets, secretKeyHex) // "my secret"

const keyHex = await secUtl.createSymKey()
const gibbrish = await secUtl.symmetricEncrypt("my secret", keyHex)
await secUtl.symmetricDecrypt(gibbrish, keyHex) // "my secret"
```

### verifySignature
**`verifySignature` resolves `undefined` when the signature is valid, and an error string when it is not. It never throws.**

- valid → `undefined`
- wrong signature, key or content → `"Invalid signature!"`
- malformed input (bad hex, wrong lengths, wrong types, lone surrogates) → `"Malformed input!"`

So the check is `if (err)`, and a forgotten `await` fails closed, because a Promise is truthy:

```js
const err = await secUtl.verifySignature(sig, publicKey, content)
if (err) return reject(err)
// valid from here
```

Migrating from `verify` (≤ 0.3.x), which resolved `true` for a valid signature:

```js
// before
if (!(await secUtl.verify(sig, publicKey, content))) return reject()
// now - mind the inverted meaning
if (await secUtl.verifySignature(sig, publicKey, content)) return reject()
```

Every other function throws on malformed input.

### Parameter conventions
- One function per operation. Keys and byte data are hex strings or `Uint8Array`s, and **the key decides the mode**: a hex key gives hex results, a `Uint8Array` key gives `Uint8Array` results. For Diffie-Hellman the `secretKey` decides. Other byte arguments may come in either form.
- Returned objects name the mode in their properties (`…Hex` / `…Bytes`).
- Functions without a key return hex and have a `…Bytes` variant: `sha256`, `sha512`, `createKeyPair`, `createSymKey`. The `Hex` in `sha256Hex` (≤ 0.3.x) meant the *output*, the input was always content.
- Content (`contentString`) is always a `string`. Only the shas also take a `Uint8Array`.
- Mind the argument order: `createSignature(contentString, secretKey)`, but `verifySignature(signature, publicKey, contentString)`.
- **Hex output is always lowercase. Hex input is case-insensitive.** Compare keys lowercased or as bytes, never as raw strings from different sources.

```js
// shas - content: string or Uint8Array
sha256(content) -> hex
sha512(content) -> hex
sha256Bytes(content) -> Uint8Array
sha512Bytes(content) -> Uint8Array

// keys - 32 byte secret keys
createKeyPair() -> { secretKeyHex, publicKeyHex }
createKeyPairBytes() -> { secretKeyBytes, publicKeyBytes }
createSymKey() -> hex          // 48 bytes
createSymKeyBytes() -> Uint8Array
createPublicKey(secretKey) -> publicKey

// signatures (ed25519, strict RFC 8032)
createSignature(contentString, secretKey) -> signature
// undefined when valid, else an error string - never throws
verifySignature(signature, publicKey, contentString) -> undefined | string

// symmetric encryption (AES-256-GCM, format v1) - key: >= 48 bytes
// context: optional, authenticated (GCM additionalData) but not stored - decrypt needs the same one
symmetricEncrypt(contentString, key, context = "") -> gibbrish
symmetricDecrypt(gibbrish, key, context = "") -> contentString

// password based key derivation - passwords only, iterations 1000..10000000
// store saltHex and iterations next to the ciphertext, they are needed to derive the same key again
deriveSymKeyFromPassword(password, saltHex = random 16 bytes, iterations = 600000) -> { keyHex, saltHex, iterations }

// asymmetric encryption (ElGamal style), context as for symmetric
asymmetricEncrypt(contentString, publicKey, context = "") -> { referencePointHex, encryptedContentHex } | { referencePointBytes, encryptedContentBytes }
// secrets: either shape above
asymmetricDecrypt(secrets, secretKey, context = "") -> contentString

// Diffie-Hellman shared secret: X25519 of our secretKey and their publicKey
diffieHellmanSecretRaw(secretKey, publicKey) -> secret (32 bytes)
// sha512(raw ‖ lower publicKey ‖ higher publicKey ‖ utf8(context))
diffieHellmanSecretHash(secretKey, publicKey, context = "") -> secret (64 bytes)

// ElGamal shared secret: ephemeral secretKey * their publicKey, referencePoint = ephemeral publicKey
elGamalSecretRaw(publicKey) -> { referencePointHex, sharedSecretHex } | { referencePointBytes, sharedSecretBytes }
elGamalSecretHash(publicKey, context = "") -> { referencePointHex, sharedSecretHex } | { referencePointBytes, sharedSecretBytes }
```

Errors: invalid hex → `SyntaxError`; content that is not a well-formed string, or bytes that are not a `Uint8Array` → `TypeError`; wrong key lengths, small-order public keys, short KDF salt, iterations out of range → `RangeError`; any decryption failure → `Error("Decryption failed!")`. `verifySignature` is the exception: it never throws.

## Breaking Updates
`0.3.x` -> `0.4.y`
------------------
- `symmetricEncrypt` writes [format v1](#symmetric-format-v1) (AES-256-GCM), and the main API **reads v1 only**. Older ciphertext is read by the [legacy entry point](#legacy-entry-point). v0.3.x cannot decrypt v1 - update readers before writers.
- `verify` is replaced by [`verifySignature`](#verifysignature): it resolves `undefined` when valid and an error string otherwise, and never throws.
- **One export per function:** `foo(…)` takes hex or bytes, the key decides what comes back. Code using the unsuffixed (hex) names keeps working. The `…Hex` and `…Bytes` exports are gone - except `sha256Bytes`, `sha512Bytes`, `createKeyPairBytes` and `createSymKeyBytes` - and so are the aliases `createSharedSecret*`, `sharedSecret*Bytes` and `referenced(Shared)Secret*`.
- `sha256`/`sha512` are async on node too (they always were in the browser), and `createSymKey` is async, like every other function.
- `saltContent`/`unsaltContent` are removed.
- **Shared secrets changed:**
  - Raw Diffie-Hellman and ElGamal secrets are X25519 again (the same values as v0.2.0), not the Edwards point of v0.3.x.
  - Hashed secrets also bind both public keys: `sha512(raw ‖ lower publicKey ‖ higher publicKey ‖ utf8(context))`. They differ from every earlier version.
  - Anything keyed by an old secret has to be re-derived.
- Asymmetric encryption uses `sha512(shared ‖ referencePoint)` as key, on top of the new shared secret.
- `asymmetricDecrypt` no longer reads the unsuffixed `{ referencePoint, encryptedContent }` of 0.0.x - `asymmetricDecryptV0_0_7` does.
- ed25519 secret keys must be exactly 32 bytes, symmetric keys at least 48 bytes, signatures 64 bytes.
- Small-order public keys are rejected everywhere, and verification is strict RFC 8032 (no ZIP-215).
- Strings with lone surrogates (`"a\uD800"`) throw instead of being silently changed to `"a�"`.
- Node >= 20.

`0.2.x` -> `0.3.y`
------------------
Since `v0.3.0` we have fixed some security concerns rooting from unauthenticated and unpadded use of AES-CBC.

This is the new salt function has changed significantly. It wraps the plaintext into an padded and verifiable envelope of random numbers.

Also as a result of this we use this salt on our symmetricEncrypt function directly and don't leave it up to the developer to manually add the salt or not.

Also we decided to ditch backwards compatibility from this point dropping:

- assymetricEncryptOld
- assymetricDecryptOld
- createRandomLengthSalt
- removeSalt

**Notice:** the inner Workings of the asymmetric encryption has changend. (Now we are sticking with the Edwards curve for multiplication instead of a Point Transformation to Montgomery coordinates for calculating the shared secret) 

These changes meant that 0.3.x could not decrypt secrets encrypted with an earlier version. Since 0.4.0 the [legacy entry point](#legacy-entry-point) reads all of them.

## Hex FTW
It is advisable that you store all encrypted contents, signatures and keys in hex strings. This appears to be the most superior way of how to universally transfer byte information.

The big wins of hex in readability and processability beats out the "downside" of being 2x the size. For keys, signatures and short content the conversion costs less than 1µs - not measurable next to the crypto. Only large content pays: at 1 MB hex encryption is ~1.5-3x and decryption up to ~10x slower than bytes. Pass a `Uint8Array` key there and you get bytes back.


## Encryption
For the asymmetric encryption we use the ed25519 keys for an ElGamal-style X25519 shared secret with a one-time key. The symmetric key is `sha512(shared ‖ referencePoint)`, which then encrypts the content in [format v1](#symmetric-format-v1).

The result of this kind of encryption is always an Object like:
```json
{
    "referencePointHex":"...",  // StringHex
    "encryptedContentHex":"...",  // StringHex
}
```

### Symmetric format v1
```
0x01 ‖ nonce(12) ‖ AES-256-GCM( padLen(1) ‖ utf8(content) ‖ random(padLen) ) ‖ tag(16)
```
- The AES key is bytes 16..47 of the symmetric key (48 bytes from `createSymKey`, or the 64 byte `sha512` on the asymmetric path). Bytes 0..15 were the legacy CBC IV and are not used by v1.
- The nonce is 12 random bytes per message, never a parameter. With random nonces, keep it to about 2^32 messages per key.
- The tag is 128 bits. WebCrypto verifies it before releasing any plaintext, so a single flipped bit makes decryption fail.
- `padLen` is random 0-255 and hides the exact content length (to within 256 bytes). It is inside the authenticated data.
- The context is GCM additional data: authenticated, but not part of the ciphertext.
- Every failure is one generic `Error("Decryption failed!")`, which never says why.

### Legacy entry point
The main API reads format v1 only. Data written by older versions is read by `secret-manager-crypto-utils/legacy`, read-side only, to convert it. It will be removed once the deprecated systems are migrated.

**Migration:** find the version that wrote your data, read it with its legacy function, and write it again with the main API.

```js
import * as legacy from "secret-manager-crypto-utils/legacy"
const content = await legacy.symmetricDecryptV0_3_1(oldGibbrishHex, keyHex)
const gibbrish = await secUtl.symmetricEncrypt(content, keyHex)
```

| Data written by | Read with | Write again with |
|---|---|---|
| symmetric 0.3.0 – 0.3.1 | `symmetricDecryptV0_3_1` | `symmetricEncrypt` |
| symmetric 0.0.1 – 0.2.0 | `symmetricDecryptV0_2_0` (no integrity check: try `V0_3_1` first) | `symmetricEncrypt` |
| asymmetric 0.3.0 – 0.3.1 | `asymmetricDecryptV0_3_1` | `asymmetricEncrypt` |
| asymmetric 0.1.0 – 0.2.0 | `asymmetricDecryptV0_2_0` | `asymmetricEncrypt` |
| asymmetric 0.0.4 – 0.0.7, `asymmetricEncryptOld` | `asymmetricDecryptV0_0_7` | `asymmetricEncrypt` |
| signatures 0.0.2 – 0.2.0 | `verifySignatureV0_2_0` | `createSignature` (needs the secret key) |
| hashed DH / elGamal secrets 0.2.0 | `diffieHellmanSecretHashV0_2_0` | re-derive with `diffieHellmanSecretHash` |
| DH / elGamal secrets 0.3.0 – 0.3.1 | `diffieHellmanSecretRawV0_3_1`, `diffieHellmanSecretHashV0_3_1` | re-derive with the main functions |

- Don't know the version? Try the functions of that operation until one succeeds. They throw on wrong data, except `symmetricDecryptV0_2_0`, which can return garbage for a wrong key (~1/256): check that the plaintext makes sense.
- Every legacy function takes hex or bytes like the main API, the key decides the mode.
- For elGamal secrets the receiver passes the `referencePoint` as `publicKey`.
- Re-deriving a shared secret means re-keying whatever the old secret protected.
- Keys need no conversion: secret and public keys are identical in every version.
- Signatures since 0.3.0 and raw DH / elGamal secrets of 0.2.0 need no legacy function: the main API gives the same results.
- Old CBC formats derive the IV from the key and have no (or a weak) integrity check, so convert and don't keep reading them.

## Security notes
- **Asymmetric key binding.** The symmetric key is `sha512(shared ‖ referencePoint)`. A and −A give the same X25519 secret, so without the referencePoint in the hash its sign bit could be flipped unnoticed. With it, any change to the referencePoint makes decryption fail. The recipient key is not included, because the only keys giving the same secret are equivalent keys of the same recipient (see below).
- **Hashed shared secrets bind both public keys.** `diffieHellmanSecretHash` and `elGamalSecretHash` hash both public keys as transmitted, sorted, so both sides get the same order. For elGamal the pair is (referencePoint, receiver). A secret derived with a different encoding of a key (−B, B + torsion) does not match, so both sides must use the keys as published.
- **Small-order points** (identity and the 7 torsion points) give a shared secret everybody knows. They are rejected with a `RangeError` as public keys and reference points, for Diffie-Hellman, ElGamal and asymmetric encryption.
- **Equivalent public keys in raw shared secrets.** X25519 multiplies by a multiple of 8, so a torsion component of a public key has no effect, and B, −B and B + torsion all give the same raw secret (standard X25519 behaviour). Nothing about the secret key leaks. Just don't treat two different public key encodings as two different parties because their raw secrets match: they are the same party.
- **Strict signatures, the same answer everywhere.** `verifySignature` follows RFC 8032 with canonical encodings (no ZIP-215) and the cofactorless equation. These signatures are always invalid:
  - small-order public keys - one signature would verify every message under such a key
  - small-order R (the first half of the signature), as the WebCrypto spec requires
  - non-canonical encodings of the key or R, and S ≥ L (no malleable signatures)
  
  Native WebCrypto implementations disagree on exactly these cases (bun and deno accept small-order keys and R, noble alone would accept cofactored-only signatures). We check them in JS before the native call, so every runtime and the fallback answer the same - except [WebKitGTK](#known-runtime-issues).
- **Passwords:** `deriveSymKeyFromPassword` is PBKDF2-SHA256, 600000 iterations by default, with a random 16 byte salt (shorter salts throw). Passwords are NFC-normalized, so the same password typed on different platforms gives the same key. Random keys belong to `createSymKey`, not the KDF.

### What this does not guarantee
- **Decryption does not prove the sender.** Asymmetric encryption is not authenticated: anyone with the public key can encrypt. Symmetric encryption proves only that the sender knew the key. Sign the content if the sender matters.
- **Not key-committing.** AES-GCM does not bind the ciphertext to one key: a crafted ciphertext can decrypt successfully under two different keys ("invisible salamanders"). Don't use decryption success as proof of *which* key was used.
- **Signatures have no context parameter.** A signature over `"yes"` is valid wherever `"yes"` is accepted. Put the purpose, recipient or timestamp into the signed content itself.
- **Diffie-Hellman has an empty default context.** Every `diffieHellmanSecretHash(sk, pk)` between the same two keys gives the same secret. Pass a context per purpose, and use `diffieHellmanSecretRaw` only as input to your own KDF.
- **Padding hides lengths only up to 255 bytes.** The ciphertext length is the content length plus 0–255 random bytes, so large size differences stay visible.
- **About 2^32 messages per symmetric key**, because of the random 96-bit nonces.

### Known runtime issues
Both concern native Ed25519 in **WebKitGTK** (GNOME Web/Epiphany and other WebKitGTK browsers, tested with 2.54.2). Apple's Safari uses its own crypto and is untested. Every other tested runtime (node, deno, bun, Chromium, Chrome, Firefox) is unaffected.

- **Large messages:** from 65536 bytes of content, `createSignature` throws and `verifySignature` returns `"Invalid signature!"` for *valid* signatures. Somewhere between 65000 and 65535 bytes the call hangs and never resolves. The bug is reported upstream to WebKit, and we expect it to be fixed. Until then, on WebKitGTK keep signed content below 65000 bytes, or sign a hash of it.
- **One edge case answers differently:** a signature from a key with a torsion component (mixed order) where `k·T8` is the identity is rejected there, and accepted everywhere else (cofactorless equation). Only a malicious signer can produce such a key, honest signatures verify the same everywhere.

## Salt Envelope
*Legacy (v0.3.x), only read by `symmetricDecryptV0_3_1` of the [legacy entry point](#legacy-entry-point).*

We random length prefix of random bytes to obsucate where potentially known plaintext could be.

Also we also add a padding postfix, so never have a "virtually predictable" ending. 
At the same time the padding verifies if the random prefix we added is still intact.

### Creation of the Salt Envelope
- We decide a random length between 33 bytes and 160 bytes and fill it with random bytes (least one full block is full of random bytes)
- We sum up all all bytes as Uint8 and write the sum as BE Uint16 to the next 2 bytes (we also make sure this condition is not accedentally met)
- We calculate the required padding and write this number to be next byte (this is the full prefix then)
- We mirror the first bytes of the salt to fill the padding (this is the full postfix)
- We write the prefix + plaintext + postfix as the new data to be encrypted

### Verification of the Salt Envelope
- We start to sum up all bytes as Uint8
- Along the way we check if the next 2bytes interpreted as BE Uint16 are equal to our sum
- If the condition is met we know the prefix length and postfix length - thus where the plaintext starts and ends
- We check if the bytes of the postfix match the the expected ones in the prefix 
- If the postfix does not fully match the prefix, then we know the message has been corrupted
- Also if the condition is not met within our expected limit, we know the message has been corrupted

## Shared Secrets
We also offer a direct solution to just use these shared secrets.

We may apply 2 different styles:
- diffieHellmanSecret = blending private with public key
- elGamalSecret = using an ephemeral private key to be blended with the target users public key, also add the public key as reference for the target user

### DiffieHellman Secrets
Imagine Alice has the keyPair `privA, pubA` and Bob `privB, pubB`

```js
const aliceSharedSecret = await secUtl.diffieHellmanSecretRaw(privA, pubB) // 32 bytes hex
const bobSharedSecret = await secUtl.diffieHellmanSecretRaw(privB, pubA)
aliceSharedSecret == bobSharedSecret // true
```

With the hashed version you may add an arbitrary context. This allows you to generate different sharedSecrets from the same key-pairs. The hash also binds `pubA` and `pubB`.
```js
const context = "onetime-context@" + Date.now()
const aliceSharedSecret = await secUtl.diffieHellmanSecretHash(privA, pubB, context) // 64 bytes hex
const bobSharedSecret = await secUtl.diffieHellmanSecretHash(privB, pubA, context)
aliceSharedSecret == bobSharedSecret // true
```

### ElGamal Secrets
ElGamal style is relevant for Alice - using a random ephemeral key instead of `privA`.
Bob uses the `diffieHellmanSecret` functions with the `referencePoint`.

```js
const { referencePointHex, sharedSecretHex } = await secUtl.elGamalSecretRaw(pubB) // 32 bytes hex each
const bobSharedSecret = await secUtl.diffieHellmanSecretRaw(privB, referencePointHex)
sharedSecretHex == bobSharedSecret // true
```

```js
const context = "onetime-context@" + Date.now()
const { referencePointHex, sharedSecretHex } = await secUtl.elGamalSecretHash(pubB, context) // 64 bytes hex secret
const bobSharedSecret = await secUtl.diffieHellmanSecretHash(privB, referencePointHex, context)
sharedSecretHex == bobSharedSecret // true
```

## Noble ed25519
The point arithmetic, key derivation and the fallback where WebCrypto has no Ed25519/X25519 are based on [noble-ed25519](https://github.com/paulmillr/noble-ed25519). A very concise and modern package for freely using the ed25519 algorithms. Big thanks for that!

---

All sorts of inputs are welcome, thanks!

---


# License
[CCO](https://creativecommons.org/publicdomain/zero/1.0/)
