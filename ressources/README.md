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
- Symmetric Encrypt/Decrypt with AES-256-GCM ([format v1](#symmetric-format-v1)), still decrypting [legacy](#legacy-v03x-ciphertext) AES-256-CBC
- Password based key derivation (PBKDF2-SHA256)
- DiffieHellman style sharedSecret as `privA * pubB = privB * pubA` in Raw and Hashed version
- ElGamal style sharedSecret using an ephemeral random `privA` and providing the referencePoint `pubA` in Raw and Hashed version


There is a convenience package around this - the [Thingy-Crypto-Node](https://www.npmjs.com/package/thingy-crypto-node)

## Usage
One implementation on WebCrypto for node (>= 20), deno, bun, browsers and workers. Every function returns a Promise.

Ed25519 and X25519 run natively in WebCrypto where the runtime has them (node, deno, bun, current browsers), and on [noble-ed25519](#noble-ed25519) otherwise. Both paths give the same bytes and the same verification answers, and the test suite runs on each of them.

```js
import * as secUtl from "secret-manager-crypto-utils"

const { secretKeyHex, publicKeyHex } = await secUtl.createKeyPair()
const sig = await secUtl.createSignature("hello", secretKeyHex)
const err = await secUtl.verifySignature(sig, publicKeyHex, "hello") // undefined = valid
if (err) throw new Error(err) // "Invalid signature!" or "Malformed input!"

const secrets = await secUtl.asymmetricEncrypt("my secret", publicKeyHex)
await secUtl.asymmetricDecrypt(secrets, secretKeyHex) // "my secret"

const keyHex = await secUtl.createSymKey()
const gibbrish = await secUtl.symmetricEncrypt("my secret", keyHex)
await secUtl.symmetricDecrypt(gibbrish, keyHex) // "my secret"
```

Every function exists as `…Hex` (hex strings in and out) and `…Bytes` (`Uint8Array` in and out). The name without suffix is the Hex variant. Content is always a `string`.

```js
// shas - content: string or Uint8Array
sha256Hex(content) -> hex                     // alias sha256
sha512Hex(content) -> hex                     // alias sha512
sha256Bytes(content) -> Uint8Array
sha512Bytes(content) -> Uint8Array

// keys
createKeyPairHex() -> { secretKeyHex, publicKeyHex }          // alias createKeyPair
createKeyPairBytes() -> { secretKeyBytes, publicKeyBytes }
createPublicKeyHex(secretKeyHex) -> publicKeyHex              // alias createPublicKey
createPublicKeyBytes(secretKeyBytes) -> publicKeyBytes
createSymKeyHex() -> hex          // 48 bytes                  // alias createSymKey
createSymKeyBytes() -> Uint8Array // 48 bytes

// signatures (ed25519, strict RFC 8032)
createSignatureHex(content, secretKeyHex) -> sigHex           // alias createSignature
createSignatureBytes(content, secretKeyBytes) -> sigBytes
// undefined when valid, else an error string - never throws
verifySignatureHex(sigHex, publicKeyHex, content) -> undefined | string    // alias verifySignature
verifySignatureBytes(sigBytes, publicKeyBytes, content) -> undefined | string

// symmetric encryption (AES-256-GCM, format v1) - key: >= 48 bytes
// context: optional, authenticated (GCM additionalData) but not stored - decrypt needs the same one
symmetricEncryptHex(content, keyHex, context = "") -> gibbrishHex           // alias symmetricEncrypt
symmetricEncryptBytes(content, keyBytes, context = "") -> gibbrishBytes
symmetricDecryptHex(gibbrishHex, keyHex, context = "") -> content           // alias symmetricDecrypt
symmetricDecryptBytes(gibbrishBytes, keyBytes, context = "") -> content

// password based key derivation - passwords only, iterations 1000..10000000
// store saltHex and iterations next to the ciphertext, they are needed to derive the same key again
deriveSymKeyFromPassword(password, saltHex = random 16 bytes, iterations = 600000) -> { keyHex, saltHex, iterations }

// asymmetric encryption (ElGamal style), context as for symmetric
asymmetricEncryptHex(content, publicKeyHex, context = "") -> { referencePointHex, encryptedContentHex }      // alias asymmetricEncrypt
asymmetricEncryptBytes(content, publicKeyBytes, context = "") -> { referencePointBytes, encryptedContentBytes }
asymmetricDecryptHex(secrets, secretKeyHex, context = "") -> content        // alias asymmetricDecrypt
asymmetricDecryptBytes(secrets, secretKeyBytes, context = "") -> content
// decrypt also accepts { referencePoint, encryptedContent }

// Diffie-Hellman shared secret: X25519 of our secretKey and their publicKey
diffieHellmanSecretRawHex(secretKeyHex, publicKeyHex) -> hex (32 bytes)
diffieHellmanSecretRawBytes(secretKeyBytes, publicKeyBytes) -> Uint8Array
diffieHellmanSecretHashHex(secretKeyHex, publicKeyHex, context = "") -> hex (64 bytes)
diffieHellmanSecretHashBytes(secretKeyBytes, publicKeyBytes, context = "") -> Uint8Array

// ElGamal shared secret: ephemeral secretKey * their publicKey, referencePoint = ephemeral publicKey
elGamalSecretRawHex(publicKeyHex) -> { referencePointHex, sharedSecretHex }
elGamalSecretRawBytes(publicKeyBytes) -> { referencePointBytes, sharedSecretBytes }
elGamalSecretHashHex(publicKeyHex, context = "") -> { referencePointHex, sharedSecretHex }
elGamalSecretHashBytes(publicKeyBytes, context = "") -> { referencePointBytes, sharedSecretBytes }
```

Errors: invalid hex → `SyntaxError`; content that is not a well-formed string, or bytes that are not a `Uint8Array` → `TypeError`; wrong key lengths, small-order public keys, short KDF salt, iterations out of range → `RangeError`; any decryption failure → `Error("Decryption failed!")`. `verifySignature*` is the exception: it never throws, see [Security notes](#security-notes).

### Aliases (kept for compatibility)
| canonical | aliases |
|---|---|
| `diffieHellmanSecretRawHex` | `diffieHellmanSecretRaw`, `createSharedSecretRaw`, `createSharedSecretRawHex` |
| `diffieHellmanSecretRawBytes` | `sharedSecretRawBytes` |
| `diffieHellmanSecretHashHex` | `diffieHellmanSecretHash`, `createSharedSecretHash`, `createSharedSecretHashHex` |
| `diffieHellmanSecretHashBytes` | `sharedSecretHashBytes` |
| `elGamalSecretRawHex` | `elGamalSecretRaw`, `referencedSecretRaw(Hex)`, `referencedSharedSecretRaw(Hex)` |
| `elGamalSecretRawBytes` | `referencedSecretRawBytes`, `referencedSharedSecretRawBytes` |
| `elGamalSecretHashHex` | `elGamalSecretHash`, `referencedSecretHash(Hex)`, `referencedSharedSecretHash(Hex)` |
| `elGamalSecretHashBytes` | `referencedSecretHashBytes`, `referencedSharedSecretHashBytes` |

## Breaking Updates
`0.3.x` -> `0.4.y`
------------------
- `symmetricEncrypt` writes [format v1](#symmetric-format-v1) (AES-256-GCM). Decryption still reads v0.3.x ciphertext, but **v0.3.x cannot decrypt v1** - update readers before writers.
- `sha256`/`sha512` are async on node too (they always were in the browser).
- `saltContent`/`unsaltContent` are removed.
- `verify*` is replaced by `verifySignature*`: it resolves `undefined` when valid and an error string otherwise, and never throws. `verify`, `verifyHex` and `verifyBytes` are gone.
- `createSymKey*` is async, like every other function.
- **Shared secrets changed:** Diffie-Hellman and ElGamal secrets are X25519 again (the same values as v0.1.x–0.2.x), not the Edwards point of v0.3.x. Anything keyed by a v0.3.x secret has to be re-derived.
- Asymmetric encryption uses `sha512(shared ‖ referencePoint)` as key, on top of the new shared secret.
- ed25519 secret keys must be exactly 32 bytes, symmetric keys at least 48 bytes, signatures 64 bytes.
- Small-order public keys are rejected everywhere, and verification is strict RFC 8032 (no ZIP-215).
- Strings with lone surrogates (`"a\uD800"`) throw instead of being silently changed to `"a\uFFFD"`.
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

These changes mean that **you cannot decrypt any secrets encrypted with an earlier version of this library**.

When dealing with old encrypted secrets - better use the the old packages like this

```sh
npm install secret-manager-crypto-utils-old@npm:secret-manager-crypto-utils@0.2.0
```

## Hex FTW
It is advisable that you store all encrypted contents, signatures and keys in hex strings. This appears to be the most superior way of how to universally transfer byte information.

The big wins of hex in readability and processability beats out the "downside" of being 2x the size. Also the performance loss is in most cases negligible ~ < 10%.


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
- Every failure is one generic `Error("Decryption failed!")`, which never says why.

### Legacy v0.3.x ciphertext
Decryption tries v1 when the first byte is `0x01` and the GCM tag verifies, otherwise it falls back to the old AES-256-CBC + [salt envelope](#salt-envelope) (1/256 of old ciphertexts also start with `0x01`, so the tag decides, not the version byte).

Residual risks of this fallback, accepted until all old secrets are re-encrypted:
- CBC has no real integrity check. A tampered v1 ciphertext falls through to CBC and, with tiny probability (valid PKCS#7 padding *and* a valid salt envelope), returns garbage instead of throwing.
- Success or failure and the timing difference between the padding check and the salt check could act as a padding oracle on **old** ciphertexts if a service decrypts attacker-controlled input and reports the result. Do not expose decryption of untrusted input as a service, and re-encrypt old secrets (decrypt + encrypt writes v1).

### Security notes
- **Not key-committing.** AES-GCM does not bind the ciphertext to one key: a crafted ciphertext can decrypt successfully under two different keys ("invisible salamanders"). Don't use decryption success as proof of *which* key was used.
- **Asymmetric key binding.** The symmetric key is `sha512(shared ‖ referencePoint)`. A and −A give the same X25519 secret, so without the referencePoint in the hash its sign bit could be flipped unnoticed. With it, any change to the referencePoint makes decryption fail. The recipient key is not included, because the only keys giving the same secret are equivalent keys of the same recipient (see below). Asymmetric encryption is not authenticated: anyone with the public key can encrypt, so sign the content if the sender matters.
- **Small-order points** (identity and the 7 torsion points) give a shared secret everybody knows. They are rejected with a `RangeError` as public keys and reference points, for Diffie-Hellman, ElGamal and asymmetric encryption.
- **Equivalent public keys in shared secrets.** X25519 multiplies by a multiple of 8, so a torsion component of a public key has no effect, and B, −B and B + torsion all give the same shared secret (standard X25519 behaviour). Nothing about the secret key leaks. Just don't treat two different public key encodings as two different parties because their secrets differ: they don't.
- **Strict signatures, the same answer everywhere.** `verifySignature*` follows RFC 8032 with canonical encodings (no ZIP-215) and the cofactorless equation. These signatures are always invalid:
  - small-order public keys - one signature would verify every message under such a key
  - small-order R (the first half of the signature), as the WebCrypto spec requires
  - non-canonical encodings of the key or R, and S ≥ L (no malleable signatures)
  
  Native WebCrypto implementations disagree on exactly these cases (bun and deno accept small-order keys and R, noble alone would accept cofactored-only signatures). We check them in JS before the native call, so every runtime and the fallback answer the same.
- **`verifySignature*` never throws.** Malformed input (bad hex, wrong lengths, wrong types, lone surrogates) gives `"Malformed input!"`, a wrong signature `"Invalid signature!"`, a valid one `undefined`. A forgotten `await` fails closed, because a Promise is truthy.
- **Passwords:** `deriveSymKeyFromPassword` is PBKDF2-SHA256, 600000 iterations by default, with a random 16 byte salt (shorter salts throw). Passwords are NFC-normalized, so the same password typed on different platforms gives the same key. Random keys belong to `createSymKey`, not the KDF.

## Salt Envelope
*Legacy (v0.3.x), only read by decryption now.*

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

With the hashed version you may add an arbitrary context. This allows you to generate different sharedSecrets from the same key-pairs.
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