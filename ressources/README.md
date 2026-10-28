# secret-manager-crypto-utils 

## Background
Starting with the [Secret Management](https://hackmd.io/PZjpRfzPSBCqS-8K54x2jA) the requirement of a set of specific cryptographic functions arose. 
This evolved to a neat cryptographic backbone based on Curve25519, AES and SHA-2.
Usable in the backend and the frontend.

It is:
- sha256
- sha512
- Sign/Verify via Ed25519
- Asymmetric Encrypt/Decrypt in ElGamal style using the Twisted Edwards Curve
- Symmetric Encrypt/Decrypt with AES-256-GCM ([format v1](#symmetric-format-v1)), still decrypting [legacy](#legacy-v03x-ciphertext) AES-256-CBC
- Password based key derivation (PBKDF2-SHA256)
- DiffieHellman style sharedSecret as `privA * pubB = privB * pubA` in Raw and Hashed version
- ElGamal style sharedSecret using an ephemeral random `privA` and providing the referencePoint `pubA` in Raw and Hashed version


There is a convenience package around this - the [Thingy-Crypto-Node](https://www.npmjs.com/package/thingy-crypto-node)

## Usage
One implementation on WebCrypto for node (>= 20), deno, bun, browsers and workers. Every function returns a Promise, except `createSymKey*`.

```js
import * as secUtl from "secret-manager-crypto-utils"

const { secretKeyHex, publicKeyHex } = await secUtl.createKeyPair()
const sig = await secUtl.createSignature("hello", secretKeyHex)
await secUtl.verify(sig, publicKeyHex, "hello") // true

const secrets = await secUtl.asymmetricEncrypt("my secret", publicKeyHex)
await secUtl.asymmetricDecrypt(secrets, secretKeyHex) // "my secret"

const keyHex = secUtl.createSymKey()
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
createSymKeyHex() -> hex          // sync, 48 bytes            // alias createSymKey
createSymKeyBytes() -> Uint8Array // sync, 48 bytes

// signatures (ed25519, strict RFC 8032)
createSignatureHex(content, secretKeyHex) -> sigHex           // alias createSignature
createSignatureBytes(content, secretKeyBytes) -> sigBytes
verifyHex(sigHex, publicKeyHex, content) -> boolean           // alias verify
verifyBytes(sigBytes, publicKeyBytes, content) -> boolean

// symmetric encryption (AES-256-GCM, format v1) - key: >= 48 bytes
symmetricEncryptHex(content, keyHex) -> gibbrishHex           // alias symmetricEncrypt
symmetricEncryptBytes(content, keyBytes) -> gibbrishBytes
symmetricDecryptHex(gibbrishHex, keyHex) -> content           // alias symmetricDecrypt
symmetricDecryptBytes(gibbrishBytes, keyBytes) -> content

// password based key derivation - low-entropy inputs (passwords, PINs) only
// store saltHex and iterations next to the ciphertext, they are needed to derive the same key again
deriveSymKeyFromPassword(password, saltHex = random 16 bytes, iterations = 600000) -> { keyHex, saltHex, iterations }

// asymmetric encryption (ElGamal style)
asymmetricEncryptHex(content, publicKeyHex) -> { referencePointHex, encryptedContentHex }      // alias asymmetricEncrypt
asymmetricEncryptBytes(content, publicKeyBytes) -> { referencePointBytes, encryptedContentBytes }
asymmetricDecryptHex(secrets, secretKeyHex) -> content        // alias asymmetricDecrypt
asymmetricDecryptBytes(secrets, secretKeyBytes) -> content
// decrypt also accepts { referencePoint, encryptedContent }

// Diffie-Hellman shared secret: ours secretKey * their publicKey
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

Errors: invalid hex → `SyntaxError`; content that is not a well-formed string → `TypeError`; wrong key lengths, small-order public keys, short KDF salt → `RangeError`; any decryption failure → `Error("Decryption failed!")`.

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
- ed25519 secret keys must be exactly 32 bytes, symmetric keys at least 48 bytes, signatures 64 bytes.
- Small-order public keys are rejected everywhere, and `verify` is strict RFC 8032 (no ZIP-215).
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
For the asymmetric encryption we use ed25519 keys for producing El-Gamal-style shared secret-keys (`sha512` of the shared point) which we then use for symmetrically encrypting the contents.

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
- **No key binding on the asymmetric path.** The symmetric key is `sha512(shared point)` and does not include the referencePoint or the recipient key (kept for v0.3.x compatibility). Asymmetric encryption is not authenticated: anyone with the public key can encrypt, so sign the content if the sender matters.
- **Small-order points** (identity and the 7 torsion points) give a shared secret everybody knows. They are rejected as public keys and reference points.
- **Strict signatures.** `verify` follows RFC 8032 with canonical encodings (no ZIP-215), so one signature cannot verify every message under a small-order key, and signatures are not malleable.
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
All of this is straight forward based on [noble-ed25519](https://github.com/paulmillr/noble-ed25519). A very concise and modern package for freely using the ed25519 algorithms. Big thanks for that!

---

All sorts of inputs are welcome, thanks!

---


# License
[CCO](https://creativecommons.org/publicdomain/zero/1.0/)