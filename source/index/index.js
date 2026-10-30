//############################################################
import * as ed from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"

//############################################################
// One implementation for node, deno, bun, browsers and workers
const subtle = globalThis.crypto.subtle
const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n))

//############################################################
//#region internalFunctions
// thingy-byte-utils validates the content (SyntaxError), not the type
const hexToBytes = (hex) => {
    if (typeof hex != "string") throw new TypeError("Expected a hex string!")
    return tbut.hexToBytes(hex)
}

const checkBytes = (bytes) => {
    if (!(bytes instanceof Uint8Array)) throw new TypeError("Expected a Uint8Array!")
}

// a shorter key would silently become AES-128/192 or fail late inside WebCrypto
const checkSymKey = (keyBytes) => {
    checkBytes(keyBytes)
    if (!(keyBytes?.length >= 48)) throw new RangeError("Symmetric key must have at least 48 bytes!")
}

// thingy-byte-utils rejects lone surrogates (TypeError), not other types
const utf8 = (content) => {
    if (typeof content != "string") throw new TypeError("Content must be a string!")
    return tbut.utf8ToBytes(content)
}

// hex mode: a hex key gives hex results, a Uint8Array key gives Uint8Array results
const isHex = (x) => typeof x == "string"
const asBytes = (x) => isHex(x) ? hexToBytes(x) : x
const asModeOf = (key, bytes) => isHex(key) ? tbut.bytesToHex(bytes) : bytes
// { fooBytes } -> { fooHex }
const asModeOfObject = (key, result) => isHex(key) ? Object.fromEntries(Object.entries(result).map(([k, v]) => [k.replace(/Bytes$/, "Hex"), tbut.bytesToHex(v)])) : result

const toBytes = (content) => (typeof content == "string") ? utf8(content) : content

const concat = (a, b) => {
    const result = new Uint8Array(a.length + b.length)
    result.set(a)
    result.set(b, a.length)
    return result
}

// small-order points give a shared secret everybody knows - torsion components are harmless, X25519 clamping removes them
const publicPoint = (publicKeyBytes) => {
    const P = ed.Point.fromBytes(publicKeyBytes)
    if (P.isSmallOrder()) throw new RangeError("Invalid public key!")
    return P
}

// noble checks the length itself, WebCrypto would throw a DOMException instead
const checkSecretKey = (secretKeyBytes) => {
    checkBytes(secretKeyBytes)
    if (secretKeyBytes.length != 32) throw new RangeError("Secret key must have 32 bytes!")
}

const { p: P, n: L } = ed.Point.CURVE()
const bytesToNumberLE = (bytes) => BigInt("0x" + tbut.bytesToHex(bytes.slice().reverse()))
const numberToBytesLE = (n) => hexToBytes(n.toString(16).padStart(64, "0")).reverse()
// Montgomery u = (1 + y) / (1 - y) of an Edwards point - the X25519 public key
const montgomeryU = (point) => {
    const { y } = point.toAffine()
    return numberToBytesLE(ed.etc.mod((1n + y) * ed.etc.invert(1n - y, P), P))
}

// native Ed25519/X25519 where the runtime has it, noble otherwise - both give the same bytes
// pkcs8 wrappers around a raw 32 byte seed (RFC 8410)
const ED25519_PKCS8 = hexToBytes("302e020100300506032b657004220420")
const X25519_PKCS8 = hexToBytes("302e020100300506032b656e04220420")
const importPkcs8 = (prefix, seed, name, usage) => subtle.importKey("pkcs8", concat(prefix, seed), name, false, [usage])
const isNative = (prefix, name, usage) => importPkcs8(prefix, new Uint8Array(32), name, usage).then(() => true, () => false)
const nativeEd25519 = await isNative(ED25519_PKCS8, "Ed25519", "sign")
const nativeX25519 = await isNative(X25519_PKCS8, "X25519", "deriveBits")

const importAesGcmKey = (keyBytes) => subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"])

//#endregion

//############################################################
//#region shas
export const sha256Bytes = async (content) => new Uint8Array(await subtle.digest("SHA-256", toBytes(content)))
export const sha512Bytes = async (content) => new Uint8Array(await subtle.digest("SHA-512", toBytes(content)))

export const sha256 = async (content) => tbut.bytesToHex(await sha256Bytes(content))
export const sha512 = async (content) => tbut.bytesToHex(await sha512Bytes(content))

//#endregion

//############################################################
//#region keys
export const createKeyPairBytes = async () => {
    const secretKeyBytes = ed.utils.randomSecretKey()
    const publicKeyBytes = await ed.getPublicKeyAsync(secretKeyBytes)
    return { secretKeyBytes, publicKeyBytes }
}
export const createSymKeyBytes = async () => randomBytes(48)
const createPublicKeyBytes = (secretKeyBytes) => ed.getPublicKeyAsync(secretKeyBytes)

// no key to take the mode from: hex, with the …Bytes variants above
export const createKeyPair = async () => asModeOfObject("", await createKeyPairBytes())
export const createSymKey = async () => tbut.bytesToHex(await createSymKeyBytes())
export const createPublicKey = async (secretKey) => asModeOf(secretKey, await createPublicKeyBytes(asBytes(secretKey)))

//#endregion

//############################################################
//#region signatures
const createSignatureBytes = async (content, signingKeyBytes) => {
    const message = utf8(content)
    checkSecretKey(signingKeyBytes)
    if (!nativeEd25519) return ed.signAsync(message, signingKeyBytes)
    const key = await importPkcs8(ED25519_PKCS8, signingKeyBytes, "Ed25519", "sign")
    return new Uint8Array(await subtle.sign("Ed25519", key, message))
}

// undefined when valid, else an error string - never throws, and a missing await is truthy so it fails closed
// strict RFC 8032, the same answer on every path: canonical A and R, S < L, cofactorless equation
// A and R are decoded and small-order rejected here, as the WebCrypto spec demands - node does, bun/deno native don't
// a small-order key would let one signature verify any message
const verifySignatureBytes = async (sigBytes, keyBytes, content) => {
    try {
        const message = utf8(content)
        checkBytes(sigBytes)
        if (sigBytes.length != 64) throw new RangeError("Signature must have 64 bytes!")
        const A = ed.Point.fromBytes(keyBytes, false)
        let R
        try { R = ed.Point.fromBytes(sigBytes.subarray(0, 32), false) } catch { return "Invalid signature!" }
        if (A.isSmallOrder() || R.isSmallOrder()) return "Invalid signature!"
        if (await (nativeEd25519 ? verifyNative : verifyFallback)(sigBytes, keyBytes, A, R, message)) return undefined
        return "Invalid signature!"
    } catch { return "Malformed input!" }
}

const verifyNative = async (sigBytes, keyBytes, A, R, message) => {
    const key = await subtle.importKey("raw", keyBytes, "Ed25519", false, ["verify"])
    return subtle.verify("Ed25519", key, sigBytes, message)
}

// S·G == R + k·A without the cofactor, like every native implementation - noble's cofactored check accepts more
const verifyFallback = async (sigBytes, keyBytes, A, R, message) => {
    const S = bytesToNumberLE(sigBytes.subarray(32))
    if (S >= L) return false
    const k = bytesToNumberLE(await sha512Bytes(concat(concat(sigBytes.subarray(0, 32), keyBytes), message))) % L
    return ed.Point.BASE.multiply(S, false).equals(R.add(A.multiply(k, false)))
}

export const createSignature = async (content, signingKey) => asModeOf(signingKey, await createSignatureBytes(content, asBytes(signingKey)))
export const verifySignature = async (sig, key, content) => {
    try { return await verifySignatureBytes(asBytes(sig), asBytes(key), content) } catch { return "Malformed input!" }
}

//#endregion

//############################################################
//#region symmetric encryption
// format v1: 0x01 ‖ nonce(12) ‖ AES-256-GCM( padLen(1) ‖ content ‖ random(padLen) ) ‖ tag(16)
// context: GCM additionalData, not transmitted - decrypt needs the same one; "" gives the same output as none
// key: 48 bytes, v1 uses bytes 16..47 as AES key (bytes 0..15 were the legacy CBC iv)
// subarray respects the byteOffset of views
const V1 = 0x01
const NONCE_LENGTH = 12
const V1_MIN_LENGTH = 1 + NONCE_LENGTH + 16 + 1 // version, nonce, tag, padLen

const symmetricEncryptBytes = async (content, keyBytes, context = "") => {
    checkSymKey(keyBytes)
    const key = await importAesGcmKey(keyBytes.subarray(16, 48))
    // random nonce per message, never a parameter: a reuse under one key breaks GCM
    const nonce = randomBytes(NONCE_LENGTH)
    const params = { name: "AES-GCM", iv: nonce, tagLength: 128, additionalData: utf8(context) }
    const sealed = await subtle.encrypt(params, key, padContent(content))
    const result = new Uint8Array(1 + NONCE_LENGTH + sealed.byteLength)
    result[0] = V1
    result.set(nonce, 1)
    result.set(new Uint8Array(sealed), 1 + NONCE_LENGTH)
    return result
}

// v1 only - legacy ciphertext is read by the ./legacy entry point
const symmetricDecryptBytes = async (gibbrishBytes, keyBytes, context = "") => {
    checkSymKey(keyBytes)
    checkBytes(gibbrishBytes)
    const additionalData = utf8(context)
    if (gibbrishBytes[0] == V1 && gibbrishBytes.length >= V1_MIN_LENGTH) {
        try { return await decryptV1(gibbrishBytes, keyBytes, additionalData) } catch { }
    }
    throw new Error("Decryption failed!")
}

const decryptV1 = async (gibbrishBytes, keyBytes, additionalData) => {
    const key = await importAesGcmKey(keyBytes.subarray(16, 48))
    const nonce = gibbrishBytes.subarray(1, 1 + NONCE_LENGTH)
    // WebCrypto verifies the tag before releasing any plaintext
    const params = { name: "AES-GCM", iv: nonce, tagLength: 128, additionalData }
    const padded = await subtle.decrypt(params, key, gibbrishBytes.subarray(1 + NONCE_LENGTH))
    return unpadContent(new Uint8Array(padded))
}

const padContent = (content) => {
    const contentBytes = utf8(content)
    const padLength = randomBytes(1)[0]
    const result = new Uint8Array(1 + contentBytes.length + padLength)
    result[0] = padLength
    result.set(contentBytes, 1)
    result.set(randomBytes(padLength), 1 + contentBytes.length)
    return result
}

const unpadContent = (paddedBytes) => {
    const end = paddedBytes.length - paddedBytes[0]
    if (!(end >= 1)) throw new Error("Unpad: invalid padding length!")
    return tbut.bytesToUtf8(paddedBytes.subarray(1, end))
}

export const symmetricEncrypt = async (content, key, context) => asModeOf(key, await symmetricEncryptBytes(content, asBytes(key), context))
export const symmetricDecrypt = async (gibbrish, key, context) => symmetricDecryptBytes(asBytes(gibbrish), asBytes(key), context)

// PBKDF2-SHA256 -> 48 byte symmetric key, for passwords only
// NFC: the same password typed on different platforms may arrive in different unicode forms
export const deriveSymKeyFromPassword = async (password, saltHex = tbut.bytesToHex(randomBytes(16)), iterations = 600000) => {
    // below 1k is no protection, above 10M an accidental DoS
    if (!Number.isInteger(iterations) || iterations < 1000 || iterations > 10000000) throw new RangeError("Iterations must be an integer in 1000..10000000!")
    const salt = hexToBytes(saltHex)
    if (salt.length < 16) throw new RangeError("Salt must have at least 16 bytes!")
    utf8(password) // thingy-byte-utils rejects lone surrogates before Firefox's normalize would turn them into U+FFFD
    const baseKey = await subtle.importKey("raw", utf8(password.normalize("NFC")), "PBKDF2", false, ["deriveBits"])
    const params = { name: "PBKDF2", hash: "SHA-256", salt, iterations }
    const keyHex = tbut.bytesToHex(await subtle.deriveBits(params, baseKey, 48 * 8))
    return { keyHex, saltHex, iterations }
}

//#endregion

//############################################################
//#region asymmetric encryption
// ElGamal style: referencePoint A is sent along, DH(n, B) = DH(k, A) is the shared secret
// symmetric key = sha512(shared ‖ A): A and -A give the same X25519 secret, A's exact bytes make the key differ
const asymmetricEncryptBytes = async (content, publicKeyBytes, context = "") => {
    const { referencePointBytes, sharedSecretBytes } = await elGamalSecretRawBytes(publicKeyBytes)
    const keyBytes = await sha512Bytes(concat(sharedSecretBytes, referencePointBytes))
    const encryptedContentBytes = await symmetricEncryptBytes(content, keyBytes, context)
    return { referencePointBytes, encryptedContentBytes }
}

const asymmetricDecryptBytes = async (ABytes, gibbrishBytes, secretKeyBytes, context = "") => {
    const kABytes = await diffieHellmanSecretRawBytes(secretKeyBytes, ABytes)
    return symmetricDecryptBytes(gibbrishBytes, await sha512Bytes(concat(kABytes, ABytes)), context)
}

export const asymmetricEncrypt = async (content, publicKey, context) => asModeOfObject(publicKey, await asymmetricEncryptBytes(content, asBytes(publicKey), context))

// takes the …Hex and the …Bytes property names
export const asymmetricDecrypt = async (secrets, secretKey, context) => {
    const A = secrets.referencePointHex || secrets.referencePointBytes
    const gibbrish = secrets.encryptedContentHex || secrets.encryptedContentBytes
    if (A == null || gibbrish == null) throw new Error("Invalid secrets Object!")
    return asymmetricDecryptBytes(asBytes(A), asBytes(gibbrish), asBytes(secretKey), context)
}

//#endregion

//############################################################
//#region diffieHellman/ElGamal secrets
// X25519: h = sha512(our secretKey)[0:32], B = their publicKey, shared secret = u(clamp(h)·B) - raw is the same as v0.1.0-0.2.0
// clamping makes the scalar a multiple of 8, so a torsion component of B drops out
const diffieHellmanSecretRawBytes = async (secretKeyBytes, publicKeyBytes) => {
    checkSecretKey(secretKeyBytes)
    const B = publicPoint(publicKeyBytes)
    const h = (await sha512Bytes(secretKeyBytes)).subarray(0, 32)
    if (nativeX25519) {
        const privateKey = await importPkcs8(X25519_PKCS8, h, "X25519", "deriveBits")
        const publicKey = await subtle.importKey("raw", montgomeryU(B), "X25519", false, [])
        return new Uint8Array(await subtle.deriveBits({ name: "X25519", public: publicKey }, privateKey, 256))
    }
    h[0] &= 248; h[31] &= 127; h[31] |= 64
    // clamp(h)·B as (clamp(h)/8)·(8B): noble needs a scalar below L
    return montgomeryU(B.clearCofactor().multiply((bytesToNumberLE(h) >> 3n) % L))
}

// sha512(shared ‖ lower publicKey ‖ higher publicKey ‖ utf8(context)): binds the secret to both public keys as transmitted
// B, -B and B + torsion give the same raw secret, but a different hash - sorted, so both sides hash the same order
const hashSecret = (sharedSecretBytes, publicKeyBytes1, publicKeyBytes2, contextString) => {
    const keys = tbut.bytesToHex(publicKeyBytes1) <= tbut.bytesToHex(publicKeyBytes2) ? [publicKeyBytes1, publicKeyBytes2] : [publicKeyBytes2, publicKeyBytes1]
    return sha512Bytes(concat(concat(sharedSecretBytes, concat(...keys)), utf8(contextString)))
}

const diffieHellmanSecretHashBytes = async (secretKeyBytes, publicKeyBytes, contextString = "") => {
    const kBBytes = await diffieHellmanSecretRawBytes(secretKeyBytes, publicKeyBytes)
    return hashSecret(kBBytes, await createPublicKeyBytes(secretKeyBytes), publicKeyBytes, contextString)
}

// one-time secret key n, A = publicKey(n) = referencePoint, shared secret = DH(n, B)
const elGamalSecretRawBytes = async (publicKeyBytes) => {
    const n = ed.utils.randomSecretKey()
    const sharedSecretBytes = await diffieHellmanSecretRawBytes(n, publicKeyBytes)
    return { referencePointBytes: await createPublicKeyBytes(n), sharedSecretBytes }
}

const elGamalSecretHashBytes = async (publicKeyBytes, contextString = "") => {
    const { referencePointBytes, sharedSecretBytes } = await elGamalSecretRawBytes(publicKeyBytes)
    return { referencePointBytes, sharedSecretBytes: await hashSecret(sharedSecretBytes, referencePointBytes, publicKeyBytes, contextString) }
}

// two keys: the secret key decides the mode
export const diffieHellmanSecretRaw = async (secretKey, publicKey) => asModeOf(secretKey, await diffieHellmanSecretRawBytes(asBytes(secretKey), asBytes(publicKey)))
export const diffieHellmanSecretHash = async (secretKey, publicKey, contextString) => asModeOf(secretKey, await diffieHellmanSecretHashBytes(asBytes(secretKey), asBytes(publicKey), contextString))

export const elGamalSecretRaw = async (publicKey) => asModeOfObject(publicKey, await elGamalSecretRawBytes(asBytes(publicKey)))
export const elGamalSecretHash = async (publicKey, contextString) => asModeOfObject(publicKey, await elGamalSecretHashBytes(asBytes(publicKey), contextString))

//#endregion
