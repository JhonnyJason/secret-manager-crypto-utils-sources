//############################################################
import * as ed from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"

//############################################################
// One implementation for node, deno, bun, browsers and workers
const subtle = globalThis.crypto.subtle
const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n))

//############################################################
//#region internalFunctions
// thingy-byte-utils does not validate - its JS fallback would turn bad hex into garbage
const hexToBytes = (hex) => {
    if (typeof hex != "string" || hex.length % 2 || /[^0-9a-fA-F]/.test(hex)) throw new SyntaxError("Invalid hex string!")
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

// lone surrogates would silently become U+FFFD - what is decrypted or verified must be what went in
const utf8 = (content) => {
    if (typeof content != "string" || !content.isWellFormed()) throw new TypeError("Content must be a well-formed string!")
    return tbut.utf8ToBytes(content)
}

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

const importAesCbcKey = (keyBytes) => subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt", "decrypt"])
const importAesGcmKey = (keyBytes) => subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"])

//#endregion

//############################################################
//#region shas
export const sha256Bytes = async (content) => new Uint8Array(await subtle.digest("SHA-256", toBytes(content)))
export const sha512Bytes = async (content) => new Uint8Array(await subtle.digest("SHA-512", toBytes(content)))

export const sha256Hex = async (content) => tbut.bytesToHex(await sha256Bytes(content))
export const sha512Hex = async (content) => tbut.bytesToHex(await sha512Bytes(content))
export const sha256 = sha256Hex
export const sha512 = sha512Hex

//#endregion

//############################################################
//#region keys
export const createKeyPairBytes = async () => {
    const secretKeyBytes = ed.utils.randomSecretKey()
    const publicKeyBytes = await ed.getPublicKeyAsync(secretKeyBytes)
    return { secretKeyBytes, publicKeyBytes }
}
export const createSymKeyBytes = async () => randomBytes(48)
export const createPublicKeyBytes = (secretKeyBytes) => ed.getPublicKeyAsync(secretKeyBytes)

export const createKeyPairHex = async () => {
    const { secretKeyBytes, publicKeyBytes } = await createKeyPairBytes()
    return { secretKeyHex: tbut.bytesToHex(secretKeyBytes), publicKeyHex: tbut.bytesToHex(publicKeyBytes) }
}
export const createSymKeyHex = async () => tbut.bytesToHex(await createSymKeyBytes())
export const createPublicKeyHex = async (secretKeyHex) => tbut.bytesToHex(await createPublicKeyBytes(hexToBytes(secretKeyHex)))
export const createKeyPair = createKeyPairHex
export const createSymKey = createSymKeyHex
export const createPublicKey = createPublicKeyHex

//#endregion

//############################################################
//#region signatures
export const createSignatureBytes = async (content, signingKeyBytes) => {
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
export const verifySignatureBytes = async (sigBytes, keyBytes, content) => {
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

export const createSignatureHex = async (content, signingKeyHex) => tbut.bytesToHex(await createSignatureBytes(content, hexToBytes(signingKeyHex)))
export const verifySignatureHex = async (sigHex, keyHex, content) => {
    try { return await verifySignatureBytes(hexToBytes(sigHex), hexToBytes(keyHex), content) } catch { return "Malformed input!" }
}
export const createSignature = createSignatureHex
export const verifySignature = verifySignatureHex

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

export const symmetricEncryptBytes = async (content, keyBytes, context = "") => {
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

// v1 when the tag verifies, else legacy CBC (1/256 of legacy ciphertexts start with 0x01 too)
export const symmetricDecryptBytes = async (gibbrishBytes, keyBytes, context = "") => {
    checkSymKey(keyBytes)
    checkBytes(gibbrishBytes)
    const additionalData = utf8(context)
    if (gibbrishBytes[0] == V1 && gibbrishBytes.length >= V1_MIN_LENGTH) {
        try { return await decryptV1(gibbrishBytes, keyBytes, additionalData) } catch { }
    }
    // legacy CBC cannot check a context, so a caller asking for one must not get legacy plaintext
    if (context === "") try { return await decryptLegacy(gibbrishBytes, keyBytes) } catch { }
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

const decryptLegacy = async (gibbrishBytes, keyBytes) => {
    const iv = keyBytes.subarray(0, 16)
    const key = await importAesCbcKey(keyBytes.subarray(16, 48))
    return unsaltContent(new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv }, key, gibbrishBytes)))
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

export const symmetricEncryptHex = async (content, keyHex, context) => tbut.bytesToHex(await symmetricEncryptBytes(content, hexToBytes(keyHex), context))
export const symmetricDecryptHex = (gibbrishHex, keyHex, context) => symmetricDecryptBytes(hexToBytes(gibbrishHex), hexToBytes(keyHex), context)
export const symmetricEncrypt = symmetricEncryptHex
export const symmetricDecrypt = symmetricDecryptHex

// PBKDF2-SHA256 -> 48 byte symmetric key, for passwords only
// NFC: the same password typed on different platforms may arrive in different unicode forms
export const deriveSymKeyFromPassword = async (password, saltHex = tbut.bytesToHex(randomBytes(16)), iterations = 600000) => {
    // below 1k is no protection, above 10M an accidental DoS
    if (!Number.isInteger(iterations) || iterations < 1000 || iterations > 10000000) throw new RangeError("Iterations must be an integer in 1000..10000000!")
    const salt = hexToBytes(saltHex)
    if (salt.length < 16) throw new RangeError("Salt must have at least 16 bytes!")
    const baseKey = await subtle.importKey("raw", utf8(password.normalize("NFC")), "PBKDF2", false, ["deriveBits"])
    const params = { name: "PBKDF2", hash: "SHA-256", salt, iterations }
    const keyHex = tbut.bytesToHex(await subtle.deriveBits(params, baseKey, 48 * 8))
    return { keyHex, saltHex, iterations }
}

//#endregion

//############################################################
//#region asymmetric encryption
// ElGamal style: referencePoint A is sent along, DH(n, B) = DH(k, A) is the shared secret, sha512 of it the symmetric key
export const asymmetricEncryptBytes = async (content, publicKeyBytes, context = "") => {
    const { referencePointBytes, sharedSecretBytes } = await elGamalSecretRawBytes(publicKeyBytes)
    const encryptedContentBytes = await symmetricEncryptBytes(content, await sha512Bytes(sharedSecretBytes), context)
    return { referencePointBytes, encryptedContentBytes }
}

export const asymmetricDecryptBytes = async (secrets, secretKeyBytes, context = "") => {
    const ABytes = secrets.referencePointBytes || secrets.referencePoint
    const gibbrishBytes = secrets.encryptedContentBytes || secrets.encryptedContent
    if (ABytes == null || gibbrishBytes == null) throw new Error("Invalid secrets Object!")
    const kABytes = await diffieHellmanSecretRawBytes(secretKeyBytes, ABytes)
    return symmetricDecryptBytes(gibbrishBytes, await sha512Bytes(kABytes), context)
}

export const asymmetricEncryptHex = async (content, publicKeyHex, context) => {
    const { referencePointBytes, encryptedContentBytes } = await asymmetricEncryptBytes(content, hexToBytes(publicKeyHex), context)
    return { referencePointHex: tbut.bytesToHex(referencePointBytes), encryptedContentHex: tbut.bytesToHex(encryptedContentBytes) }
}

export const asymmetricDecryptHex = (secrets, secretKeyHex, context) => {
    const AHex = secrets.referencePointHex || secrets.referencePoint
    const gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if (AHex == null || gibbrishHex == null) throw new Error("Invalid secrets Object!")
    const secretsBytes = { referencePointBytes: hexToBytes(AHex), encryptedContentBytes: hexToBytes(gibbrishHex) }
    return asymmetricDecryptBytes(secretsBytes, hexToBytes(secretKeyHex), context)
}
export const asymmetricEncrypt = asymmetricEncryptHex
export const asymmetricDecrypt = asymmetricDecryptHex

//#endregion

//############################################################
//#region diffieHellman/ElGamal secrets
// X25519: h = sha512(our secretKey)[0:32], B = their publicKey, shared secret = u(clamp(h)·B) - same as v0.1.0-0.2.0
// clamping makes the scalar a multiple of 8, so a torsion component of B drops out
export const diffieHellmanSecretRawBytes = async (secretKeyBytes, publicKeyBytes) => {
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

export const diffieHellmanSecretHashBytes = async (secretKeyBytes, publicKeyBytes, contextString = "") => {
    const kBBytes = await diffieHellmanSecretRawBytes(secretKeyBytes, publicKeyBytes)
    return sha512Bytes(concat(kBBytes, utf8(contextString)))
}

// one-time secret key n, A = publicKey(n) = referencePoint, shared secret = DH(n, B)
export const elGamalSecretRawBytes = async (publicKeyBytes) => {
    const n = ed.utils.randomSecretKey()
    const sharedSecretBytes = await diffieHellmanSecretRawBytes(n, publicKeyBytes)
    return { referencePointBytes: await createPublicKeyBytes(n), sharedSecretBytes }
}

export const elGamalSecretHashBytes = async (publicKeyBytes, contextString = "") => {
    const { referencePointBytes, sharedSecretBytes } = await elGamalSecretRawBytes(publicKeyBytes)
    return { referencePointBytes, sharedSecretBytes: await sha512Bytes(concat(sharedSecretBytes, utf8(contextString))) }
}

export const diffieHellmanSecretRawHex = async (secretKeyHex, publicKeyHex) => tbut.bytesToHex(await diffieHellmanSecretRawBytes(hexToBytes(secretKeyHex), hexToBytes(publicKeyHex)))
export const diffieHellmanSecretHashHex = async (secretKeyHex, publicKeyHex, contextString = "") => tbut.bytesToHex(await diffieHellmanSecretHashBytes(hexToBytes(secretKeyHex), hexToBytes(publicKeyHex), contextString))

export const elGamalSecretRawHex = async (publicKeyHex) => {
    const { referencePointBytes, sharedSecretBytes } = await elGamalSecretRawBytes(hexToBytes(publicKeyHex))
    return { referencePointHex: tbut.bytesToHex(referencePointBytes), sharedSecretHex: tbut.bytesToHex(sharedSecretBytes) }
}
export const elGamalSecretHashHex = async (publicKeyHex, contextString = "") => {
    const { referencePointBytes, sharedSecretBytes } = await elGamalSecretHashBytes(hexToBytes(publicKeyHex), contextString)
    return { referencePointHex: tbut.bytesToHex(referencePointBytes), sharedSecretHex: tbut.bytesToHex(sharedSecretBytes) }
}

// aliases - kept for compatibility
export const diffieHellmanSecretRaw = diffieHellmanSecretRawHex
export const createSharedSecretRaw = diffieHellmanSecretRawHex
export const createSharedSecretRawHex = diffieHellmanSecretRawHex
export const sharedSecretRawBytes = diffieHellmanSecretRawBytes

export const diffieHellmanSecretHash = diffieHellmanSecretHashHex
export const createSharedSecretHash = diffieHellmanSecretHashHex
export const createSharedSecretHashHex = diffieHellmanSecretHashHex
export const sharedSecretHashBytes = diffieHellmanSecretHashBytes

export const elGamalSecretRaw = elGamalSecretRawHex
export const referencedSharedSecretRaw = elGamalSecretRawHex
export const referencedSharedSecretRawHex = elGamalSecretRawHex
export const referencedSecretRaw = elGamalSecretRawHex
export const referencedSecretRawHex = elGamalSecretRawHex
export const referencedSharedSecretRawBytes = elGamalSecretRawBytes
export const referencedSecretRawBytes = elGamalSecretRawBytes

export const elGamalSecretHash = elGamalSecretHashHex
export const referencedSharedSecretHash = elGamalSecretHashHex
export const referencedSharedSecretHashHex = elGamalSecretHashHex
export const referencedSecretHash = elGamalSecretHashHex
export const referencedSecretHashHex = elGamalSecretHashHex
export const referencedSharedSecretHashBytes = elGamalSecretHashBytes
export const referencedSecretHashBytes = elGamalSecretHashBytes

//#endregion

//############################################################
//#region legacy salt envelope
// strips the salt envelope v0.3.1 put around content before AES-CBC
const unsaltContent = (contentBytes) => {
    const fullLength = contentBytes.length
    const limit = Math.min(fullLength, 160)

    let sum = 0
    let idx = 32
    while (idx--) sum += contentBytes[idx]

    let start, padding
    for (idx = 32; idx <= limit; idx++) {
        if (sum == (contentBytes[idx] * 256 + contentBytes[idx + 1])) {
            start = idx + 3
            padding = contentBytes[idx + 2]
            break
        }
        sum += contentBytes[idx]
    }
    if (idx > limit) throw new Error("Unsalt: No valid prefix ending found!")

    // Check if the padding matches the salt - so we can verify here nobody has tampered with it
    const end = fullLength - 1
    let invalid = 0
    for (idx = 0; idx < padding; idx++) invalid += (contentBytes[idx] != contentBytes[end - idx])
    if (invalid) throw new Error("Unsalt: Postfix and prefix did not match as expected!")

    return tbut.bytesToUtf8(contentBytes.subarray(start, fullLength - padding))
}

//#endregion
