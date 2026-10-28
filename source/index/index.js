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

// a shorter key would silently become AES-128/192 or fail late inside WebCrypto
const checkSymKey = (keyBytes) => {
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

// small-order points give a shared secret everybody knows
const publicPoint = (publicKeyBytes) => {
    const P = ed.Point.fromBytes(publicKeyBytes)
    if (P.isSmallOrder()) throw new RangeError("Invalid public key!")
    return P
}

// sha512(secretKey) clamped and reduced mod ORDER - the ed25519 secret scalar
const secretScalar = async (secretKeyBytes) => (await ed.utils.getExtendedPublicKeyAsync(secretKeyBytes)).scalar

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
export const createSymKeyBytes = () => randomBytes(48)
export const createPublicKeyBytes = (secretKeyBytes) => ed.getPublicKeyAsync(secretKeyBytes)

export const createKeyPairHex = async () => {
    const { secretKeyBytes, publicKeyBytes } = await createKeyPairBytes()
    return { secretKeyHex: tbut.bytesToHex(secretKeyBytes), publicKeyHex: tbut.bytesToHex(publicKeyBytes) }
}
export const createSymKeyHex = () => tbut.bytesToHex(createSymKeyBytes())
export const createPublicKeyHex = async (secretKeyHex) => tbut.bytesToHex(await createPublicKeyBytes(hexToBytes(secretKeyHex)))
export const createKeyPair = createKeyPairHex
export const createSymKey = createSymKeyHex
export const createPublicKey = createPublicKeyHex

//#endregion

//############################################################
//#region signatures
export const createSignatureBytes = async (content, signingKeyBytes) => ed.signAsync(utf8(content), signingKeyBytes)
// strict RFC 8032: zip215 accepts small-order keys for which one signature verifies any message
export const verifyBytes = async (sigBytes, keyBytes, content) => ed.verifyAsync(sigBytes, utf8(content), keyBytes, { zip215: false })

export const createSignatureHex = async (content, signingKeyHex) => tbut.bytesToHex(await createSignatureBytes(content, hexToBytes(signingKeyHex)))
export const verifyHex = (sigHex, keyHex, content) => verifyBytes(hexToBytes(sigHex), hexToBytes(keyHex), content)
export const createSignature = createSignatureHex
export const verify = verifyHex

//#endregion

//############################################################
//#region symmetric encryption
// format v1: 0x01 ‖ nonce(12) ‖ AES-256-GCM( padLen(1) ‖ content ‖ random(padLen) ) ‖ tag(16)
// key: 48 bytes, v1 uses bytes 16..47 as AES key (bytes 0..15 were the legacy CBC iv)
// subarray respects the byteOffset of views
const V1 = 0x01
const NONCE_LENGTH = 12
const V1_MIN_LENGTH = 1 + NONCE_LENGTH + 16 + 1 // version, nonce, tag, padLen

export const symmetricEncryptBytes = async (content, keyBytes) => {
    checkSymKey(keyBytes)
    const key = await importAesGcmKey(keyBytes.subarray(16, 48))
    // random nonce per message, never a parameter: a reuse under one key breaks GCM
    const nonce = randomBytes(NONCE_LENGTH)
    const sealed = await subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, key, padContent(content))
    const result = new Uint8Array(1 + NONCE_LENGTH + sealed.byteLength)
    result[0] = V1
    result.set(nonce, 1)
    result.set(new Uint8Array(sealed), 1 + NONCE_LENGTH)
    return result
}

// v1 when the tag verifies, else legacy CBC (1/256 of legacy ciphertexts start with 0x01 too)
export const symmetricDecryptBytes = async (gibbrishBytes, keyBytes) => {
    checkSymKey(keyBytes)
    if (gibbrishBytes[0] == V1 && gibbrishBytes.length >= V1_MIN_LENGTH) {
        try { return await decryptV1(gibbrishBytes, keyBytes) } catch { }
    }
    try { return await decryptLegacy(gibbrishBytes, keyBytes) } catch { }
    throw new Error("Decryption failed!")
}

const decryptV1 = async (gibbrishBytes, keyBytes) => {
    const key = await importAesGcmKey(keyBytes.subarray(16, 48))
    const nonce = gibbrishBytes.subarray(1, 1 + NONCE_LENGTH)
    // WebCrypto verifies the tag before releasing any plaintext
    const padded = await subtle.decrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, key, gibbrishBytes.subarray(1 + NONCE_LENGTH))
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

export const symmetricEncryptHex = async (content, keyHex) => tbut.bytesToHex(await symmetricEncryptBytes(content, hexToBytes(keyHex)))
export const symmetricDecryptHex = (gibbrishHex, keyHex) => symmetricDecryptBytes(hexToBytes(gibbrishHex), hexToBytes(keyHex))
export const symmetricEncrypt = symmetricEncryptHex
export const symmetricDecrypt = symmetricDecryptHex

// PBKDF2-SHA256 -> 48 byte symmetric key, for low-entropy inputs (passwords, PINs) only
// NFC: the same password typed on different platforms may arrive in different unicode forms
export const deriveSymKeyFromPassword = async (password, saltHex = tbut.bytesToHex(randomBytes(16)), iterations = 600000) => {
    if (!Number.isInteger(iterations) || iterations < 1) throw new RangeError("Iterations must be a positive integer!")
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
// ElGamal style: A = lG is sent along, lB = kA is the shared secret, sha512(lB) the symmetric key
export const asymmetricEncryptBytes = async (content, publicKeyBytes) => {
    const { referencePointBytes, sharedSecretBytes } = await elGamalSecretRawBytes(publicKeyBytes)
    const encryptedContentBytes = await symmetricEncryptBytes(content, await sha512Bytes(sharedSecretBytes))
    return { referencePointBytes, encryptedContentBytes }
}

export const asymmetricDecryptBytes = async (secrets, secretKeyBytes) => {
    const ABytes = secrets.referencePointBytes || secrets.referencePoint
    const gibbrishBytes = secrets.encryptedContentBytes || secrets.encryptedContent
    if (ABytes == null || gibbrishBytes == null) throw new Error("Invalid secrets Object!")
    const kABytes = await diffieHellmanSecretRawBytes(secretKeyBytes, ABytes)
    return symmetricDecryptBytes(gibbrishBytes, await sha512Bytes(kABytes))
}

export const asymmetricEncryptHex = async (content, publicKeyHex) => {
    const { referencePointBytes, encryptedContentBytes } = await asymmetricEncryptBytes(content, hexToBytes(publicKeyHex))
    return { referencePointHex: tbut.bytesToHex(referencePointBytes), encryptedContentHex: tbut.bytesToHex(encryptedContentBytes) }
}

export const asymmetricDecryptHex = (secrets, secretKeyHex) => {
    const AHex = secrets.referencePointHex || secrets.referencePoint
    const gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if (AHex == null || gibbrishHex == null) throw new Error("Invalid secrets Object!")
    const secretsBytes = { referencePointBytes: hexToBytes(AHex), encryptedContentBytes: hexToBytes(gibbrishHex) }
    return asymmetricDecryptBytes(secretsBytes, hexToBytes(secretKeyHex))
}
export const asymmetricEncrypt = asymmetricEncryptHex
export const asymmetricDecrypt = asymmetricDecryptHex

//#endregion

//############################################################
//#region diffieHellman/ElGamal secrets
// k = secretScalar(our secretKey), B = their publicKey, kB = shared secret
export const diffieHellmanSecretRawBytes = async (secretKeyBytes, publicKeyBytes) => {
    const B = publicPoint(publicKeyBytes)
    return B.multiply(await secretScalar(secretKeyBytes)).toBytes()
}

export const diffieHellmanSecretHashBytes = async (secretKeyBytes, publicKeyBytes, contextString = "") => {
    const kBBytes = await diffieHellmanSecretRawBytes(secretKeyBytes, publicKeyBytes)
    return sha512Bytes(concat(kBBytes, utf8(contextString)))
}

// one-time secret n -> l = secretScalar(n), A = lG = referencePoint, lB = shared secret
export const elGamalSecretRawBytes = async (publicKeyBytes) => {
    const B = publicPoint(publicKeyBytes)
    const { scalar, pointBytes } = await ed.utils.getExtendedPublicKeyAsync(ed.utils.randomSecretKey())
    return { referencePointBytes: pointBytes, sharedSecretBytes: B.multiply(scalar).toBytes() }
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
