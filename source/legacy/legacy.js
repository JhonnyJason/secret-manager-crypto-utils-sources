//############################################################
// read-only functions for data written by old versions - read, then re-encrypt/re-sign with the main API
// spec: testing/legacy-formats.md - remove this entry point once all deprecated data is converted
import * as ed from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"
import { sha256Bytes, sha512Bytes, diffieHellmanSecretRaw } from "./index.js"

const subtle = globalThis.crypto.subtle

//############################################################
//#region internalFunctions
// same type checks as index.js - thingy-byte-utils validates the content
const hexToBytes = (hex) => {
    if (typeof hex != "string") throw new TypeError("Expected a hex string!")
    return tbut.hexToBytes(hex)
}

const checkBytes = (bytes) => {
    if (!(bytes instanceof Uint8Array)) throw new TypeError("Expected a Uint8Array!")
}

const utf8 = (content) => {
    if (typeof content != "string") throw new TypeError("Content must be a string!")
    return tbut.utf8ToBytes(content)
}

// hex mode: a hex key gives hex results, a Uint8Array key gives Uint8Array results
const isHex = (x) => typeof x == "string"
const asBytes = (x) => isHex(x) ? hexToBytes(x) : x
const asModeOf = (key, bytes) => isHex(key) ? tbut.bytesToHex(bytes) : bytes

const concat = (a, b) => {
    const result = new Uint8Array(a.length + b.length)
    result.set(a)
    result.set(b, a.length)
    return result
}

// AES-256-CBC, iv = key[0:16], aesKey = key[16:48] - the iv is the same for every message
const cbc = async (gibbrishBytes, keyBytes) => {
    checkBytes(gibbrishBytes)
    checkBytes(keyBytes)
    if (keyBytes.length < 48) throw new RangeError("Symmetric key must have at least 48 bytes!")
    const key = await subtle.importKey("raw", keyBytes.subarray(16, 48), { name: "AES-CBC" }, false, ["decrypt"])
    return new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv: keyBytes.subarray(0, 16) }, key, gibbrishBytes))
}

// k·A on the Edwards curve, k = clamped sha512(sk)[0:32] mod L - the same point in every noble version
const edwardsSecret = async (secretKeyBytes, publicKeyBytes) => {
    checkBytes(secretKeyBytes)
    const { scalar } = await ed.utils.getExtendedPublicKeyAsync(secretKeyBytes)
    const A = ed.Point.fromBytes(publicKeyBytes)
    if (A.isSmallOrder()) throw new RangeError("Invalid public key!")
    return A.multiply(scalar)
}

// …Hex, …Bytes, and the unsuffixed names of 0.0.x
const readSecrets = (secrets) => {
    const A = secrets.referencePointHex || secrets.referencePointBytes || secrets.referencePoint
    const gibbrish = secrets.encryptedContentHex || secrets.encryptedContentBytes || secrets.encryptedContent
    if (A == null || gibbrish == null) throw new Error("Invalid secrets Object!")
    return [asBytes(A), asBytes(gibbrish)]
}

//#endregion

//############################################################
//#region symmetric
// 0.0.1 - 0.2.0: no integrity check - a wrong key may return garbage (~1/256)
const symmetricDecryptBytesV0_2_0 = async (gibbrishBytes, keyBytes) => tbut.bytesToUtf8(await cbc(gibbrishBytes, keyBytes))
// 0.3.0 - 0.3.1: CBC + salt envelope
const symmetricDecryptBytesV0_3_1 = async (gibbrishBytes, keyBytes) => unsaltContent(await cbc(gibbrishBytes, keyBytes))

export const symmetricDecryptV0_2_0 = async (gibbrish, key) => symmetricDecryptBytesV0_2_0(asBytes(gibbrish), asBytes(key))
export const symmetricDecryptV0_3_1 = async (gibbrish, key) => symmetricDecryptBytesV0_3_1(asBytes(gibbrish), asBytes(key))

//#endregion

//############################################################
//#region asymmetric
// 0.0.4 - 0.0.7 and asymmetricEncryptOld of 0.1.0 - 0.2.0: key = sha512 of the lowercase hex *string* of k·A
export const asymmetricDecryptV0_0_7 = async (secrets, secretKey) => {
    const [ABytes, gibbrishBytes] = readSecrets(secrets)
    const kA = await edwardsSecret(asBytes(secretKey), ABytes)
    return symmetricDecryptBytesV0_2_0(gibbrishBytes, await sha512Bytes(kA.toHex()))
}

// 0.1.0 - 0.2.0: key = sha512(X25519 secret) - main DH is the same X25519
export const asymmetricDecryptV0_2_0 = async (secrets, secretKey) => {
    const [ABytes, gibbrishBytes] = readSecrets(secrets)
    const shared = await diffieHellmanSecretRaw(asBytes(secretKey), ABytes)
    return symmetricDecryptBytesV0_2_0(gibbrishBytes, await sha512Bytes(shared))
}

// 0.3.0 - 0.3.1: key = sha512(k·A point bytes)
export const asymmetricDecryptV0_3_1 = async (secrets, secretKey) => {
    const [ABytes, gibbrishBytes] = readSecrets(secrets)
    const kA = await edwardsSecret(asBytes(secretKey), ABytes)
    return symmetricDecryptBytesV0_3_1(gibbrishBytes, await sha512Bytes(kA.toBytes()))
}

//#endregion

//############################################################
//#region signatures
// 0.0.2 - 0.2.0 signed sha256(content), not the content - same contract as main verifySignature: undefined when valid, never throws
// strict RFC 8032 with noble only: canonical encodings, small-order keys rejected
export const verifySignatureV0_2_0 = async (sig, key, content) => {
    try {
        const message = await sha256Bytes(utf8(content))
        if (await ed.verifyAsync(asBytes(sig), message, asBytes(key), { zip215: false })) return undefined
        return "Invalid signature!"
    } catch { return "Malformed input!" }
}

//#endregion

//############################################################
//#region diffieHellman/ElGamal secrets
// 0.1.0 - 0.2.0: sha512(X25519 secret ‖ context) without the public keys - the raw secret is main's diffieHellmanSecretRaw
export const diffieHellmanSecretHashV0_2_0 = async (secretKey, publicKey, contextString = "") => {
    const kBBytes = await diffieHellmanSecretRaw(asBytes(secretKey), asBytes(publicKey))
    return asModeOf(secretKey, await sha512Bytes(concat(kBBytes, utf8(contextString))))
}

// 0.3.0 - 0.3.1: the Edwards point k·B instead of X25519 - elGamal recovery: the receiver passes the referencePoint as publicKey
const diffieHellmanSecretRawBytesV0_3_1 = async (secretKeyBytes, publicKeyBytes) => (await edwardsSecret(secretKeyBytes, publicKeyBytes)).toBytes()

export const diffieHellmanSecretRawV0_3_1 = async (secretKey, publicKey) => asModeOf(secretKey, await diffieHellmanSecretRawBytesV0_3_1(asBytes(secretKey), asBytes(publicKey)))
export const diffieHellmanSecretHashV0_3_1 = async (secretKey, publicKey, contextString = "") => {
    const kBBytes = await diffieHellmanSecretRawBytesV0_3_1(asBytes(secretKey), asBytes(publicKey))
    return asModeOf(secretKey, await sha512Bytes(concat(kBBytes, utf8(contextString))))
}

//#endregion

//############################################################
//#region salt envelope
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
