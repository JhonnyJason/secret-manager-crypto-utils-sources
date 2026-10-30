// Read-only functions for data written by old versions: read, then re-encrypt or re-sign with the main API.
// The key decides the mode: a hex string key takes/gives hex, a Uint8Array key takes/gives Uint8Array.
// Removed once all deprecated data is converted.

type Key = string | Uint8Array
type LegacySecrets =
    | { referencePointHex: string, encryptedContentHex: string }
    | { referencePointBytes: Uint8Array, encryptedContentBytes: Uint8Array }
    | { referencePoint: string, encryptedContent: string } // 0.0.x

/** 0.0.1 – 0.2.0. No integrity check: a wrong key may return garbage - try V0_3_1 first. */
export declare function symmetricDecryptV0_2_0(gibbrish: Key, key: Key): Promise<string>
/** 0.3.0 – 0.3.1 */
export declare function symmetricDecryptV0_3_1(gibbrish: Key, key: Key): Promise<string>

/** 0.0.4 – 0.0.7, and asymmetricEncryptOld of 0.1.0 – 0.2.0 */
export declare function asymmetricDecryptV0_0_7(secrets: LegacySecrets, secretKey: Key): Promise<string>
/** 0.1.0 – 0.2.0 */
export declare function asymmetricDecryptV0_2_0(secrets: LegacySecrets, secretKey: Key): Promise<string>
/** 0.3.0 – 0.3.1 */
export declare function asymmetricDecryptV0_3_1(secrets: LegacySecrets, secretKey: Key): Promise<string>

/** 0.0.2 – 0.2.0 signed sha256(content). Resolves undefined when valid, else an error string. Never rejects. */
export declare function verifySignatureV0_2_0(sig: Key, publicKey: Key, content: string): Promise<string | undefined>

/** 0.2.0 hashed secrets: sha512(X25519 secret ‖ context), no public keys bound. The raw secret is main's diffieHellmanSecretRaw. ElGamal recovery: pass the referencePoint as publicKey. */
export declare function diffieHellmanSecretHashV0_2_0<K extends Key>(secretKey: K, publicKey: Key, contextString?: string): Promise<K>

/** 0.3.0 – 0.3.1 Edwards-point secrets. ElGamal recovery: pass the referencePoint as publicKey. */
export declare function diffieHellmanSecretRawV0_3_1<K extends Key>(secretKey: K, publicKey: Key): Promise<K>
export declare function diffieHellmanSecretHashV0_3_1<K extends Key>(secretKey: K, publicKey: Key, contextString?: string): Promise<K>
