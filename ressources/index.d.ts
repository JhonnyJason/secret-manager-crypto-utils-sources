// Key: a hex string (any case) or a Uint8Array. The key decides the mode: a hex key gives hex results
// (always lowercase), a Uint8Array key gives Uint8Array results. Other byte arguments may come in either form.
// contentString: a well-formed string (no lone surrogates). Every function returns a Promise.

export type Key = string | Uint8Array
type Mode<K extends Key, Hex, Bytes> = K extends string ? Hex : Bytes

//############################################################
// sha*: hex output, the …Bytes variants give Uint8Array
export declare function sha256(content: string | Uint8Array): Promise<string>
export declare function sha512(content: string | Uint8Array): Promise<string>
export declare function sha256Bytes(content: string | Uint8Array): Promise<Uint8Array>
export declare function sha512Bytes(content: string | Uint8Array): Promise<Uint8Array>

//############################################################
export declare function createKeyPair(): Promise<{ secretKeyHex: string, publicKeyHex: string }>
export declare function createKeyPairBytes(): Promise<{ secretKeyBytes: Uint8Array, publicKeyBytes: Uint8Array }>
/** 48 bytes */
export declare function createSymKey(): Promise<string>
export declare function createSymKeyBytes(): Promise<Uint8Array>
export declare function createPublicKey<K extends Key>(secretKey: K): Promise<K>

//############################################################
/** Ed25519, strict RFC 8032. Note the order: content first here, signature first in verifySignature. */
export declare function createSignature<K extends Key>(contentString: string, secretKey: K): Promise<K>
/** Resolves undefined when the signature is valid, else an error string. Never rejects: `if (err)` means invalid. */
export declare function verifySignature(signature: Key, publicKey: Key, contentString: string): Promise<string | undefined>

//############################################################
/** AES-256-GCM format v1. Key: >= 48 bytes. context: authenticated, not transmitted - decrypt needs the same one. */
export declare function symmetricEncrypt<K extends Key>(contentString: string, key: K, context?: string): Promise<K>
/** Reads format v1 only - older data: secret-manager-crypto-utils/legacy. Throws Error("Decryption failed!"). */
export declare function symmetricDecrypt(gibbrish: Key, key: Key, context?: string): Promise<string>

/** PBKDF2-SHA256 -> 48 byte key. For passwords only. saltHex: >= 16 bytes, random by default. iterations: 1000..10000000. */
export declare function deriveSymKeyFromPassword(password: string, saltHex?: string, iterations?: number): Promise<{ keyHex: string, saltHex: string, iterations: number }>

//############################################################
export interface SecretsHex { referencePointHex: string, encryptedContentHex: string }
export interface SecretsBytes { referencePointBytes: Uint8Array, encryptedContentBytes: Uint8Array }

/** Not authenticated: anyone with the public key can encrypt - sign the content if the sender matters. */
export declare function asymmetricEncrypt<K extends Key>(contentString: string, publicKey: K, context?: string): Promise<Mode<K, SecretsHex, SecretsBytes>>
export declare function asymmetricDecrypt(secrets: SecretsHex | SecretsBytes, secretKey: Key, context?: string): Promise<string>

//############################################################
// two keys: the secretKey decides the mode
/** X25519, 32 bytes. Equivalent encodings of a public key (B, -B, B + torsion) give the same raw secret. */
export declare function diffieHellmanSecretRaw<K extends Key>(secretKey: K, publicKey: Key): Promise<K>
/** sha512(raw ‖ lower publicKey ‖ higher publicKey ‖ utf8(contextString)), 64 bytes - binds both public keys as transmitted. */
export declare function diffieHellmanSecretHash<K extends Key>(secretKey: K, publicKey: Key, contextString?: string): Promise<K>

export interface SharedSecretHex { referencePointHex: string, sharedSecretHex: string }
export interface SharedSecretBytes { referencePointBytes: Uint8Array, sharedSecretBytes: Uint8Array }
/** The receiver gets the same secret from diffieHellmanSecretRaw/Hash(secretKey, referencePoint). */
export declare function elGamalSecretRaw<K extends Key>(publicKey: K): Promise<Mode<K, SharedSecretHex, SharedSecretBytes>>
export declare function elGamalSecretHash<K extends Key>(publicKey: K, contextString?: string): Promise<Mode<K, SharedSecretHex, SharedSecretBytes>>
