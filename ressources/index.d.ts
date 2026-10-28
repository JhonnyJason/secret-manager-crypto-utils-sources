// Hex: lowercase or uppercase hex string. Content: well-formed string (no lone surrogates).

export declare function sha256Hex(content: string | Uint8Array): Promise<string>
export declare function sha512Hex(content: string | Uint8Array): Promise<string>
export declare function sha256Bytes(content: string | Uint8Array): Promise<Uint8Array>
export declare function sha512Bytes(content: string | Uint8Array): Promise<Uint8Array>
export declare const sha256: typeof sha256Hex
export declare const sha512: typeof sha512Hex

//############################################################
export declare function createKeyPairHex(): Promise<{ secretKeyHex: string, publicKeyHex: string }>
export declare function createKeyPairBytes(): Promise<{ secretKeyBytes: Uint8Array, publicKeyBytes: Uint8Array }>
export declare function createPublicKeyHex(secretKeyHex: string): Promise<string>
export declare function createPublicKeyBytes(secretKeyBytes: Uint8Array): Promise<Uint8Array>
export declare function createSymKeyHex(): string
export declare function createSymKeyBytes(): Uint8Array
export declare const createKeyPair: typeof createKeyPairHex
export declare const createPublicKey: typeof createPublicKeyHex
export declare const createSymKey: typeof createSymKeyHex

//############################################################
export declare function createSignatureHex(content: string, secretKeyHex: string): Promise<string>
export declare function createSignatureBytes(content: string, secretKeyBytes: Uint8Array): Promise<Uint8Array>
export declare function verifyHex(sigHex: string, publicKeyHex: string, content: string): Promise<boolean>
export declare function verifyBytes(sigBytes: Uint8Array, publicKeyBytes: Uint8Array, content: string): Promise<boolean>
export declare const createSignature: typeof createSignatureHex
export declare const verify: typeof verifyHex

//############################################################
/** AES-256-GCM format v1. Key: >= 48 bytes. */
export declare function symmetricEncryptHex(content: string, keyHex: string): Promise<string>
export declare function symmetricEncryptBytes(content: string, keyBytes: Uint8Array): Promise<Uint8Array>
/** Reads format v1 and legacy v0.3.x. Throws Error("Decryption failed!"). */
export declare function symmetricDecryptHex(gibbrishHex: string, keyHex: string): Promise<string>
export declare function symmetricDecryptBytes(gibbrishBytes: Uint8Array, keyBytes: Uint8Array): Promise<string>
export declare const symmetricEncrypt: typeof symmetricEncryptHex
export declare const symmetricDecrypt: typeof symmetricDecryptHex

/** PBKDF2-SHA256 -> 48 byte key. For passwords and PINs only. saltHex: >= 16 bytes, random by default. */
export declare function deriveSymKeyFromPassword(password: string, saltHex?: string, iterations?: number): Promise<{ keyHex: string, saltHex: string, iterations: number }>

//############################################################
export interface SecretsHex { referencePointHex: string, encryptedContentHex: string }
export interface SecretsBytes { referencePointBytes: Uint8Array, encryptedContentBytes: Uint8Array }

export declare function asymmetricEncryptHex(content: string, publicKeyHex: string): Promise<SecretsHex>
export declare function asymmetricEncryptBytes(content: string, publicKeyBytes: Uint8Array): Promise<SecretsBytes>
export declare function asymmetricDecryptHex(secrets: SecretsHex | { referencePoint: string, encryptedContent: string }, secretKeyHex: string): Promise<string>
export declare function asymmetricDecryptBytes(secrets: SecretsBytes | { referencePoint: Uint8Array, encryptedContent: Uint8Array }, secretKeyBytes: Uint8Array): Promise<string>
export declare const asymmetricEncrypt: typeof asymmetricEncryptHex
export declare const asymmetricDecrypt: typeof asymmetricDecryptHex

//############################################################
export declare function diffieHellmanSecretRawHex(secretKeyHex: string, publicKeyHex: string): Promise<string>
export declare function diffieHellmanSecretRawBytes(secretKeyBytes: Uint8Array, publicKeyBytes: Uint8Array): Promise<Uint8Array>
export declare function diffieHellmanSecretHashHex(secretKeyHex: string, publicKeyHex: string, contextString?: string): Promise<string>
export declare function diffieHellmanSecretHashBytes(secretKeyBytes: Uint8Array, publicKeyBytes: Uint8Array, contextString?: string): Promise<Uint8Array>

export declare function elGamalSecretRawHex(publicKeyHex: string): Promise<{ referencePointHex: string, sharedSecretHex: string }>
export declare function elGamalSecretRawBytes(publicKeyBytes: Uint8Array): Promise<{ referencePointBytes: Uint8Array, sharedSecretBytes: Uint8Array }>
export declare function elGamalSecretHashHex(publicKeyHex: string, contextString?: string): Promise<{ referencePointHex: string, sharedSecretHex: string }>
export declare function elGamalSecretHashBytes(publicKeyBytes: Uint8Array, contextString?: string): Promise<{ referencePointBytes: Uint8Array, sharedSecretBytes: Uint8Array }>

// aliases - kept for compatibility
export declare const diffieHellmanSecretRaw: typeof diffieHellmanSecretRawHex
export declare const createSharedSecretRaw: typeof diffieHellmanSecretRawHex
export declare const createSharedSecretRawHex: typeof diffieHellmanSecretRawHex
export declare const sharedSecretRawBytes: typeof diffieHellmanSecretRawBytes

export declare const diffieHellmanSecretHash: typeof diffieHellmanSecretHashHex
export declare const createSharedSecretHash: typeof diffieHellmanSecretHashHex
export declare const createSharedSecretHashHex: typeof diffieHellmanSecretHashHex
export declare const sharedSecretHashBytes: typeof diffieHellmanSecretHashBytes

export declare const elGamalSecretRaw: typeof elGamalSecretRawHex
export declare const referencedSharedSecretRaw: typeof elGamalSecretRawHex
export declare const referencedSharedSecretRawHex: typeof elGamalSecretRawHex
export declare const referencedSecretRaw: typeof elGamalSecretRawHex
export declare const referencedSecretRawHex: typeof elGamalSecretRawHex
export declare const referencedSharedSecretRawBytes: typeof elGamalSecretRawBytes
export declare const referencedSecretRawBytes: typeof elGamalSecretRawBytes

export declare const elGamalSecretHash: typeof elGamalSecretHashHex
export declare const referencedSharedSecretHash: typeof elGamalSecretHashHex
export declare const referencedSharedSecretHashHex: typeof elGamalSecretHashHex
export declare const referencedSecretHash: typeof elGamalSecretHashHex
export declare const referencedSecretHashHex: typeof elGamalSecretHashHex
export declare const referencedSharedSecretHashBytes: typeof elGamalSecretHashBytes
export declare const referencedSecretHashBytes: typeof elGamalSecretHashBytes
