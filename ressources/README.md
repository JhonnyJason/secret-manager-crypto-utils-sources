# secret-manager-crypto-utils 

## Background
For the specific usecases in the edeavor to get a reasonable [Secret Management](https://hackmd.io/PZjpRfzPSBCqS-8K54x2jA) we do not need too many features such that it made sense to specifically craft this small convenience library for the small required functionality.

This is:

- sha256
- sha512
- Sign/Verify via Ed25519
- Asymmetric Encrypt/Decrypt in ElGamal style using the Twisted Edwards Curve
- Symmetric Encrypt/Decrypt with [`salted`](#salt-envelope) AES-256-CBC
- DiffieHellman style sharedSecret as `privA * pubB = privB * pubA` in Raw and Hashed version 
- ElGamal style sharedSecret using an ephemeral random `privA` and providing the referencePoint `pubA` in Raw and Hashed version

This is directly used by other parts of the [Secret Management](https://hackmd.io/PZjpRfzPSBCqS-8K54x2jA?view) system.

## Usage
Current Functionality
---------------------

```coffee
import *  as secUtl from "secret-manager-crypto-utils"

## shas
# secUtl.sha256 is secUtl.sha256Hex 
await secUtl.sha256Hex( String ) -> StringHex

await secUtl.sha256Bytes( String ) -> Uint8Array | Buffer


# secUtl.sha512 is secUtl.sha512Hex
await secUtl.sha512Hex( String ) -> StringHex

await secUtl.sha512Bytes( String ) -> Uint8Array | Buffer


## keys
# secUtl.createKeyPair is secUtl.createKeyPairHex
await secUtl.createKeyPairHex() -> Object { secretKeyHex, publicKeyHex }
await secUtl.createKeyPairHex() -> Object { StringHex, StringHex }

await secUtl.createKeyPairBytes() -> Object { secretKeyBytes, publicKeyBytes }
await secUtl.createKeyPairBytes() -> Object { Uint8Array, Uint8Array }


# secUtl.publicKey is secUtl.publicKeyHex
await secUtl.publicKeyHex( secretKeyHex ) -> publicKeyHex
await secUtl.publicKeyHex( StringHex ) -> StringHex

await secUtl.publicKeyBytes( secretKeyBytes ) -> publicKeyBytes
await secUtl.publicKeyBytes( Uint8Array ) -> Uint8Array


#secUtl.createSymKey = secUtl.createSymKeyHex
secUtl.createSymKeyHex() -> StringHex 

secUtl.createSymKeyBytes() -> Uint8Array


## signatures
# secUtl.createSignature is secUtl.createSignatureHex
await secUtl.createSignatureHex( content, secretKey )
await secUtl.createSignatureHex( String, StringHex ) -> StringHex

await secUtl.createSignatureBytes( content, secretKey )
await secUtl.createSignatureHex( String, Uint8Array ) -> Uint8Array


# secUtl.verify is secUtl.verifyHex
await secUtl.verifyHex( signature, publicKey, content )
await secUtl.verifyHex(StringHex, StringHex, String) -> Boolean

await secUtl.verifyBytes( signature, publicKey, content )
await secUtl.verifyHex( Uint8Array, Uint8Array, String) -> Boolean


## encryption - symmetric
# secUtl.symmetricEncrypt is secUtl.symmetricEncryptHex
await secUtl.symmetricEncryptHex( content, symKey )
await secUtl.symmetricEncryptHex( String, StringHex ) -> StringHex

await secUtl.symmetricEncryptBytes( content, symKey )
await secUtl.symmetricEncryptBytes( String, Uint8Array ) -> Uint8Array


# secUtl.symmetricDecrypt is secUtl.symmetricDecryptHex
await secUtl.symmetricDecryptHex( encryptedContent, symKey )
await secUtl.symmetricDecryptHex( StringHex, StringHex ) -> String

await secUtl.symmetricDecryptBytes( encryptedContent, symKey )
await secUtl.symmetricDecryptBytes( Uint8Array, Uint8Array ) -> String



## encryption - asymmetric
# secUtl.asymmetricEncrypt is secUtl.asymmetricEncryptHex
await secUtl.asymmetricEncryptHex( content, publicKey )
await secUtl.asymmetricEncryptHex( String, StringHex ) -> Object { referencePointHex, encryptetContentsHex }
await secUtl.asymmetricEncryptHex( String, StringHex ) -> Object { StringHex, StringHex}

await secUtl.asymmetricEncryptBytes( content, publicKey )
await secUtl.asymmetricEncryptBytes( String, Uint8Array ) -> Object { referencePointBytes, encryptedContentsBytes }
await secUtl.asymmetricEncryptBytes( String, Uint8Array ) -> Object { Uint8Array, Uint8Array }

# secUtl.asymmetricDecrypt is secUtl.asymmetricDecryptHex
await secUtl.asymmetricDecryptHex( secretsObject, secretKey )
await secUtl.asymmetricDecryptHex( Object { referencePointHex, encryptedContentsHex }, StringHex }, StringHex ) -> String
await secUtl.asymmetricDecryptHex( Object { StringHex, StringHex }, StringHex }, StringHex ) -> String

await secUtl.asymmetricDecryptBytes( secretsObject, secretKey )
await secUtl.asymmetricDecryptBytes( Object { referencePointBytes, encryptedContentsBytes }, Uint8Array ) -> String
await secUtl.asymmetricDecryptBytes( Object { Uint8Array, Uint8Array }, Uint8Array ) -> String


## shared secret - hashed
# secUtl.diffieHellmanSecretHash is secUtl.diffieHellmanSecretHashHex
await secUtl.diffieHellmanSecretHashHex( secretKeyHex, publicKeyHex, context )
await secUtl.diffieHellmanSecretHashHex( StringHex, StringHex, String ) -> StringHex

await secUtl.diffieHellmanSecretHashBytes( secretKeyBytes, publicKeyBytes, context )
await secUtl.diffieHellmanSecretHashBytes( Uint8Array, Uint8Array, String ) -> Uint8Array


## shared secret - raw
# secUtl.diffieHellmanSecretHash is secUtl.diffieHellmanSecretHashHex
await secUtl.diffieHellmanSecretRawHex( secretKeyHex, publicKeyHex)
await secUtl.diffieHellmanSecretRawHex( StringHex, StringHex ) -> StringHex

await secUtl.diffieHellmanSecretRawBytes( secretKeyBytes, publicKeyBytes)
await secUtl.diffieHellmanSecretRawBytes( Uint8Array, Uint8Array ) -> Uint8Array


## referenced secret - hashed
# secUtl.elGamalSecretHash is secUtl.elGamalSecretHashHex
await secUtl.elGamalSecretHashHex( secretKeyHex, publicKeyHex, context )
await secUtl.elGamalSecretHashHex( StringHex, StringHex, String ) -> Object { referencePointHex, sharedSecretHex}
await secUtl.elGamalSecretHashHex( StringHex, StringHex, String ) -> Object { StringHex, StringHex}

await secUtl.elGamalSecretHashBytes( secretKeyBytes, publicKeyBytes, context )
await secUtl.elGamalSecretHashBytes( Uint8Array, Uint8Array, String ) -> Object { referencePointBytes, sharedSecretBytes }
await secUtl.elGamalSecretHashBytes( Uint8Array, Uint8Array, String ) -> Object { Uint8Array, Uint8Array }

## referenced secret - raw
# secUtl.elGamalSecretRaw is secUtl.elGamalSecretRawHex
await secUtl.elGamalSecretRawHex( secretKeyHex, publicKeyHex )
await secUtl.elGamalSecretRawHex( StringHex, StringHex ) -> Object { referencePointHex, sharedSecretHex}
await secUtl.elGamalSecretRawHex( StringHex, StringHex ) -> Object { StringHex, StringHex}

await secUtl.elGamalSecretRawBytes( secretKeyBytes, publicKeyBytes)
await secUtl.elGamalSecretRawBytes( Uint8Array, Uint8Array) -> Object { referencePointBytes, sharedSecretBytes }
await secUtl.elGamalSecretRawBytes( Uint8Array, Uint8Array) -> Object { Uint8Array, Uint8Array }


## salts
secUtl.saltContent(String) -> Uint8Array
secUtl.unsaltContent( Uint8Array ) -> String

```


## Breaking Updates
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
It is adivsable  that you stare all encrypted contents, signatures and keys in hex strings. This appears to be the most superior way of how to universally transfer byte information.

The big wins of hex in readability and processability beats out the "downside" of being 2x the size. Also the performance loss is in most cases neglible ~ < 10%.


## Encryption
For the encryption functionality we use ed25519 keys for producing El-Gamal-style shared secret-keys which we then use for symmetrically encrypting the contents.

The result of this kind of encryption is always an Object like:
```json
{
    "referencePoint":"...",  // StringHex 
    "encryptedContent":"...",  // StringHex 
}
```

The symmetric encryption uses `aes-256-cbc`.

### Potential AES-CBC Weaknesses
There are some potential weaknesses in CBC Mode.
- [Padding Oracle Attacks](https://robertheaton.com/2013/07/29/padding-oracle-attack/)
- [Bit Flipping](https://crypto.stackexchange.com/questions/66085/bit-flipping-attack-on-cbc-mode)
- [predictable IV](https://stackoverflow.com/questions/3008139/why-is-using-a-non-random-iv-with-cbc-mode-a-vulnerability)

While for most cases GCM is recommended to use, the CBC Mode just tastes better.

One part of the solution is our new salt-envelope introduced on `v0.3.0`. It is a padded verifiable envelope of our plaintext consisting of random bytes. 
If any bit is flipped we should see that this envelope has become invalid.

Also generally we donot provide any oracle. Most of these potential attacks rely on an oracle. Because an attacker could try to flip muliple bits in an attempt to cover up the manipulation. If we provide an oracle which could quickly tell the attacker that the message was still valid or not then there is some surface of an attack.

For our purpose what we encrypt are well-kept secrets with unique keys and unique IVs. Only to be accessed sporadically by the consumer. A Service guarantees uncorrupted storage of these secrets - preferrably signing the stored data which makes it tamper-proof at that level anyways. If the consumer receives a corrupted secret this means the service has been corrupted and the recovery scenario would not look like requesting the secret over and over again until decryption is achieved.


## Salt Envelope
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

The Shared Secrets work in this way:
```coffee
aliceSharedSecret = await secUtl.diffieHellmanSecretRaw(privA, pubB) # 32 bytes HexString
bobSharedSecret = await secUtl.diffieHellmanSecretRaw(privB, pubA)
(aliceSharedSecret == bobSharedSecret) # true

```

With the hashed version you may add an arbitrary context. This allows you to generate different sharedSecrets from the same key-pairs.
```coffee
context = "onetime-context@"+Date.now()
aliceSharedSecret = await secUtl.diffieHellmanSecretHash(privA, pubB, context) # 64 bytes HexString
bobSharedSecret = await secUtl.diffieHellmanSecretHash(privB, pubA, context)
(aliceSharedSecret == bobSharedSecret) # true

``` 

### ElGamal Secrets
ElGamal style is relevant for Alice - using any random ephemeral key instead of `privA`.
Bob would use the `diffiHellmanSecret` functions for blending with the `referencePoint`.

```coffee
elGamalSecret = await secUtl.elGamalSecretRaw(pubB) # Object {referencePointHex, sharedSecretHex} 
referencePoint = elGamalSecret.referencePointHex # 32 bytes Hex String
aliceSharedSecret = elGamalSecret.sharedSecretHex  # 32 bytes Hex String
bobSharedSecret = await secUtl.diffieHellmanSecretRaw(privB, referencePointHex)
(aliceSharedSecret == bobSharedSecret) # true

```


```coffee
context = "onetime-context@"+Date.now()
elGamalSecret = await secUtl.elGamalSecretHash(pubB, context) # Object {referencePointHex, sharedSecretHex}
referencePoint = elGamalSecret.referencePointHex # 32 bytes Hex String
aliceSharedSecret = elGamalSecret.sharedSecretHex  # 64 bytes Hex String
bobSharedSecret = await secUtl.diffieHellmanSecretHash(privB, referencePointHex, context)
(aliceSharedSecret == bobSharedSecret) # true

``` 

## Noble ed25519
All of this is straight forward based on [noble-ed25519](https://github.com/paulmillr/noble-ed25519). A very concise and modern package for freely using the ed25519 algorithms. Big thanks for that!

---

All sorts of inputs are welcome, thanks!

---


# License
[Unlicense JhonnyJason style](https://hackmd.io/nCpLO3gxRlSmKVG3Zxy2hA?view)