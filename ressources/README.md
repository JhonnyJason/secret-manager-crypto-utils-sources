# secret-manager-crypto-utils 

## Background
For the specific usecases in the edeavor to get a reasonable [Secret Management](https://hackmd.io/PZjpRfzPSBCqS-8K54x2jA) we do not need too many features such that it made sense to specifically craft this small convenience library for the small required functionality.

This is:

- sha256
- sha512
- Sign/Verify via Ed25519
- Asymmetric Encrypt/Decrypt in ElGamal style using Curve25519
- Symmetric Encrypt/Decrypt with AES-256-CBC
- SharedSecret in Raw and Hashed version as privA * pubB = privB * pubA
- ReferencedSharedSecret - using a random PrivA and adding the referencePoint pubA - in Raw and Hashed version
- Random length salts to mitigate Known Plaintext Attacks

This is directly used from other parts of the [Secret Management](https://hackmd.io/PZjpRfzPSBCqS-8K54x2jA?view) system.

## Usage
Current Functionality
---------------------

```coffee
import *  as secUtl from "secret-manager-crypto-utils"

## shas
# secUtl.sha256 is secUtl.sha256Hex 
secUtl.sha256Hex( String ) -> StringHex

secUtl.sha256Bytes( String ) -> Uint8Array | Buffer


# secUtl.sha512 is secUtl.sha512Hex
secUtl.sha512Hex( String ) -> StringHex

secUtl.sha512Bytes( String ) -> Uint8Array | Buffer


## keys
# secUtl.createKeyPair is secUtl.createKeyPairHex
secUtl.createKeyPairHex() -> Object { secretKeyHex, publicKeyHex }
secUtl.createKeyPairHex() -> Object { StringHex, StringHex }

secUtl.createKeyPairBytes() -> Object { secretKeyBytes, publicKeyBytes }
secUtl.createKeyPairBytes() -> Object { Uint8Array, Uint8Array }


# secUtl.publicKey is secUtl.publicKeyHex
secUtl.publicKeyHex( secretKeyHex ) -> publicKeyHex
secUtl.publicKeyHex( StringHex ) -> StringHex

secUtl.publicKeyBytes( secretKeyBytes ) -> publicKeyBytes
secUtl.publicKeyBytes( Uint8Array ) -> Uint8Array


#secUtl.createSymKey = secUtl.createSymKeyHex
secUtl.createSymKeyHex() -> StringHex 

secUtl.createSymKeyBytes() -> Uint8Array


## signatures
# secUtl.createSignature is secUtl.createSignatureHex
secUtl.createSignatureHex( content, secretKey )
secUtl.createSignatureHex( String, StringHex ) -> StringHex

secUtl.createSignatureBytes( content, secretKey )
secUtl.createSignatureHex( String, Uint8Array ) -> Uint8Array


# secUtl.verify is secUtl.verifyHex
secUtl.verifyHex( signature, publicKey, content )
secUtl.verifyHex(StringHex, StringHex, String) -> Boolean

secUtl.verifyBytes( signature, publicKey, content )
secUtl.verifyHex( Uint8Array, Uint8Array, String) -> Boolean


## encryption - symmetric
# secUtl.symmetricEncrypt is secUtl.symmetricEncryptHex
secUtl.symmetricEncryptHex( content, symKey )
secUtl.symmetricEncryptHex( String, StringHex ) -> StringHex

secUtl.symmetricEncryptBytes( content, symKey )
secUtl.symmetricEncryptBytes( String, Uint8Array ) -> Uint8Array


# secUtl.symmetricDecrypt is secUtl.symmetricDecryptHex
secUtl.symmetricDecryptHex( encryptedContent, symKey )
secUtl.symmetricDecryptHex( StringHex, StringHex ) -> String

secUtl.symmetricDecryptBytes( encryptedContent, symKey )
secUtl.symmetricDecryptBytes( Uint8Array, Uint8Array ) -> String



## encryption - asymmetric
# secUtl.asymmetricEncrypt is secUtl.asymmetricEncryptHex
secUtl.asymmetricEncryptHex( content, publicKey )
secUtl.asymmetricEncryptHex( String, StringHex ) -> Object { referencePointHex, encryptetContentsHex }
secUtl.asymmetricEncryptHex( String, StringHex ) -> Object { StringHex, StringHex}

secUtl.asymmetricEncryptBytes( content, publicKey )
secUtl.asymmetricEncryptBytes( String, Uint8Array ) -> Object { referencePointBytes, encryptedContentsBytes }
secUtl.asymmetricEncryptBytes( String, Uint8Array ) -> Object { Uint8Array, Uint8Array }

# secUtl.asymmetricDecrypt is secUtl.asymmetricDecryptHex
secUtl.asymmetricDecryptHex( secretsObject, secretKey )
secUtl.asymmetricDecryptHex( Object { referencePointHex, encryptedContentsHex }, StringHex }, StringHex ) -> String
secUtl.asymmetricDecryptHex( Object { StringHex, StringHex }, StringHex }, StringHex ) -> String

secUtl.asymmetricDecryptBytes( secretsObject, secretKey )
secUtl.asymmetricDecryptBytes( Object { referencePointBytes, encryptedContentsBytes }, Uint8Array ) -> String
secUtl.asymmetricDecryptBytes( Object { Uint8Array, Uint8Array }, Uint8Array ) -> String


## shared secret - hashed
# secUtl.createSharedSecretHash is secUtl.createSharedSecretHashHex
secUtl.createSharedSecretHashHex( secretKeyHex, publicKeyHex, context )
secUtl.createSharedSecretHashHex( StringHex, StringHex, String ) -> StringHex

secUtl.createSharedSecretHashBytes( secretKeyBytes, publicKeyBytes, context )
secUtl.createSharedSecretHashBytes( Uint8Array, Uint8Array, String ) -> Uint8Array


## shared secret - raw
# secUtl.createSharedSecretHash is secUtl.createSharedSecretHashHex
secUtl.createSharedSecretRawHex( secretKeyHex, publicKeyHex)
secUtl.createSharedSecretRawHex( StringHex, StringHex ) -> StringHex

secUtl.createSharedSecretRawBytes( secretKeyBytes, publicKeyBytes)
secUtl.createSharedSecretRawBytes( Uint8Array, Uint8Array ) -> Uint8Array


## referenced secret - hashed
# secUtl.referencedSharedSecretHash is secUtl.referencedSharedSecretHashHex
secUtl.referencedSharedSecretHashHex( secretKeyHex, publicKeyHex, context )
secUtl.referencedSharedSecretHashHex( StringHex, StringHex, String ) -> Object { referencePointHex, sharedSecretHex}
secUtl.referencedSharedSecretHashHex( StringHex, StringHex, String ) -> Object { StringHex, StringHex}

secUtl.referencedSharedSecretHashBytes( secretKeyBytes, publicKeyBytes, context )
secUtl.referencedSharedSecretHashBytes( Uint8Array, Uint8Array, String ) -> Object { referencePointBytes, sharedSecretBytes }
secUtl.referencedSharedSecretHashBytes( Uint8Array, Uint8Array, String ) -> Object { Uint8Array, Uint8Array }

## referenced secret - raw
# secUtl.referencedSharedSecretRaw is secUtl.referencedSharedSecretRawHex
secUtl.referencedSharedSecretRawHex( secretKeyHex, publicKeyHex )
secUtl.referencedSharedSecretRawHex( StringHex, StringHex ) -> Object { referencePointHex, sharedSecretHex}
secUtl.referencedSharedSecretRawHex( StringHex, StringHex ) -> Object { StringHex, StringHex}

secUtl.referencedSharedSecretRawBytes( secretKeyBytes, publicKeyBytes)
secUtl.referencedSharedSecretRawBytes( Uint8Array, Uint8Array) -> Object { referencePointBytes, sharedSecretBytes }
secUtl.referencedSharedSecretRawBytes( Uint8Array, Uint8Array) -> Object { Uint8Array, Uint8Array }



## salts
secUtl.createRandomLengthSalt() -> String
secUtl.removeSalt( String ) -> String

```

## Breaking Updates
`0.0.x` -> `0.1.y`
------------------

### API Changes
The API has changed as spelling mistake has been corrected:
- symetric -> symmetric
- asymetric -> asymmetric

### Incompatibility
Also the asymmetric encryption algorithm has slightly changed, specifically how the shared secret is calculated. The result is that secrets being encrypted with the old version are not decryptable with the newer version and vice-versa.

For conversion purposes we have included the old style functions as well, which only exist in the hex version:
- asymmetricEncryptOld(content, publicKeyHex)
- asymmetricDecryptOld(secrets, secretKeyHex)

## Breaking Updates
`0.2.x` -> `0.3.y`
------------------
Since `v0.3.0` we have fixed some security concerns rooting from unauthenticated and unpadded use of AES-CBC.

This is the the salt function has changed significantly to wrap the plaintext into an padded and verifiable envelope of random numbers.

Also as a result of this we use this salt on our symmetricEncrypt function directly and don't leave it up to the developer to manually add the salt or not.

However for compatibility purposes with old Code we include the hex versions of the function as:
- symmetricEncryptUnsalted(content, keyHex)
- symmetricDecryptUnsalted(content, keyHex)

Also we keep the old salt functions as they were:
- createRandomLengthSalt()
- removeSalt(content)


## Hex FTW
It is adivsable  that you stare all encrypted contents, signatures and keys in hex strings. This appears to be the most superior way of how to universally transfer byte information.

The big wins of hex in readability and processability beats out the "downside" of being 2x the size. Also the performance loss is in most cases neglible ~ < 10%.


## Encryption
For the encryption functionality we use ed25519 keys for producing El-Gamal-style shared secret-keys which we then use for symmetrically encrypting the contents.

The result of this kind of encryption is always an Object like:
```json
{
    "referencePoint":"...",  // StringHex 
    "encryptedContents":"...",  // StringHex 
}
```

The symmetric encryption uses `aes-256-cbc`.

### Potential AES-CBC Weaknesses
There are some potential weaknesses in CBC Mode.
- Padding Oracle Attacks
- Bit Flipping
- IV Reuse

While for most cases GCM is recommended to use instead it seems less desirable for our use. Basically we just have to use CBC carefully.

One part of the solution is our new salt introduced on `v0.3.0`. It is a padded verifiable envelope of our plaintext consisting of random bytes. 
If any bit is flipped we should see that this envelope has become invalid.

Also generally we donot provide any oracle. Most of these potential attacks rely on an oracle. Because an attacker could try to flip muliple bits in an attempt to cover up the manipulation. If we provide an oracle which could quickly tell the attacker that the message was still valid or not then there is some surface of an attack. 

For our purpose what we encrypt are well-kept secrets with unique keys. Only to be accessed sporadically by the consumer having a valid signature. The Service guarantees uncorrupted storage of these secrets - usually signing the stored data which makes it tamper-proof at that level already. If the secret the consumer receives is corrupted this would immediatly break the trust to the service and any secrets from this server cannot be trusted anymore.

## Shared Secrets
Imagine Alice has the keyPair `privA, pubA` and Bob `privB, pubB`

The Shared Secrets work in this way:
```coffee
aliceSharedSecret = await secUtl.createSharedSecretRaw(privA, pubB) # 32 bytes HexString
bobSharedSecret = await secUtl.createSharedSecretRaw(privB, pubA)
(aliceSharedSecret == bobSharedSecret) # true

```

With the hashed version you may add an arbitrary context. This allows you to generate different sharedSecrets from the same key-pairs.
```coffee
context = "onetime-context@"+Date.now()
aliceSharedSecret = await secUtl.createSharedSecretHash(privA, pubB, context) # 64 bytes HexString
bobSharedSecret = await secUtl.createSharedSecretHash(privB, pubA, context)
(aliceSharedSecret == bobSharedSecret) # true

``` 

## Referenced Secrets
For the referenced shared secret there will be a random key generated to calculate the shared secret. The public Key of it then is also returned as "referencePointHex".

```coffee
referencedSecret = await secUtl.referencedSharedSecretRaw(pubB) # Object {referencePointHex, sharedSecretHex} 
referencePoint = referencedSecret.referencePointHex # 32 bytes Hex String
aliceSharedSecret = referencedSecret.sharedSecretHex  # 32 bytes Hex String
bobSharedSecret = await secUtl.createSharedSecretRaw(privB, referencePointHex)
(aliceSharedSecret == bobSharedSecret) # true

```

With the hashed version you may add an arbitrary context. This allows you to generate different sharedSecrets from the same key-pairs.
```coffee
context = "onetime-context@"+Date.now()
sharedSecret = await secUtl.createSharedSecretHash(privA, pubB, context) # 64 bytes HexString
sameSharedSecret = await secUtl.createSharedSecretHash(privB, pubA, context)
(sharedSecret == sameSharedSecret) # true

``` 

## Noble ed25519
All of this is straight forward based on [noble-ed25519](https://github.com/paulmillr/noble-ed25519). A very concise and modern package for freely using the ed25519 algorithms. Big thanks for that!

## Old Salts
- The salt functionality is to create a random string of random length terminated by `\0`
- The random length is limited to be at max 511bytes
- The `removeSalt` would cut off all bytes until it reaches `\0`
- Using AES-256-CBC in combination with this random length salt prefix effectivly eliminates the known plaintext attack surface and reduces dangers of [bit-flipping](https://crypto.stackexchange.com/questions/66085/bit-flipping-attack-on-cbc-mode)

## New Salts
Similar to the old Salt we add a randomness in length in form of a random prefix to obsucate where potentially known plaintext could really be.

Newly we also add a padding, so we have no "virtually predictable" ending. 
Plus this padding verifies if the random prefix we added is still intact.

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


---

All sorts of inputs are welcome, thanks!

---


# License
[Unlicense JhonnyJason style](https://hackmd.io/nCpLO3gxRlSmKVG3Zxy2hA?view)