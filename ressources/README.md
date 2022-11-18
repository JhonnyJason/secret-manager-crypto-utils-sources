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

```coffeescript
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


## Hex FTW
It is adivsable  that you stare all encrypted contents, signatures and keys in hex strings. This appears to be the most superior way of how to universally transfer byte information.

The big wins of hex in readability and processability beats out the "downside" of being 2x the size. Also the performance loss is in most cases neglible ~ < 10%.

## Performance is more important?
We also have the versions using bytes, buffers, and specifically Uint8Arrays. To skip all the conversions back and forth. Use the Uint8Arrays in your code and use the byte-versions then.

We have for each function the `functionHex` version and the `functionBytes` version.
Because of reasons we assigned the standard `function` without the postfix to be the hex version.

*The reason is simply: The person who wants to skip the explicit version is more likely the be the one who needs the enhancanced readability later. ;-)*

>> Not just is the difference between byte version and hex version not signification, also sometimes the byte version is even slower. Probably in later versions we will optimize and maybe even deprecate the bytes versions if there is not significant benefit to them.

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

*Notice: it is your responsibility to salt your contents to be encrypted.*

## Shared Secrets
Image Alice has the keyPair `privA, pubA` and Bob `privB, pubB`

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
For the referenced shared secret there will be a random key generated to calculate the shared secret. The public Key then is also returned as "referencePointHex".

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

---

All sorts of inputs are welcome, thanks!

---

## Salts
- The salt functionality is to create a random string of random length terminated by a `0` byte
- The random length is limited to be at max 511bytes
- The `removeSalt` would cut off all bytes until it reaches the first `0` byte
- Using AES-256-CBC in combination with this random length salt prefix effectivly eliminates the known plaintext attack surface.

# License
[Unlicense JhonnyJason style](https://hackmd.io/nCpLO3gxRlSmKVG3Zxy2hA?view)