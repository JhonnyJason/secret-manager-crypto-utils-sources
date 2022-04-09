# secret-manager-crypto-utils 

## Background
For the specific usecases in the edeavor to get a reasonable [Secret Management](https://hackmd.io/PZjpRfzPSBCqS-8K54x2jA) we do not need too many features such that it made sense to specifically craft this small convenience library for the small required functionality.

This is:

- sha256
- sha512
- Sign/Verify via Ed25519
- Asymmetric Encrypt/Decrypt in ElGamal style using Curve25519
- Symmetric Encrypt/Decrypt with AES-256-CBC
- Random length salts to mitigate Known Plaintext Attacks

This is directly used from other parts of the [Secret Management](https://hackmd.io/PZjpRfzPSBCqS-8K54x2jA?view) system.

## Usage
Current Functionality
---------------------

```coffeescript
import *  as secUtl from "secret-manager-crypto-utils"

## shas
secUtl.sha256 = secUtl.sha256Hex 
secUtl.sha256Hex( String ) -> StringHex

secUtl.sha256Bytes( String ) -> ArrayBuffer | Buffer


secUtl.sha512 = secUtl.sha512Hex
secUtl.sha512Hex( String ) -> StringHex

secUtl.sha512Bytes( String ) -> ArrayBuffer | Buffer


## keys
secUtl.createKeyPair = secUtl.createKeyPairHex
secUtl.createKeyPairHex() -> Object { privateKeyHex, publicKeyHex }
secUtl.createKeyPairHex() -> Object { StringHex, StringHex }

secUtl.createKeyPairBytes() -> Object { privateKeyBytes, publicKeyBytes }
secUtl.createKeyPairBytes() -> Object { Uint8Array, Uint8Array }


secUtl.createSymKey = secUtl.createSymKeyHex
secUtl.createSymKeyHex() -> StringHex 

secUtl.createSymKeyBytes() -> Uint8Array


## signatures
secUtl.createSignature = secUtl.createSignatureHex
secUtl.createSignatureHex( content, privateKey )
secUtl.createSignatureHex( String, StringHex ) -> StringHex

secUtl.createSignatureBytes( content, privateKey )
secUtl.createSignatureHex( String, Uint8Array ) -> Uint8Array


secUtl.verify = secUtl.verifyHex
secUtl.verifyHex( signature, publicKey, content )
secUtl.verifyHex(StringHex, StringHex, String) -> Boolean

secUtl.verifyBytes( signature, publicKey, content )
secUtl.verifyHex( Uint8Array, Uint8Array, String) -> Boolean


## encryption - symmetric
secUtl.symmetricEncrypt = secUtl.symmetricEncryptHex
secUtl.symmetricEncryptHex( content, symKey )
secUtl.symmetricEncryptHex( String, StringHex ) -> StringHex

secUtl.symmetricEncryptBytes( content, symKey )
secUtl.symmetricEncryptBytes( String, Uint8Array ) -> Uint8Array


secUtl.symmetricDecrypt = secUtl.symmetricDecryptHex
secUtl.symmetricDecryptHex( encryptedContent, symKey )
secUtl.symmetricDecryptHex( StringHex, StringHex ) -> String

secUtl.symmetricDecryptBytes( encryptedContent, symKey )
secUtl.symmetricDecryptBytes( Uint8Array, Uint8Array ) -> String


## encryption - asymmetric
secUtl.asymmetricEncrypt = secUtl.asymmetricEncryptHex
secUtl.asymmetricEncryptHex( content, publicKey )
secUtl.asymmetricEncryptHex( String, StringHex ) -> Object { referencePointHex, encryptetContentsHex }
secUtl.asymmetricEncryptHex( String, StringHex ) -> Object { StringHex, StringHex}

secUtl.asymmetricEncryptBytes( content, publicKey )
secUtl.asymmetricEncryptBytes( String, Uint8Array ) -> Object { referencePointBytes, encryptedContentsBytes }
secUtl.asymmetricEncryptBytes( String, Uint8Array ) -> Object { Uint8Array, Uint8Array }


secUtl.asymmetricDecrypt = secUtl.asymmetricDecryptHex
secUtl.asymmetricDecryptHex( secretsObject, privateKey )
secUtl.asymmetricDecryptHex( Object { referencePointHex, encryptedContentsHex }, StringHex }, StringHex ) -> String
secUtl.asymmetricDecryptHex( Object { StringHex, StringHex }, StringHex }, StringHex ) -> String

secUtl.asymmetricDecryptBytes( secretsObject, privateKey )
secUtl.asymmetricDecryptBytes( Object { referencePointBytes, encryptedContentsBytes }, StringHex ) -> String
secUtl.asymmetricDecryptBytes( Object { Uint8Array, Uint8Array }, StringHex ) -> String

## salts
secUtl.createRandomLengthSalt() -> String
secUtl.removeSalt( String ) -> String

```

## Breaking Updates
From `0.0.x` -> `0.1.0`

### API Changes
The API has changed as spelling mistake has been corrected:
- symetric -> symmetric
- asymetric -> asymmetric

### Incompatibility
Also the asymmetric encryption algorithm has slightly changed, specifically just how the shared secret is calculated. The result is that secrets being encrypted with the old version are not decryptable with the newer version and vice-versa.

To combat this we have included the old style functions as well, which only exist in the hex version:
- asymmetricEncryptOld(content, publicKeyHex)
- asymmetricDecryptOld(secrets, privateKeyHex)


## Hex FTW
For good reasons all encrypted contents, signatures and keys are stored in hex strings. This appears to be the most superior way of how to universally transfer byte information.

The big wins of hex in readability and processability beats out the "downside" of being 2x the size.

## Performance is more important?
We also have the versions using bytes, buffers, and specifically Uint8Arrays. To skip all the conversions back and forth. Use the Uint8Arrays in your code and use the byte-versions then.

We have for each function the `functionHex` version and the `functionBytes` version.
Because of reasons we assigned the standard `function` without the postfix to be the hex version.

*The reason is simply: The person who wants to skip the explicit version is more likely the be the one who needs the enhancanced readability later. ;-)*


## Encryption
For the encryption functionality we use ed25519 keys for producing El-Gamal-style shared secret keys which we then use for symmetrically encrypting the contents.

The result of this kind of encryption is always an Object like:
```json
{
    "referencePoint":"...",  // StringHex 
    "encryptedContents":"...",  // StringHex 
}
```

The symmetric encryption uses `aes-256-cbc`.

*Notice: it is your responsibility to salt your contents to be encrypted.*

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

## The Unlicense JhonnyJason style

- Information has no ownership.
- Information only has memory to reside in and relations to be meaningful.
- Information cannot be stolen. Only shared or destroyed.

And you wish it has been shared before it is destroyed.

The one claiming copyright or intellectual property either is really evil or probably has some insecurity issues which makes him blind to the fact that he also just connected information which was freely available to him.

The value is not in him who "created" the information the value is what is being done with the information.
So the restriction and friction of the informations' usage is exclusively reducing value overall.

The only preceived "value" gained due to restriction is actually very similar to the concept of blackmail (power gradient, control and dependency).

The real problems to solve are all in the "reward/credit" system and not the information distribution. Too much value is wasted because of not solving the right problem.

I can only contribute in that way - none of the information is "mine" everything I "learned" I actually also copied.
I only connect things to have something I feel is missing and share what I consider useful. So please use it without any second thought and please also share whatever could be useful for others. 

I also could give credits to all my sources - instead I use the freedom and moment of creativity which lives therein to declare my opinion on the situation. 

*Unity through Intelligence.*

We cannot subordinate us to the suboptimal dynamic we are spawned in, just because power is actually driving all things around us.
In the end a distributed network of intelligence where all information is transparently shared in the way that everyone has direct access to what he needs right now is more powerful than any brute power lever.

The same for our programs as for us.

It also is peaceful, helpful, friendly - decent. How it should be, because it's the most optimal solution for us human beings to learn, to connect to develop and evolve - not being excluded, let hanging and destroy oneself or others.

If we really manage to build an real AI which is far superior to us it will unify with this network of intelligence.
We never have to fear superior intelligence, because it's just the better engine connecting information to be most understandable/usable for the other part of the intelligence network.

The only thing to fear is a disconnected unit without a sufficient network of intelligence on its own, filled with fear, hate or hunger while being very powerful. That unit needs to learn and connect to develop and evolve then.

We can always just give information and hints :-) The unit needs to learn by and connect itself.

Have a nice day! :D