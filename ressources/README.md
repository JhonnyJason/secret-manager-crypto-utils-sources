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
secUtl.sha256Hex( String ) -> String
secUtl.sha512Hex( String ) -> String

secUtl.sha256Bytes( String ) -> ArrayBuffer | Buffer
secUtl.sha512Bytes( String ) -> ArrayBuffer | Buffer

## keys
secUtl.getNewKeyPair() -> Object { privateKeyHex, publicKeyHex }
secUtl.getNewKeyPair() -> Object { StringHex, StringHex }

## signatures
secUtl.createSignature( content, privateKey )
secUtl.createSignature( String, StringHex ) -> StringHex

secUtl.verify( signature, publicKey, content )
secUtl.verify(StringHex, StringHex, String) -> Boolean

## encryption - asymetric
secUtl.asymetricEncrypt( content, publicKey )
secUtl.asymetricEncrypt( String, StringHex ) -> Object

secUtl.asymetricDecrypt( secretsObject, privateKey )
secUtl.asymetricDecrypt( Object, StringHex ) -> String

## encryption - symetric
secUtl.symetricEncryptHex( content, sharedKey )
secUtl.symetricEncryptHex( String, StringHex ) -> StringHex

secUtl.symetricDecrypttHex( encryptedContent, sharedKey )
secUtl.symetricDecrypttHex( StringHex, StringHex ) -> String

## salts
secUtl.createRandomLengthSalt() -> String
secUtl.removeSalt( String ) -> String

```

## Hex FTW
For good reasons all encrypted contents, signatures and keys are stored in hex strings. This appears to be the most superior way of how to universally transfer byte information.

The big wins of hex in readability and processability beats out the "downside" of being 2x the size.

## Salts
- The salt functionality is to create a random string of random length terminated by a `0` byte
- The random length is limited to be at max 511bytes
- The `removeSalt` would cut off all bytes until it reaches the first `0` byte

## Encryption
For the encryption functionality we use ed25519 keys for producing El-Gamal-style shared secret keys which we then use for symetrically encrypting the contents.

The result of this kind of encryption is always an Object like:
```json
{
    "referencePoint":"...",  // StringHex 
    "encryptedContents":"...",  // StringHex 
}
```

The symetric encryption uses `aes-256-cbc`.

## Noble ed25519
All of this is straight forward based on [noble-ed25519](https://github.com/paulmillr/noble-ed25519). A very concise and modern package for freely using the ed25519 algorithms. Big thanks for that!

---

All sorts of inputs are welcome, thanks!

---

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