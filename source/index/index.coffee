############################################################
import *  as noble from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"
import crypto from "crypto"

############################################################
algorithm = 'aes-256-cbc'

ORDER = BigInt(2) ** BigInt(252) + BigInt('27742317777372353535851937790883648493')

############################################################
hashToScalar = (hash) ->
    relevant = hash.slice(0, 32)
    relevant[0] &= 248
    relevant[31] &= 127
    relevant[31] |= 64
    bigInt = tbut.bytesToBigInt(relevant)
    return mod(bigInt)

mod = (a, b = ORDER) ->
  result = a % b;
  if result >= 0n then return result
  else return result + b


############################################################
#region exposedStuff

############################################################
#region shas

############################################################
# Hex Version
export sha256 = (content) -> tbut.bytesToHex(sha256Bytes(content))

export sha512 = (content) -> tbut.bytesToHex(sha512Bytes(content))

export sha256Hex = sha256
export sha512Hex = sha512

############################################################
# Bytes Version
export sha256Bytes = (content) ->
    hasher = crypto.createHash("sha256")
    hasher.update(content)
    return hasher.digest()

export sha512Bytes = (content) ->
    hasher = crypto.createHash("sha512")
    hasher.update(content)
    return hasher.digest()

#endregion

############################################################
#region keys

############################################################
# Hex Version
export createKeyPair =  ->
    secretKeyBytes = noble.utils.randomPrivateKey()
    publicKeyBytes = await noble.getPublicKey(secretKeyBytes)
    secretKeyHex = tbut.bytesToHex(secretKeyBytes)
    publicKeyHex = tbut.bytesToHex(publicKeyBytes)
    return {secretKeyHex, publicKeyHex}

export createSymKey = ->
    keyAndIV = crypto.randomBytes(48)
    return tbut.bytesToHex(keyAndIV)

export createPublicKey = (secretKeyHex) ->
    publicKeyBytes = await noble.getPublicKey(secretKeyHex)
    return tbut.bytesToHex(publicKeyBytes)

export createKeyPairHex = createKeyPair
export createSymKeyHex = createSymKey
export createPublicKeyHex = createPublicKey

############################################################
# Byte Version
export createKeyPairBytes =  ->
    secretKeyBytes = noble.utils.randomPrivateKey()
    publicKeyBytes = await noble.getPublicKey(secretKeyBytes)
    return {secretKeyBytes, publicKeyBytes}

export createSymKeyBytes = -> new Uint8Array((crypto.randomBytes(48)).buffer)

export createPublicKeyBytes = (secretKeyBytes) -> await noble.getPublicKey(secretKeyBytes)

#endregion

############################################################
#region signatures

############################################################
# Hex Version
export createSignature = (content, signingKeyHex) ->
    hashHex = sha256Hex(content)
    signature = await noble.sign(hashHex, signingKeyHex)
    return tbut.bytesToHex(signature)

export verify = (sigHex, keyHex, content) ->
    hashHex = sha256Hex(content)
    return await noble.verify(sigHex, hashHex, keyHex)

export createSignatureHex = createSignature
export verifyHex = verify 
############################################################
# Byte Version
export createSignatureBytes = (content, signingKeyBytes) ->
    hashBytes = sha256Bytes(content)
    return await noble.sign(hashBytes, signingKeyBytes)

export verifyBytes = (sigBytes, keyBytes, content) ->
    hashBytes = sha256Bytes(content)
    return await noble.verify(sigBytes, hashBytes, keyBytes)

#endregion

############################################################
#region symmetric encryption

############################################################
# Hex Version
export symmetricEncrypt = (content, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    ivBuffer = Buffer.from(ivHex, "hex")
    aesKeyHex = keyHex.substring(32,96)
    aesKeyBuffer = Buffer.from(aesKeyHex, "hex")
    # console.log "- - ivHex: "
    # console.log ivHex
    # console.log ivHex.length
    # console.log "- - aesKeyHex: "
    # console.log aesKeyHex
    # console.log aesKeyHex.length

    cipher = crypto.createCipheriv(algorithm, aesKeyBuffer, ivBuffer)
    gibbrish = cipher.update(content, 'utf8', 'hex')
    gibbrish += cipher.final('hex')
    return gibbrish

export symmetricDecrypt = (gibbrishHex, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    ivBuffer = Buffer.from(ivHex, "hex")
    aesKeyHex = keyHex.substring(32,96)
    aesKeyBuffer = Buffer.from(aesKeyHex, "hex")
    # console.log "- - ivHex: "
    # console.log ivHex
    # console.log ivHex.length
    # console.log "- - aesKeyHex: "
    # console.log aesKeyHex
    # console.log aesKeyHex.length

    decipher = crypto.createDecipheriv(algorithm, aesKeyBuffer, ivBuffer)
    content = decipher.update(gibbrishHex, 'hex', 'utf8')
    content += decipher.final('utf8')
    return content

export symmetricEncryptHex = symmetricEncrypt
export symmetricDecryptHex = symmetricDecrypt
############################################################
# Byte Version
export symmetricEncryptBytes = (content, keyBytes) ->
    ivBuffer = Buffer.from(keyBytes.buffer, 0, 16)
    aesKeyBuffer = Buffer.from(keyBytes.buffer, 16, 32)
    
    cipher = crypto.createCipheriv(algorithm, aesKeyBuffer, ivBuffer)
    gibbrish = cipher.update(content, 'utf8')
    gibbrishFinal = cipher.final()
    allGibbrish = Buffer.concat([gibbrish,gibbrishFinal])
    return new Uint8Array(allGibbrish)

export symmetricDecryptBytes = (gibbrishBytes, keyBytes) ->
    ivBuffer = Buffer.from(keyBytes.buffer, 0, 16)
    aesKeyBuffer = Buffer.from(keyBytes.buffer, 16, 32)
    # gibbrishBuffer = Buffer.from(gibbrishBytes)
    
    decipher = crypto.createDecipheriv(algorithm, aesKeyBuffer, ivBuffer)
    content = decipher.update(gibbrishBytes, null, 'utf8')
    # content = decipher.update(gibbrishBuffer, null, 'utf8')
    content += decipher.final('utf8')
    return content

#endregion

############################################################
#region asymmetric encryption

############################################################
# Hex Version
export asymmetricEncryptOld = (content, publicKeyHex) ->
    # a = Secret Key
    # k = sha512(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key
    
    B = noble.Point.fromHex(publicKeyHex)
    BHex = publicKeyHex
    # console.log "BHex: " + BHex

    # n = new one-time secret (generated on sever and forgotten about)
    # l = sha512(n) -> hashToScalar
    # lB = lkG = shared secret
    # key = sha512(lBHex)
    # X = symmetricEncrypt(content, key)
    # A = lG = one time public reference point
    # {A,X} = data to be stored for B

    # n = one-time secret
    nBytes = noble.utils.randomPrivateKey()
    nHex = tbut.bytesToHex(nBytes)

    lBigInt = hashToScalar(sha512Bytes(nBytes))
    
    #A one time public key = reference Point
    ABytes = await noble.getPublicKey(nHex)
    lB = await B.multiply(lBigInt)
    
    symkey = sha512Hex(lB.toHex())
    
    gibbrish = symmetricEncryptHex(content, symkey)
    
    referencePointHex = tbut.bytesToHex(ABytes)
    encryptedContentHex = gibbrish

    return {referencePointHex, encryptedContentHex}

export asymmetricDecryptOld = (secrets, secretKeyHex) ->
    AHex = secrets.referencePointHex || secrets.referencePoint
    gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if !AHex? or !gibbrishHex? then throw new Error("Invalid secrets Object!")
    # a = Secret Key
    # k = sha512(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key
    aBytes = tbut.hexToBytes(secretKeyHex)
    kBigInt = hashToScalar(sha512Bytes(aBytes))
    
    # {A,X} = secrets
    # A = lG = one time public reference point 
    # klG = lB = kA = shared secret
    # key = sha512(kAHex)
    # content = symmetricDecrypt(X, key)
    A = noble.Point.fromHex(AHex)
    kA = await A.multiply(kBigInt)
    
    symkey = sha512Hex(kA.toHex())

    content = symmetricDecryptHex(gibbrishHex,symkey)
    return content

export asymmetricEncrypt = (content, publicKeyHex) ->
    nBytes = noble.utils.randomPrivateKey()
    A = await noble.getPublicKey(nBytes)
    lB = await noble.getSharedSecret(nBytes, publicKeyHex)

    symkey = sha512Bytes(lB)
    # symkey = sha512Bytes(tbut.bytesToHex(lB))
    
    gibbrish = symmetricEncryptBytes(content, symkey)    
    
    referencePointHex = tbut.bytesToHex(A)
    encryptedContentHex = tbut.bytesToHex(gibbrish)

    return {referencePointHex, encryptedContentHex}

export asymmetricDecrypt = (secrets, secretKeyHex) ->
    AHex = secrets.referencePointHex || secrets.referencePoint
    gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if !AHex? or !gibbrishHex? then throw new Error("Invalid secrets Object!")

    kA = await noble.getSharedSecret(secretKeyHex, AHex)
    symkey = sha512Bytes(kA)
    # symkey = sha512Bytes(tbut.bytesToHex(kA))

    gibbrishBytes = tbut.hexToBytes(gibbrishHex)
    content = symmetricDecryptBytes(gibbrishBytes, symkey)
    return content

export asymmetricEncryptHex = asymmetricEncrypt
export asymmetricDecryptHex = asymmetricDecrypt
############################################################
# Byte Version
export asymmetricEncryptBytes = (content, publicKeyBytes) ->
    nBytes = noble.utils.randomPrivateKey()
    ABytes = await noble.getPublicKey(nBytes)
    lB = await noble.getSharedSecret(nBytes, publicKeyBytes)

    symkeyBytes = sha512Bytes(lB)
    gibbrishBytes = symmetricEncryptBytes(content, symkeyBytes)    
    
    referencePointBytes = ABytes
    encryptedContentBytes = gibbrishBytes

    return {referencePointBytes, encryptedContentBytes}

export asymmetricDecryptBytes = (secrets, secretKeyBytes) ->
    ABytes = secrets.referencePointBytes || secrets.referencePoint
    gibbrishBytes = secrets.encryptedContentBytes || secrets.encryptedContent
    if !ABytes? or !gibbrishBytes? then throw new Error("Invalid secrets Object!")

    kABytes = await noble.getSharedSecret(secretKeyBytes, ABytes)
    symkeyBytes = sha512Bytes(kABytes)

    content = symmetricDecryptBytes(gibbrishBytes, symkeyBytes)
    return content

#endregion

############################################################
#region referenced shared secrets

############################################################
# create shared secrets
export createSharedSecretContexedHash512 = (secretKeyHex, publicKeyHex, contextString = "") ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = tbut.hexToBytes(secretKeyHex)
    BBytes = tbut.hexToBytes(publicKeyHex)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    cBytes = tbut.utf8ToBytes(contextString)
    seedBytes = Buffer.concat([nBBytes, cBytes])

    sharedSecretBytes = sha512Bytes(seedBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    return sharedSecretHex

export createSharedSecretHash512 = (secretKeyHex, publicKeyHex) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = tbut.hexToBytes(secretKeyHex)
    BBytes = tbut.hexToBytes(publicKeyHex)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    sharedSecretBytes = sha512Bytes(nBBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    return sharedSecretHex

############################################################
export createSharedSecretContexedHash256 = (secretKeyHex, publicKeyHex, contextString = "") ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = tbut.hexToBytes(secretKeyHex)
    BBytes = tbut.hexToBytes(publicKeyHex)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    cBytes = tbut.utf8ToBytes(contextString)
    seedBytes = Buffer.concat([nBBytes, cBytes])

    sharedSecretBytes = sha256Bytes(seedBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    return sharedSecretHex

export createSharedSecretHash256 = (secretKeyHex, publicKeyHex) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = tbut.hexToBytes(secretKeyHex)
    BBytes = tbut.hexToBytes(publicKeyHex)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    sharedSecretBytes = sha256Bytes(nBBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    return sharedSecretHex

############################################################
export createSharedSecretRaw = (secretKeyHex, publicKeyHex) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = tbut.hexToBytes(secretKeyHex)
    BBytes = tbut.hexToBytes(publicKeyHex)
    
    sharedSecretBytes = await noble.getSharedSecret(nBytes, BBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    return sharedSecretHex

############################################################
# create shared secrets with reference point
export referencedSharedSecretContexedHash512 = (publicKeyHex, contextString = "") ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = noble.utils.randomPrivateKey()
    
    BBytes = tbut.hexToBytes(publicKeyHex)
    ABytes = await noble.getPublicKey(nBytes)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    cBytes = tbut.utf8ToBytes(contextString)
    seedBytes = Buffer.concat([nBBytes, cBytes])

    sharedSecretBytes = sha512Bytes(seedBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

export referencedSharedSecretHash512 = (publicKeyHex) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = noble.utils.randomPrivateKey()
    
    BBytes = tbut.hexToBytes(publicKeyHex)
    ABytes = await noble.getPublicKey(nBytes)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    sharedSecretBytes = sha512Bytes(nBBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

############################################################
export referencedSharedSecretContexedHash256 = (publicKeyHex, contextString = "") ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = noble.utils.randomPrivateKey()
    
    BBytes = tbut.hexToBytes(publicKeyHex)
    ABytes = await noble.getPublicKey(nBytes)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    cBytes = tbut.utf8ToBytes(contextString)
    seedBytes = Buffer.concat([nBBytes, cBytes])

    sharedSecretBytes = sha256Bytes(seedBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

export referencedSharedSecretHash256 = (publicKeyHex) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = noble.utils.randomPrivateKey()
    
    BBytes = tbut.hexToBytes(publicKeyHex)
    ABytes = await noble.getPublicKey(nBytes)
    
    nBBytes = await noble.getSharedSecret(nBytes, BBytes)

    sharedSecretBytes = sha256Bytes(nBBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

############################################################
export referencedSharedSecretRaw = (publicKeyHex) ->
    # n = SecretKey
    # A = referencePoint = nG
    # B = publicKey = lG
    # nB = shared Secret = nlG
    nBytes = noble.utils.randomPrivateKey()
    
    BBytes = tbut.hexToBytes(publicKeyHex)
    ABytes = await noble.getPublicKey(nBytes)
    
    sharedSecretBytes = await noble.getSharedSecret(nBytes, BBytes)

    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

#endregion

############################################################
#region salts
export createRandomLengthSalt = ->
    loop
        bytes = crypto.randomBytes(512)
        for byte,i in bytes when byte == 0
            return bytes.slice(0,i+1).toString("utf8")        

export removeSalt = (content) ->
    for char,i in content when char == "\0"
        return content.slice(i+1)
    throw new Error("No Salt termination found!")    

#endregion

#endregion