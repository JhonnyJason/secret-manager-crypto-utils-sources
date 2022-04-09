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
    secretKey = noble.utils.randomPrivateKey()
    publicKey = await noble.getPublicKey(secretKey)
    secretKeyHex = tbut.bytesToHex(secretKey)
    publicKeyHex = tbut.bytesToHex(publicKey)
    return {secretKeyHex, publicKeyHex}

export createSymKey = ->
    keyAndIV = crypto.randomBytes(48)
    return tbut.bytesToHex(keyAndIV)

export createKeyPairHex = createKeyPair
export createSymKeyHex = createSymKey

############################################################
# Byte Version
export createKeyPairBytes =  ->
    secretKeyBytes = noble.utils.randomPrivateKey()
    publicKeyBytes = await noble.getPublicKey(secretKeyBytes)
    return {secretKeyBytes, publicKeyBytes}

export createSymKeyBytes = -> new Uint8Array((crypto.randomBytes(48)).buffer)

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
    # log "- - ivHex: "
    # log ivHex
    # log ivHex.length
    # log "- - aesKeyHex: "
    # log aesKeyHex
    # log aesKeyHex.length

    cipher = crypto.createCipheriv(algorithm, aesKeyBuffer, ivBuffer)
    gibbrish = cipher.update(content, 'utf8', 'hex')
    gibbrish += cipher.final('hex')
    return gibbrish

export symmetricDecrypt = (gibbrishHex, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    ivBuffer = Buffer.from(ivHex, "hex")
    aesKeyHex = keyHex.substring(32,96)
    aesKeyBuffer = Buffer.from(aesKeyHex, "hex")
    # log "- - ivHex: "
    # log ivHex
    # log ivHex.length
    # log "- - aesKeyHex: "
    # log aesKeyHex
    # log aesKeyHex.length

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
    # a = Private Key
    # k = sha512(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key
    
    B = noble.Point.fromHex(publicKeyHex)
    BHex = publicKeyHex
    # log "BHex: " + BHex

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

export asymmetricDecryptOld = (secrets, privateKeyHex) ->
    AHex = secrets.referencePointHex || secrets.referencePoint
    gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if !AHex? or !gibbrishHex? then throw new Error("Invalid secrets Object!")
    # a = Private Key
    # k = sha512(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key
    aBytes = tbut.hexToBytes(privateKeyHex)
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

export asymmetricDecrypt = (secrets, privateKeyHex) ->
    AHex = secrets.referencePointHex || secrets.referencePoint
    gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if !AHex? or !gibbrishHex? then throw new Error("Invalid secrets Object!")

    kA = await noble.getSharedSecret(privateKeyHex, AHex)
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

export asymmetricDecryptBytes = (secrets, privateKeyBytes) ->
    ABytes = secrets.referencePointBytes || secrets.referencePoint
    gibbrishBytes = secrets.encryptedContentBytes || secrets.encryptedContent
    if !ABytes? or !gibbrishBytes? then throw new Error("Invalid secrets Object!")

    kABytes = await noble.getSharedSecret(privateKeyBytes, ABytes)
    symkeyBytes = sha512Bytes(kABytes)

    content = symmetricDecryptBytes(gibbrishBytes, symkeyBytes)
    return content

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