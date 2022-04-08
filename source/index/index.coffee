############################################################
import *  as noble from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"
import crypto from "crypto"

############################################################
algorithm = 'aes-256-cbc'

############################################################
hashToScalar = (hash) ->
    relevant = hash.slice(0, 32)
    relevant[0] &= 248
    relevant[31] &= 127
    relevant[31] |= 64
    return tbut.bytesToBigInt(relevant)

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
#region symetric encryption

############################################################
# Hex Version
export symetricEncrypt = (content, keyHex) ->
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

export symetricDecrypt = (gibbrishHex, keyHex) ->
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

export symetricEncryptHex = symetricEncrypt
export symetricDecryptHex = symetricDecrypt
############################################################
# Byte Version
export symetricEncryptBytes = (content, keyBytes) ->
    ivBuffer = Buffer.from(keyBytes.buffer, 0, 16)
    aesKeyBuffer = Buffer.from(keyBytes.buffer, 16, 32)
    
    cipher = crypto.createCipheriv(algorithm, aesKeyBuffer, ivBuffer)
    gibbrish = cipher.update(content, 'utf8')
    gibbrishFinal = cipher.final()
    allGibbrish = Buffer.concat([gibbrish,gibbrishFinal])
    return new Uint8Array(allGibbrish)

export symetricDecryptBytes = (gibbrishBytes, keyBytes) ->
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
#region asymetric encryption

############################################################
# Hex Version
export asymetricEncrypt = (content, publicKeyHex) ->
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
    # X = symetricEncrypt(content, key)
    # A = lG = one time public reference point
    # {A,X} = data to be stored for B

    # n = one-time secret
    nBytes = noble.utils.randomPrivateKey()
    nHex = tbut.bytesToHex(nBytes)

    lBigInt = hashToScalar(sha512Bytes(nBytes))
    # log lBigInt
    
    #A one time public key = reference Point
    AHex = await noble.getPublicKey(nHex)
    
    lB = await B.multiply(lBigInt)
    
    symkey = @sha512Hex(lB.toHex())
    
    gibbrish = @symetricEncryptHex(content, symkey)
    
    referencePoint = AHex
    encryptedContent = gibbrish

    return {referencePoint, encryptedContent}

export asymetricDecrypt = (secrets, privateKeyHex) ->
    if !secrets.referencePoint? or !secrets.encryptedContent?
        throw new Error("unexpected secrets format!")
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
    # content = symetricDecrypt(X, key)
    AHex = secrets.referencePoint
    A = noble.Point.fromHex(AHex)
    kA = await A.multiply(kBigInt)
    
    symkey = @sha512Hex(kA.toHex())

    gibbrishHex = secrets.encryptedContent
    content = @symetricDecryptHex(gibbrishHex,symkey)
    return content

export asymetricEncryptHex = asymetricEncrypt
export asymetricDecryptHex = asymetricDecrypt
############################################################
# Byte Version
export asymetricEncryptBytes = (content, publicKeyBytes) ->
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
    # X = symetricEncrypt(content, key)
    # A = lG = one time public reference point
    # {A,X} = data to be stored for B

    # n = one-time secret
    nBytes = noble.utils.randomPrivateKey()
    nHex = tbut.bytesToHex(nBytes)

    lBigInt = hashToScalar(sha512Bytes(nBytes))
    # log lBigInt
    
    #A one time public key = reference Point
    AHex = await noble.getPublicKey(nHex)
    
    lB = await B.multiply(lBigInt)
    
    symkey = @sha512Hex(lB.toHex())
    
    gibbrish = @symetricEncryptHex(content, symkey)
    
    referencePoint = AHex
    encryptedContent = gibbrish

    return {referencePoint, encryptedContent}

export asymetricDecryptBytes = (secrets, privateKeyBytes) ->
    if !secrets.referencePoint? or !secrets.encryptedContent?
        throw new Error("unexpected secrets format!")
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
    # content = symetricDecrypt(X, key)
    AHex = secrets.referencePoint
    A = noble.Point.fromHex(AHex)
    kA = await A.multiply(kBigInt)
    
    symkey = @sha512Hex(kA.toHex())

    gibbrishHex = secrets.encryptedContent
    content = @symetricDecryptHex(gibbrishHex,symkey)
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