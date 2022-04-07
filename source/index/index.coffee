cryptoutilsnode = {}

############################################################
import *  as noble from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"
import crypto from "crypto"

############################################################
#region internalProperties
algorithm = 'aes-256-cbc'
#endregion

############################################################
#region internalFunctions
hashToScalar = (hash) ->
    relevant = hash.slice(0, 32)
    relevant[0] &= 248
    relevant[31] &= 127
    relevant[31] |= 64
    return tbut.bytesToBigInt(relevant)

sha256 = (content) ->
    hasher = crypto.createHash("sha256")
    hasher.update(content)
    return hasher.digest()

sha512 = (content) ->
    hasher = crypto.createHash("sha512")
    hasher.update(content)
    return hasher.digest()

#endregion

############################################################
#region exposedStuff

############################################################
#region shas
export sha256Hex = (content) -> tbut.bytesToHex(sha256(content))

export sha512Hex = (content) -> tbut.bytesToHex(sha512(content))

############################################################
export sha256Bytes = sha256

export sha512Bytes = sha512

#endregion

############################################################
#region keys
export getNewKeyPair =  -> 
    secretKey = noble.utils.randomPrivateKey()
    publicKey = await noble.getPublicKey(secretKey)
    secretKeyHex = tbut.bytesToHex(secretKey)
    publicKeyHex = tbut.bytesToHex(publicKey)
    return {secretKeyHex, publicKeyHex}

#endregion

############################################################
#region signatures
export createSignature = (content, signingKeyHex) ->
    hashHex = @sha256Hex(content)
    signature = await noble.sign(hashHex, signingKeyHex)
    return tbut.bytesToHex(signature)

export verify = (sigHex, keyHex, content) ->
    hashHex = @sha256Hex(content)
    return await noble.verify(sigHex, hashHex, keyHex)

#endregion


############################################################
#region encryption
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

    lBigInt = hashToScalar(sha512(nBytes))
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
    kBigInt = hashToScalar(sha512(aBytes))
    
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

############################################################
export symetricEncryptHex = (content, keyHex) ->
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

export symetricDecryptHex = (gibbrishHex, keyHex) ->
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