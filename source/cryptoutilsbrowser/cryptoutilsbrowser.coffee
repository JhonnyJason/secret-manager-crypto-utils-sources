cryptoutilsbrowser = {}

############################################################
noble = require("noble-ed25519")
tbut = require("thingy-byte-utils")

crypto = window.crypto.subtle

############################################################
#region internalFunctions

hashToScalar = (byteBuffer) ->
    relevant = new Uint8Array(byteBuffer.slice(0, 32))
    relevant[0] &= 248
    relevant[31] &= 127
    relevant[31] |= 64
    return tbut.bytesToBigInt(relevant.buffer)

createKeyObject = (keyHex) ->
    keyBuffer = tbut.hexToBytes(keyHex)
    return await crypto.importKey("raw", keyBuffer, {name:"AES-CBC"}, false, ["decrypt", "encrypt"])

#endregion

############################################################
#region exposedStuff

############################################################
#region shas
cryptoutilsbrowser.sha256Hex = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    hashBytes = await crypto.digest("SHA-256", contentBytes)
    return tbut.bytesToHex(hashBytes)

cryptoutilsbrowser.sha512Hex = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    hashBytes = await crypto.digest("SHA-512", contentBytes)
    return tbut.bytesToHex(hashBytes)

############################################################
cryptoutilsbrowser.sha256Bytes = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    return await crypto.digest("SHA-256", contentBytes)

cryptoutilsbrowser.sha512Bytes = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    return await crypto.digest("SHA-512", contentBytes)

#endregion

############################################################
#region salts
cryptoutilsbrowser.createRandomLengthSalt = ->
    bytes = new Uint8Array(512)
    loop
        window.crypto.getRandomValues(bytes)
        for byte,i in bytes when byte == 0
            return tbut.bufferToUtf8(bytes.slice(0,i+1))        

cryptoutilsbrowser.removeSalt = (content) ->
    for char,i in content when char == "\0"
        return content.slice(i+1)
    throw new Error("No Salt termination found!")    

#endregion

############################################################
#region encryption
cryptoutilsbrowser.asymetricEncrypt = (content, publicKeyHex) ->
    # a = Private Key
    # k = @sha512Bytes(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key
    B = noble.Point.fromHex(publicKeyHex)
    BHex = publicKeyHex
    # log "BHex: " + BHex

    # n = new one-time secret (generated on sever and forgotten about)
    # l = @sha512Bytes(n) -> hashToScalar
    # lB = lkG = shared secret
    # key = @sha512Bytes(lBHex)
    # X = symetricEncrypt(content, key)
    # A = lG = one time public reference point
    # {A,X} = data to be stored for B

    # n = one-time secret
    nBytes = noble.utils.randomPrivateKey()
    nHex = tbut.bytesToHex(nBytes)
    nHashed = await @sha512Bytes(nBytes)
    lBigInt = hashToScalar(nHashed)
    # log lBigInt
    
    #A one time public key = reference Point
    AHex = await noble.getPublicKey(nHex)
    
    lB = await B.multiply(lBigInt)
    
    ## TODO generate AES key
    symkeyHex = await @sha512Hex(lB.toHex())
    gibbrish = await @symetricEncryptHex(content, symkeyHex)
    
    referencePoint = AHex
    encryptedContent = gibbrish

    return {referencePoint, encryptedContent}

cryptoutilsbrowser.asymetricDecrypt = (secrets, privateKeyHex) ->
    if !secrets.referencePoint? or !secrets.encryptedContent?
        throw new Error("unexpected secrets format!")
    # a = Private Key
    # k = @sha512Bytes(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key

    aBytes = tbut.hexToBytes(privateKeyHex)
    aHashed = await @sha512Bytes(aBytes)
    kBigInt = hashToScalar(aHashed)
    
    # {A,X} = secrets
    # A = lG = one time public reference point 
    # klG = lB = kA = shared secret
    # key = @sha512Bytes(kAHex)
    # content = symetricDecrypt(X, key)
    AHex = secrets.referencePoint
    A = noble.Point.fromHex(AHex)
    kA = await A.multiply(kBigInt)
    symkeyHex = await @sha512Hex(kA.toHex())

    gibbrishHex = secrets.encryptedContent
    content = await @symetricDecryptHex(gibbrishHex,symkeyHex)
    return content

############################################################
cryptoutilsbrowser.symetricEncryptHex = (content, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    aesKeyHex = keyHex.substring(32,96)

    ivBuffer = utl.hexToBytes(ivHex)
    contentBuffer = utl.utf8ToBuffer(content)

    key = await createKeyObject(aesKeyHex)
    algorithm = 
        name: "AES-CBC"
        iv: ivBuffer

    gibbrishBuffer = await crypto.encrypt(algorithm, key, contentBuffer)
    return tbut.bytesToHex(gibbrishBuffer)

cryptoutilsbrowser.symetricDecryptHex = (gibbrishHex, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    aesKeyHex = keyHex.substring(32,96)
    
    ivBuffer = tbut.hexToBytes(ivHex)
    gibbrishBuffer = tbut.hexToBytes(gibbrishHex)
    
    key = await createKeyObject(aesKeyHex)
    algorithm = 
        name: "AES-CBC"
        iv: ivBuffer

    contentBuffer = await crypto.decrypt(algorithm, key, gibbrishBuffer)
    return tbut.bufferToUtf8(contentBuffer)

#endregion

############################################################
#region signatures
cryptoutilsbrowser.createSignature = (content, signingKeyHex) ->
    hashHex = await @sha256Hex(content)
    return await noble.sign(hashHex, signingKeyHex)

cryptoutilsbrowser.verify = (sigHex, keyHex, content) ->
    hashHex = @sha256Hex(content)
    return await noble.verify(sigHex, hashHex, keyHex)

#endregion

#endregion

module.exports = cryptoutilsbrowser








