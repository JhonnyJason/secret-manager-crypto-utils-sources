############################################################
import * as noble from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"

crypto = window.crypto.subtle

ORDER = BigInt(2) ** BigInt(252) + BigInt('27742317777372353535851937790883648493')

############################################################
#region internalFunctions
hashToScalar = (byteBuffer) ->
    relevant = new Uint8Array(byteBuffer.slice(0, 32))
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
createKeyObject = (keyHex) ->
    keyBytes = tbut.hexToBytes(keyHex)
    return await crypto.importKey("raw", keyBytes, {name:"AES-CBC"}, false, ["decrypt", "encrypt"])

createKeyObjectHex = createKeyObject

createKeyObjectBytes = (keyBytes) ->
    return await crypto.importKey("raw", keyBytes, {name:"AES-CBC"}, false, ["decrypt", "encrypt"])

#endregion

############################################################
#region exposedStuff

############################################################
#region shas

############################################################
# Hex Version
export sha256 = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    hashBytes = await crypto.digest("SHA-256", contentBytes)
    return tbut.bytesToHex(hashBytes)

export sha512 = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    hashBytes = await crypto.digest("SHA-512", contentBytes)
    return tbut.bytesToHex(hashBytes)

export sha256Hex = sha256
export sha512Hex = sha512

############################################################
# Byte Version
export sha256Bytes = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    return await crypto.digest("SHA-256", contentBytes)

export sha512Bytes = (content) ->
    if (typeof content) == "string" then contentBytes = tbut.utf8ToBytes(content)
    else contentBytes = content
    return await crypto.digest("SHA-512", contentBytes)

#endregion

############################################################
#region keys

############################################################
# Hex Version
export createKeyPair = ->
    secretKey = noble.utils.randomPrivateKey()
    publicKey = await noble.getPublicKey(secretKey)
    secretKeyHex = tbut.bytesToHex(secretKey)
    publicKeyHex = tbut.bytesToHex(publicKey)
    return {secretKeyHex, publicKeyHex}

export createSymKey = ->
    keyAndIV = new Uint8Array(48)
    window.crypto.getRandomValues(keyAndIV)
    return tbut.bytesToHex(keyAndIV)

export createKeyPairHex = createKeyPair
export createSymKeyHex = createSymKey

############################################################
# Byte Version
export createKeyPairBytes = ->
    secretKeyBytes = noble.utils.randomPrivateKey()
    publicKeyBytes = await noble.getPublicKey(secretKeyBytes)
    return {secretKeyBytes, publicKeyBytes}

export createSymKeyBytes = -> 
    keyAndIV = new Uint8Array(48)
    window.crypto.getRandomValues(keyAndIV)
    return keyAndIV

#endregion

############################################################
#region signatures

############################################################
# Hex Version
export createSignature = (content, signingKeyHex) ->
    hashHex = await sha256Hex(content)
    signature = await noble.sign(hashHex, signingKeyHex)
    return tbut.bytesToHex(signature)

export verify = (sigHex, keyHex, content) ->
    hashHex = await sha256Hex(content)
    return await noble.verify(sigHex, hashHex, keyHex)

export createSignatureHex = createSignature
export verifyHex = verify

############################################################
# Byte Version
export createSignatureBytes = (content, signingKeyBytes) ->
    hashBytes = await sha256Bytes(content)
    return await noble.sign(hashBytes, signingKeyBytes)

export verifyBytes = (sigBytes, keyBytes, content) ->
    hashBytes = await sha256Bytes(content)
    return await noble.verify(sigBytes, hashBytes, keyBytes)
#endregion

############################################################
#region symmetric encryption

############################################################
# Hex Version
export symmetricEncrypt = (content, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    aesKeyHex = keyHex.substring(32,96)

    ivBuffer = tbut.hexToBytes(ivHex)
    contentBuffer = tbut.utf8ToBytes(content)

    keyObjHex = await createKeyObjectHex(aesKeyHex)
    algorithm = 
        name: "AES-CBC"
        iv: ivBuffer

    gibbrishBuffer = await crypto.encrypt(algorithm, keyObjHex, contentBuffer)
    return tbut.bytesToHex(gibbrishBuffer)

export symmetricDecrypt = (gibbrishHex, keyHex) ->
    ivHex = keyHex.substring(0, 32)
    aesKeyHex = keyHex.substring(32,96)
    
    ivBuffer = tbut.hexToBytes(ivHex)
    gibbrishBuffer = tbut.hexToBytes(gibbrishHex)
    
    keyObjHex = await createKeyObjectHex(aesKeyHex)
    algorithm = 
        name: "AES-CBC"
        iv: ivBuffer

    contentBuffer = await crypto.decrypt(algorithm, keyObjHex, gibbrishBuffer)
    return tbut.bytesToUtf8(contentBuffer)

export symmetricEncryptHex = symmetricEncrypt
export symmetricDecryptHex = symmetricDecrypt
############################################################
# Byte Version
export symmetricEncryptBytes = (content, keyBytes) ->
    # ivHex = keyHex.substring(0, 32)
    ivBytes = new Uint8Array(keyBytes.buffer, 0, 16)
    # aesKeyHex = keyHex.substring(32,96)
    aesKeyBytes = new Uint8Array(keyBytes.buffer, 16, 32)

    contentBytes = tbut.utf8ToBytes(content)

    keyObjBytes = await createKeyObjectBytes(aesKeyBytes)
    algorithm = 
        name: "AES-CBC"
        iv: ivBytes

    gibbrishBytes = await crypto.encrypt(algorithm, keyObjBytes, contentBytes)
    return gibbrishBytes

export symmetricDecryptBytes = (gibbrishBytes, keyBytes) ->
    ivBytes = new Uint8Array(keyBytes.buffer, 0, 16)
    aesKeyBytes = new Uint8Array(keyBytes.buffer, 16, 32)

    # ivHex = keyHex.substring(0, 32)
    # aesKeyHex = keyHex.substring(32,96)
        
    keyObjBytes = await createKeyObjectHex(aesKeyBytes)
    algorithm = 
        name: "AES-CBC"
        iv: ivBytes

    contentBytes = await crypto.decrypt(algorithm, keyObjBytes, gibbrishBytes)
    return tbut.bytesToUtf8(contentBytes)

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

    lBigInt = hashToScalar(await sha512Bytes(nBytes))
    
    #A one time public key = reference Point
    ABytes = await noble.getPublicKey(nHex)
    lB = await B.multiply(lBigInt)
    
    symkey = await sha512Hex(lB.toHex())
    
    gibbrish = await  symmetricEncryptHex(content, symkey)
    
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
    kBigInt = hashToScalar(await sha512Bytes(aBytes))
    
    # {A,X} = secrets
    # A = lG = one time public reference point 
    # klG = lB = kA = shared secret
    # key = sha512(kAHex)
    # content = symmetricDecrypt(X, key)
    A = noble.Point.fromHex(AHex)
    kA = await A.multiply(kBigInt)
    
    symkey = await sha512Hex(kA.toHex())

    content = await symmetricDecryptHex(gibbrishHex,symkey)
    return content

export asymmetricEncrypt = (content, publicKeyHex) ->
    nBytes = noble.utils.randomPrivateKey()
    A = await noble.getPublicKey(nBytes)
    lB = await noble.getSharedSecret(nBytes, publicKeyHex)

    symkey = await sha512Bytes(lB)
    
    gibbrish = await symmetricEncryptBytes(content, symkey)    
    
    referencePointHex = tbut.bytesToHex(A)
    encryptedContentHex = tbut.bytesToHex(gibbrish)

    return {referencePointHex, encryptedContentHex}

export asymmetricDecrypt = (secrets, privateKeyHex) ->
    AHex = secrets.referencePointHex || secrets.referencePoint
    gibbrishHex = secrets.encryptedContentHex || secrets.encryptedContent
    if !AHex? or !gibbrishHex? then throw new Error("Invalid secrets Object!")

    kA = await noble.getSharedSecret(privateKeyHex, AHex)
    symkey = await sha512Bytes(kA)

    gibbrishBytes = tbut.hexToBytes(gibbrishHex)
    content = await symmetricDecryptBytes(gibbrishBytes, symkey)
    return content

export asymmetricEncryptHex = asymmetricEncrypt
export asymmetricDecryptHex = asymmetricDecrypt
############################################################
# Byte Version
export asymmetricEncryptBytes = (content, publicKeyBytes) ->
    nBytes = noble.utils.randomPrivateKey()
    ABytes = await noble.getPublicKey(nBytes)
    lB = await noble.getSharedSecret(nBytes, publicKeyBytes)

    symkeyBytes = await sha512Bytes(lB)
    gibbrishBytes = await symmetricEncryptBytes(content, symkeyBytes)    
    
    referencePointBytes = ABytes
    encryptedContentBytes = gibbrishBytes

    return {referencePointBytes, encryptedContentBytes}

export asymmetricDecryptBytes = (secrets, privateKeyBytes) ->
    ABytes = secrets.referencePointBytes || secrets.referencePoint
    gibbrishBytes = secrets.encryptedContentBytes || secrets.encryptedContent
    if !ABytes? or !gibbrishBytes? then throw new Error("Invalid secrets Object!")

    kABytes = await noble.getSharedSecret(privateKeyBytes, ABytes)
    symkeyBytes = await sha512Bytes(kABytes)

    content = await symmetricDecryptBytes(gibbrishBytes, symkeyBytes)
    return content

#endregion

############################################################
#region salts
export createRandomLengthSalt = ->
    bytes = new Uint8Array(512)
    loop
        window.crypto.getRandomValues(bytes)
        for byte,i in bytes when byte == 0
            return tbut.bytesToUtf8(bytes.slice(0,i+1))        

export removeSalt = (content) ->
    for char,i in content when char == "\0"
        return content.slice(i+1)
    throw new Error("No Salt termination found!")    

#endregion

#endregion