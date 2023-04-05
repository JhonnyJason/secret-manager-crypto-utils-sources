############################################################
import * as ed255 from "@noble/ed25519"
import * as tbut from "thingy-byte-utils"
import crypto from "crypto"

############################################################
encAlgo = 'aes-256-cbc'

############################################################
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
export sha256 = (content) ->
    hasher = crypto.createHash("sha256")
    hasher.update(content)
    return hasher.digest("hex")

export sha512 = (content) ->
    hasher = crypto.createHash("sha512")
    hasher.update(content)
    return hasher.digest("hex")

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
export createKeyPair = ->
    secretKeyBytes = ed255.utils.randomPrivateKey()
    publicKeyBytes = await ed255.getPublicKeyAsync(secretKeyBytes)
    secretKeyHex = tbut.bytesToHex(secretKeyBytes)
    publicKeyHex = tbut.bytesToHex(publicKeyBytes)
    return {secretKeyHex, publicKeyHex}

export createSymKey = ->
    keyAndIV = crypto.randomBytes(48)
    return tbut.bytesToHex(keyAndIV)

export createPublicKey = (secretKeyHex) ->
    publicKeyBytes = await ed255.getPublicKeyAsync(tbut.hexToBytes(secretKeyHex))
    return tbut.bytesToHex(publicKeyBytes)

export createKeyPairHex = createKeyPair
export createSymKeyHex = createSymKey
export createPublicKeyHex = createPublicKey

############################################################
# Byte Version
export createKeyPairBytes =  ->
    secretKeyBytes = ed255.utils.randomPrivateKey()
    publicKeyBytes = await ed255.getPublicKeyAsync(secretKeyBytes)
    return {secretKeyBytes, publicKeyBytes}

export createSymKeyBytes = -> new Uint8Array((crypto.randomBytes(48)))

export createPublicKeyBytes = (secretKeyBytes) -> await ed255.getPublicKeyAsync(secretKeyBytes)

#endregion

############################################################
#region signatures

############################################################
# Hex Version
export createSignature = (content, signingKeyHex) ->
    contentBytes = tbut.utf8ToBytes(content)
    signingKeyBytes = tbut.hexToBytes(signingKeyHex)
    signature = await ed255.signAsync(contentBytes, signingKeyBytes)
    return tbut.bytesToHex(signature)

export verify = (sigHex, keyHex, content) ->
    sigBytes = tbut.hexToBytes(sigHex)
    keyBytes = tbut.hexToBytes(keyHex)
    contentBytes = tbut.utf8ToBytes(content)
    return await ed255.verifyAsync(sigBytes, contentBytes, keyBytes)

export createSignatureHex = createSignature
export verifyHex = verify 
############################################################
# Byte Version
export createSignatureBytes = (content, signingKeyBytes) ->
    contentBytes = tbut.utf8ToBytes(content)
    return await ed255.signAsync(contentBytes, signingKeyBytes)

export verifyBytes = (sigBytes, keyBytes, content) ->
    contentBytes = tbut.utf8ToBytes(content)
    return await ed255.verifyAsync(sigBytes, contentBytes, keyBytes)


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

    saltedContent = saltContent(content)
    cipher = crypto.createCipheriv(encAlgo, aesKeyBuffer, ivBuffer)
    gibbrish = cipher.update(saltedContent, null, 'hex')
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

    decipher = crypto.createDecipheriv(encAlgo, aesKeyBuffer, ivBuffer)
    saltedContent = decipher.update(gibbrishHex, 'hex')
    finalContent = decipher.final()
    if finalContent.length == 0 then return unsaltContent(saltedContent)

    allSaltedContent = new Uint8Array(saltedContent.length + finalContent.length)
    for b,i in saltContent
        allSaltedContent[i] = b
    for b,i in finalContent
        allSaltedContent[saltedContent.length + i] = b
    return unsaltContent(allSaltedContent)
    
export symmetricEncryptHex = symmetricEncrypt
export symmetricDecryptHex = symmetricDecrypt
############################################################
# Byte Version
export symmetricEncryptBytes = (content, keyBytes) ->
    ivBuffer = Buffer.from(keyBytes.buffer, 0, 16)
    aesKeyBuffer = Buffer.from(keyBytes.buffer, 16, 32)
    
    saltedContent = saltContent(content)
    cipher = crypto.createCipheriv(encAlgo, aesKeyBuffer, ivBuffer)
    gibbrish = cipher.update(saltedContent)
    gibbrishFinal = cipher.final()
    if gibbrishFinal.length == 0 then return new Uint8Array(gibbrish)
    allGibbrish = new Uint8Array(gibbrishFinal.length + gibbrish.length)
    for b,i in gibbrish
        allGibbrish[i] = b
    for b,i in gibbrishFinal
        allGibbrish[gibbrish.length + i] = b
    return allGibbrish

export symmetricDecryptBytes = (gibbrishBytes, keyBytes) ->
    ivBuffer = Buffer.from(keyBytes.buffer, 0, 16)
    aesKeyBuffer = Buffer.from(keyBytes.buffer, 16, 32)
    
    decipher = crypto.createDecipheriv(encAlgo, aesKeyBuffer, ivBuffer)
    saltedContent = decipher.update(gibbrishBytes)
    finalContent = decipher.final()
    if finalContent.length == 0 then return unsaltContent(saltedContent)

    allSaltedContent = new Uint8Array(saltedContent.length + finalContent.length)
    for b,i in saltContent
        allSaltedContent[i] = b
    for b,i in finalContent
        allSaltedContent[saltedContent.length + i] = b
    return unsaltContent(allSaltedContent)
    
#endregion

############################################################
#region asymmetric encryption

############################################################
# Hex Version

export asymmetricEncrypt = (content, publicKeyHex) ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)

    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(sha512Bytes(nBytes))
    
    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    
    # encrypt with symmetricEncryptHex
    symkeyHex = sha512Hex(lB.toRawBytes())    
    gibbrishHex = symmetricEncryptHex(content, symkeyHex)

    referencePointHex = tbut.bytesToHex(ABytes)
    encryptedContentHex = gibbrishHex
    return {referencePointHex, encryptedContentHex}

export asymmetricDecrypt = (secrets, secretKeyHex) ->
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
    A = ed255.ExtendedPoint.fromHex(AHex)
    kA = A.multiply(kBigInt)

    symkeyHex = sha512Hex(kA.toRawBytes())
    content = symmetricDecryptHex(gibbrishHex,symkeyHex)
    return content


export asymmetricEncryptHex = asymmetricEncrypt
export asymmetricDecryptHex = asymmetricDecrypt

############################################################
# Byte Version
export asymmetricEncryptBytes = (content, publicKeyBytes) ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    publicKeyHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)
    
    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(sha512Bytes(nBytes))

    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)

    symkeyBytes = sha512Bytes(lB.toRawBytes())
    gibbrishBytes = symmetricEncryptBytes(content, symkeyBytes)

    referencePointBytes = ABytes
    encryptedContentBytes = gibbrishBytes
    return {referencePointBytes, encryptedContentBytes}

export asymmetricDecryptBytes = (secrets, secretKeyBytes) ->
    ABytes = secrets.referencePointBytes || secrets.referencePoint
    gibbrishBytes = secrets.encryptedContentBytes || secrets.encryptedContent
    if !ABytes? or !gibbrishBytes? then throw new Error("Invalid secrets Object!")

    # a = Secret Key
    # k = sha512(a) -> hashToScalar
    # G = basePoint
    # B = kG = Public Key
    kBigInt = hashToScalar(sha512Bytes(secretKeyBytes))

    # {A,X} = secrets
    # A = lG = one time public reference point 
    # klG = lB = kA = shared secret
    # key = sha512(kAHex)
    # content = symmetricDecrypt(X, key)
    AHex = tbut.bytesToHex(ABytes)
    A = ed255.ExtendedPoint.fromHex(AHex)
    kA = A.multiply(kBigInt)

    symkeyBytes = sha512Bytes(kA.toRawBytes())
    content = symmetricDecryptBytes(gibbrishBytes, symkeyBytes)
    return content

#endregion

############################################################
#region deffieHellman/ElGamal secrets

############################################################
# Hex Versions

############################################################
export diffieHellmanSecretHash = (secretKeyHex, publicKeyHex, contextString = "") ->
    # a = our SecretKey
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # B = lG = target User Public Key
    # kB = klG = shared Secret
    aBytes = tbut.hexToBytes(secretKeyHex)
    kBigInt = hashToScalar(sha512Bytes(aBytes))
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)
    
    # A reference Point
    kB = B.multiply(kBigInt)
    kBBytes = kB.toRawBytes()
    cBytes = tbut.utf8ToBytes(contextString)

    seedBytes = new Uint8Array(kBBytes.length + cBytes.length)
    for b,i in kBBytes
        seedBytes[i] = b
    for b,i in cBytes
        seedBytes[kBBytes.length + i] = b

    sharedSecretHex = sha512Hex(seedBytes)
    return sharedSecretHex

export diffieHellmanSecretRaw = (secretKeyHex, publicKeyHex) ->
    # a = our SecretKey
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # B = lG = target User Public Key
    # kB = klG = shared Secret
    aBytes = tbut.hexToBytes(secretKeyHex)
    kBigInt = hashToScalar(sha512Bytes(aBytes))
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)
    
    kB = B.multiply(kBigInt)

    sharedSecretBytes = kB.toRawBytes()
    sharedSecretHex = tbut.bytesToHex(sharedSecretBytes) 
    return sharedSecretHex

export diffieHellmanSecretHashHex = diffieHellmanSecretHash
export diffieHellmanSecretRawHex = diffieHellmanSecretRaw

############################################################
export elGamalSecretHash = (publicKeyHex, contextString = "") ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)

    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(sha512Bytes(nBytes))
    
    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    lBBytes = lB.toRawBytes()

    cBytes = tbut.utf8ToBytes(contextString)

    seedBytes = new Uint8Array(lBBytes.length + cBytes.length)
    for b,i in lBBytes
        seedBytes[i] = b
    for b,i in cBytes
        seedBytes[lBBytes.length + i] = b

    sharedSecretHex = sha512Hex(seedBytes)
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

export elGamalSecretRaw = (publicKeyHex) ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    B = ed255.ExtendedPoint.fromHex(publicKeyHex)

    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(sha512Bytes(nBytes))
    
    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    lBBytes = lB.toRawBytes()
    
    sharedSecretHex = tbut.bytesToHex(lBBytes) 
    referencePointHex = tbut.bytesToHex(ABytes)
    return { referencePointHex, sharedSecretHex }

export elGamalSecretHashHex = elGamalSecretHash
export elGamalSecretRawHex = elGamalSecretRaw

############################################################
# Bytes Versions

############################################################
export diffieHellmanSecretHashBytes = (secretKeyBytes, publicKeyBytes, contextString = "") ->
    # a = our SecretKey
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # B = lG = target User Public Key
    # kB = klG = shared Secret
    BHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(BHex)
    # k 
    kBigInt = hashToScalar(sha512Bytes(secretKeyBytes))
    # kB = klG = shared Secret
    kB = B.multiply(kBigInt)
    kBBytes = kB.toRawBytes()
    cBytes = tbut.utf8ToBytes(contextString)
    
    seedBytes = new Uint8Array(kBBytes.length + cBytes.length)
    for b,i in kBBytes
        seedBytes[i] = b
    for b,i in cBytes
        seedBytes[kBBytes.length + i] = b

    sharedSecretBytes = sha512Bytes(seedBytes)
    return sharedSecretBytes

export diffieHellmanSecretRawBytes = (secretKeyBytes, publicKeyBytes) ->
    # a = our SecretKey
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # B = lG = target User Public Key
    # kB = klG = shared Secret
    BHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(BHex)
    # k 
    kBigInt = hashToScalar(sha512Bytes(secretKeyBytes))
    # kB = klG = shared Secret
    kB = B.multiply(kBigInt)
    kBBytes = kB.toRawBytes()
    return kBBytes

############################################################
export elGamalSecretHashBytes = (publicKeyBytes, contextString = "") ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    BHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(BHex)

    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(sha512Bytes(nBytes))
    
    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    lBBytes = lB.toRawBytes()

    cBytes = tbut.utf8ToBytes(contextString)

    seedBytes = new Uint8Array(lBBytes.length + cBytes.length)
    for b,i in lBBytes
        seedBytes[i] = b
    for b,i in cBytes
        seedBytes[lBBytes.length + i] = b
    
    sharedSecretBytes = sha512Bytes(seedBytes)
    referencePointBytes = ABytes
    return { referencePointBytes, sharedSecretBytes }

export elGamalSecretRawBytes = (publicKeyBytes) ->
    # a = Secret Key of target user
    # k = sha512(a) -> hashToScalar (scalar for multiplication)
    # G = basePoint
    # B = kG = Public Key
    BHex = tbut.bytesToHex(publicKeyBytes)
    B = ed255.ExtendedPoint.fromHex(BHex)
    
    # n = new one-time secret (generated forgotten about)
    # l = sha512(n) -> hashToScalar (scalar for multiplication)
    # A = lG = one time public key = reference point
    # lB = lkG = shared secret
    # key = sha512(lB)
    # X = symmetricEncrypt(content, key)
    # {A,X} = data for targt user

    # n = one-time secret -> l
    nBytes = ed255.utils.randomPrivateKey()
    lBigInt = hashToScalar(sha512Bytes(nBytes))
    
    # A reference Point
    ABytes = await ed255.getPublicKeyAsync(nBytes)
    # lB = lkG = shared Secret
    lB = B.multiply(lBigInt)
    lBBytes = lB.toRawBytes()

    sharedSecretBytes = lBBytes
    referencePointBytes = ABytes
    return { referencePointBytes, sharedSecretBytes }

#endregion

############################################################
#region salts

export saltContent = (content) ->
    content = tbut.utf8ToBytes(content)
    contentLength = content.length

    saltLength = 33 + (crypto.randomBytes(1)[0] & 127 )
    salt = crypto.randomBytes(saltLength)
    
    # Prefix is salt + 3 bytes
    prefixLength = saltLength + 3
    unpaddedLength = prefixLength + contentLength
    overlap = unpaddedLength % 32
    padding = 32 - overlap

    fullLength = unpaddedLength + padding

    resultBuffer = new Uint8Array(fullLength)
    # immediatly write the content to the resultBuffer
    for c,idx in content
        resultBuffer[idx + prefixLength] = c

    # The first 32 bytes of the prefix are 1:1 from the salt.
    sum = 0 
    idx = 32
    while(idx--)
        sum += salt[idx]
        resultBuffer[idx] = salt[idx]

    # the last byte of the prefix is the padding length
    resultBuffer[saltLength + 2] = padding

    # the postfix padding is the first salt bytes up to padding size
    idx = 0    
    end = fullLength - 1
    while(idx < padding)
        resultBuffer[end - idx] = salt[idx]
        idx++


    # the prefix keeps the sum of the salt values as ending identification 
    # make sure this condition is not met before we reach the real end
    idx = 32
    while(idx < saltLength)
        # when the condition is met we add +1 to the LSB(salt[idx+1]) to destroy it 
        # Notice! If we add +1 to the MSB(salt[idx]) then we change what we cheched for previously, which might accidentally result in the condition being met now one byte before, which we donot check for ever again
        # if (sum == (salt[idx]*256 + salt[idx+1])) then salt[idx+1]++
        salt[idx+1] += (sum == (salt[idx]*256 + salt[idx+1]))
        sum += salt[idx]
        resultBuffer[idx] = salt[idx]
        idx++

    # save the sum in the right bytes
    resultBuffer[saltLength] = (sum >> 8)
    resultBuffer[saltLength + 1] = (sum % 256)

    # in this case we have the condition met when just taking the most significatn bytes of the real sum into account
    if resultBuffer[saltLength] == resultBuffer[saltLength - 1] and resultBuffer[saltLength + 1] == 2 * resultBuffer[saltLength]
        resultBuffer[saltLength - 1]++
        sum++
        resultBuffer[saltLength] = (sum >> 8)
        resultBuffer[saltLength + 1] = (sum % 256)

    return resultBuffer

export unsaltContent = (contentBytes) ->
    fullLength = contentBytes.length

    if fullLength > 160 then limit = 160
    else limit = fullLength
    overLimit = limit + 1

    sum = 0 
    idx = 32
    while(idx--)
        sum += contentBytes[idx]

    idx = 32
    while idx < overLimit
        if (sum == (contentBytes[idx]*256 + contentBytes[idx+1]))
            start = idx + 3
            padding = contentBytes[idx+2]
            break
        sum += contentBytes[idx]
        idx++

    if idx > limit then throw new Error("Unsalt: No valid prefix ending found!")
    

    # Check if the padding matches the salt - so we can verify here nobody has tampered with it
    idx = 0
    end = fullLength - 1
    invalid = 0
    while idx < padding
        invalid += (contentBytes[idx] != contentBytes[end - idx])
        idx++
    if invalid then throw new Error("Unsalt: Postfix and prefix did not match as expected!")
    end = fullLength - padding

    contentBytes = contentBytes.slice(start, end)
    return tbut.bytesToUtf8(contentBytes)

#endregion

#endregion