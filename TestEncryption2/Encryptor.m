#import "Encryptor.h"
#import "NSData+AESCrypt.h"

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 1024;
const uint32_t PADDING = kSecPaddingNone;

@implementation Encryptor

- (id)initWithPublicKey:(NSString *)public_key andPrivateKey:(NSString *)private_key
{
    if(self = [super init])
    {
        static const UInt8 publicKeyIdentifier[] = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFhZ4yM1bdm+m6pQhrtACraeM9UvCd5ROteiyt4CJ+mU1eY/rmD4mkRJdnny23jKm1RgO91dAXOekEY1MdQ/Xfx7LZY9Vv4NXwGjGWsXvZJoZVLBKJhgeM2RLZmMKVuTbN6xyBb7/3cx0C2yYQ70DeEsAffLWFERbf8QdHe8iM1QIDAQAB-----END PUBLIC KEY-----";
        static const UInt8 privateKeyIdentifier[] = "-----BEGIN RSA PRIVATE KEY-----MIICXAIBAAKBgQDFhZ4yM1bdm+m6pQhrtACraeM9UvCd5ROteiyt4CJ+mU1eY/rmD4mkRJdnny23jKm1RgO91dAXOekEY1MdQ/Xfx7LZY9Vv4NXwGjGWsXvZJoZVLBKJhgeM2RLZmMKVuTbN6xyBb7/3cx0C2yYQ70DeEsAffLWFERbf8QdHe8iM1QIDAQABAoGAdVGt6sdPmwUWSIPpgn9Bvo6AKFZxEHeVvn5It2XfVy6bI6tixO8JpAYRn7yOHO1xh3f0lPbASGtfGfoczc8l5B8IxHK98uNR2ajUXTThZaFG45IuK/QfBbPAmBwYpbjsiEq38vec8JqZPvtthIT0sgTb2s/y7lWw0DHkfcFKNakCQQDycdFVgJmcQlm4R1iEiJievtNlwN53MJlKJc+WVWgx71iiGPS5q9KalcC80HeTt6+wRiJTGOxGleVb58P7y6iHAkEA0JDPDavO4W+vnnIaBcNRjy5fSw/6/OERPWnxQ4r1Mj4E8vAf3ygYiZji4ppCR8+wWp/6N6/xeo0lcau6jCDiwwJAUA7Hik1p7BB44gIlN7aHdzwaQGp8y6zvoW106/aN7pdTlEtbXIhhhgxXVcIdCllImZO/N+Nt+iz7TOrua5IntwJBAJ7l1Hmr7Z/fQUNL1vuRBTA6uisr76J9rm7FqiQ1V/2BNrAHtaCEob0jF6hgsiKX3toMi8ulZipiIqbpmORtoZUCQErSpG0hQlj97PtM2bN8C309oEkJ9bYiR7qVvWaU73TKuFbEHR+TBy7ZpeSqHjYZ91x6nWVylp3h1I3BOhedGRk=-----END RSA PRIVATE KEY-----";
        
        NSLog(@"Encryptor created");
        
        privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
        publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
        
        [self generateKeyPair:512];
    }else{
        @throw [[NSException alloc] initWithName:@"Init failed" reason:@"Something goes wrong" userInfo:nil];
    }
    return self;
}

-(SecKeyRef)getPublicKeyRef {
    
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if (publicKey == NULL) {
        [self generateKeyPair:512];
        NSMutableDictionary *queryPublicKey = [[NSMutableDictionary alloc] init];
        
        // Set the public key query dictionary.
        [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        
        // Get the key.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        
        
        if (sanityCheck != noErr)
        {
            publicKeyReference = NULL;
            @throw [[NSException alloc] initWithName:@"Faild to generate key" reason:@"getPrivateKeyRef failed" userInfo:nil];
        }
        
    } else {
        return publicKey;
    }
    
    return publicKeyReference;
}
- (SecKeyRef)getPrivateKeyRef
{
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if (publicKey == NULL) {
        [self generateKeyPair:512];
        NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
        
        // Set the private key query dictionary.
        [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        // Get the key.
        resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
        
        if(resultCode != noErr)
        {
            @throw [[NSException alloc] initWithName:@"Faild to generate key" reason:@"getPrivateKeyRef failed" userInfo:nil];
        }
    }else{
        return privateKey;
    }
    return privateKeyReference;
}
- (NSString *) encrypt:(NSString *)str
{
    OSStatus status = noErr;
    
    size_t cipherBufferSize;
    uint8_t *cipherBuffer;
    
    // [cipherBufferSize]
    size_t dataSize = [str lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    const uint8_t* textData = [[str dataUsingEncoding:NSUTF8StringEncoding] bytes];
    
    //  Allocate a buffer
    
    cipherBufferSize = SecKeyGetBlockSize(publicKey);
    // plain text block size must be 11 less than cipher buffer size because of
    // the PKSC1 padding used:
    const size_t blockSizeMinusPadding = cipherBufferSize - 11;
    cipherBuffer = malloc(cipherBufferSize);
    
    NSMutableData* accumulatedEncryptedData = [NSMutableData dataWithCapacity:0];
    
    for (int ii = 0; ii*blockSizeMinusPadding < dataSize; ii++) {
        const uint8_t* dataToEncrypt = (textData+(ii*blockSizeMinusPadding));
        const size_t subsize = (((ii+1)*blockSizeMinusPadding) > dataSize) ? blockSizeMinusPadding-(((ii+1)*blockSizeMinusPadding) - dataSize) : blockSizeMinusPadding;
        
        // Encrypt using the public key.
        status = SecKeyEncrypt(publicKey,
                               kSecPaddingPKCS1,
                               dataToEncrypt,
                               subsize,
                               cipherBuffer,
                               &cipherBufferSize
                               );
        
        [accumulatedEncryptedData appendBytes:cipherBuffer length:cipherBufferSize];
    }
    
    free(cipherBuffer);
    
    return [accumulatedEncryptedData base64Encoding];
    /*uint8_t *plainBuffer;
    uint8_t *cipherBuffer;
    
    const char* inputString = [str UTF8String];
    int len = strlen(inputString);
    
    plainBuffer = (uint8_t *)calloc(len, sizeof(uint8_t));
    cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
    
    strncpy((char *)plainBuffer, inputString, len);
    
    [self encryptWithPublicKey:(UInt8 *)plainBuffer cipherBuffer:cipherBuffer];
    NSData *data = [[NSData alloc] initWithBytes:cipherBuffer length:strlen((char *)cipherBuffer)];
    
    free(plainBuffer);
    free(cipherBuffer);
    
    return [data base64Encoding];*/
}
- (NSString *) decrypt:(NSString *)str
{
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str];
    
    uint8_t *cipherBuffer = (uint8_t *)[data bytes];
    
    return nil;
    
    uint8_t *decryptedBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    
    [self decryptWithPrivateKey:cipherBuffer plainBuffer:decryptedBuffer];
    
    free(decryptedBuffer);
    
    return [[NSString alloc] initWithUTF8String:(const char *)decryptedBuffer];
}

- (void)encryptWithPublicKey:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer
{
    
    OSStatus status = noErr;
    
    size_t plainBufferSize = strlen((char *)plainBuffer);
    size_t cipherBufferSize = strlen((char *)cipherBuffer);
    
    // Encrypt using the public.
    status = SecKeyEncrypt(publicKey, PADDING, plainBuffer, plainBufferSize, &cipherBuffer[0], &cipherBufferSize);
    
    //Error handling
    if(status != noErr){
        NSLog(@"encrypt error %li", status);
    }
}

- (void)decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer
{
    OSStatus status = noErr;
    
    size_t cipherBufferSize = strlen((char *)cipherBuffer);
    
    //NSLog(@"decryptWithPrivateKey: length of buffer: %lu", BUFFER_SIZE);
    //NSLog(@"decryptWithPrivateKey: length of input: %lu", cipherBufferSize);
    
    // DECRYPTION
    size_t plainBufferSize = BUFFER_SIZE;
    
    //  Error handling
    //NSLog(@"cipherBuffer %s", cipherBuffer);
    status = SecKeyDecrypt(privateKey,
                           PADDING,
                           &cipherBuffer[0],
                           cipherBufferSize,
                           &plainBuffer[0],
                           &plainBufferSize
                           );
    //NSLog(@"decryption result code: %ld (size: %lu)", status, plainBufferSize);
    //NSLog(@"FINAL decrypted text: %s", plainBuffer);
}

- (void)generateKeyPair:(NSUInteger)keySize {
    OSStatus sanityCheck = noErr;
    publicKey = NULL;
    privateKey = NULL;
    
    // Container dictionaries.
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // Set top level dictionary for the keypair.
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    // Set the private key dictionary.
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);
    
    if(sanityCheck == noErr  && publicKey != NULL && privateKey != NULL)
    {
        //NSLog(@"Successful");
    }else{
        NSLog(@"Fail");
    }
}


@end