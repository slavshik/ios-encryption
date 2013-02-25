#import "Encryptor.h"
#import "NSData+AESCrypt.h"

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 1024;
const uint32_t PADDING = kSecPaddingNone;
const uint32_t keySize = 512;

@implementation Encryptor

- (id) initWithPublicKey:(NSString *)public_key andPrivateKey:(NSString *)private_key
{
    if(self = [super init])
    {
        privateTag = [private_key dataUsingEncoding:NSUTF8StringEncoding];
        publicTag = [public_key dataUsingEncoding:NSUTF8StringEncoding];
        
        [self generateKeyPair:keySize];
    }
    return self;
}

- (SecKeyRef) getPublicKeyRef {
    
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if (publicKey == NULL) {
        [self generateKeyPair:keySize];
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
- (SecKeyRef) getPrivateKeyRef
{
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if (publicKey == NULL) {
        [self generateKeyPair:keySize];
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
            @throw [[NSException alloc] initWithName:@"Failed to generate key" reason:@"getPrivateKeyRef failed" userInfo:nil];
        }
    }else{
        return privateKey;
    }
    return privateKeyReference;
}
- (NSString *) encrypt:(NSString *)str
{
    __unused OSStatus status = noErr;
    
    NSData* inputData = [str dataUsingEncoding:NSUTF8StringEncoding];
    
    //  Allocate a buffer
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);
    
    NSMutableData* accumulatedEncryptedData = [NSMutableData dataWithCapacity:0];
    NSInputStream *stream = [[NSInputStream alloc] initWithData:inputData];
    [stream open];
    while ([stream hasBytesAvailable]) {
        uint8_t buffer[cipherBufferSize];
        NSUInteger bytesRead = [stream read:buffer maxLength:cipherBufferSize];
        
        status = SecKeyEncrypt(publicKey, PADDING, buffer, bytesRead, cipherBuffer, &cipherBufferSize);
        
        [accumulatedEncryptedData appendBytes:cipherBuffer length:cipherBufferSize];
        
    }
    [stream close];
    
    return [accumulatedEncryptedData base64Encoding];
}
- (NSString *) decrypt:(NSString *)str
{
    
    OSStatus status = noErr;
    
    NSData *inputData = [[NSData alloc] initWithBase64EncodedString:str];
    size_t dataSize = [inputData length];
    const uint8_t* dataBytes = [inputData bytes];
    
    //  Allocate a buffer
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);
    
    NSMutableData* decryptedData = [NSMutableData dataWithCapacity:0];
    
    for (int i = 0; i*cipherBufferSize < dataSize; i++) {
        const uint8_t* dataToDecrypt = dataBytes+(i*cipherBufferSize);
        size_t subsize;
        size_t cur_size = (i+1) * cipherBufferSize - dataSize;
        if(cur_size > 0) {
            subsize =  cipherBufferSize - cur_size;
        }else{
            subsize = cipherBufferSize;
        }
        
        // Decrypt using the private key.
        status = SecKeyDecrypt(privateKey, PADDING, dataToDecrypt, subsize, cipherBuffer, &cipherBufferSize);
        
        [decryptedData appendBytes:cipherBuffer length:cipherBufferSize];
    }
    
    free(cipherBuffer);
    
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

- (void) generateKeyPair:(NSUInteger)keySize {
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