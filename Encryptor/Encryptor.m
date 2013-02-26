//
//  Created by Alexander Slavschik on 25.02.13.
//

#import "Encryptor.h"
#import "NSData+AESCrypt.h"

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 1024;
const uint32_t PADDING = kSecPaddingNone;
const uint32_t keySize = 512;

@implementation Encryptor
{
    SecKeyRef publicKey;
    SecKeyRef privateKey;
    NSData *publicTag;
    NSData *privateTag;
}
- (id) init
{
    @throw [[NSException alloc] initWithName:@"Initialisation failed" reason:@"You should use initWithPublicKey:andPrivateKey initialisation." userInfo:nil];
}
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

- (NSString *) encrypt:(NSString *)str error:(NSError**)e
{
    OSStatus status = noErr;
    
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
        
        if(status != noErr){
            *e = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
            return nil;
        }
        
        [accumulatedEncryptedData appendBytes:cipherBuffer length:cipherBufferSize];
        
    }
    [stream close];
    free(cipherBuffer);
    
    return [accumulatedEncryptedData base64Encoding];
}
- (NSString *) decrypt:(NSString *)str error:(NSError**)e
{
    
    OSStatus status = noErr;
    
    NSData *inputData = [[NSData alloc] initWithBase64EncodedString:str];
    
    //  Allocate a buffer
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);
    
    NSMutableData* decryptedData = [NSMutableData dataWithCapacity:0];
    NSInputStream *stream = [[NSInputStream alloc] initWithData:inputData];
    [stream open];
    while ([stream hasBytesAvailable]) {
        uint8_t buffer[cipherBufferSize];
        NSUInteger bytesRead = [stream read:buffer maxLength:cipherBufferSize];
        
        status = SecKeyDecrypt(privateKey, PADDING, buffer, bytesRead, cipherBuffer, &cipherBufferSize);
        
        if(status != noErr){
            *e = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
            return nil;
        }
        
        [decryptedData appendBytes:cipherBuffer length:cipherBufferSize];
        
    }
    [stream close];
    
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
    
    // Set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    // Set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);
    NSError *error;
    if(sanityCheck != noErr){
        error = [[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:sanityCheck userInfo:nil];
    }else{
        if(publicKey == NULL || privateKey == NULL)
        {
            NSDictionary *userInfo = [NSDictionary dictionaryWithObjects:@[[NSNumber numberWithBool:publicKey != NULL], [NSNumber numberWithBool:privateKey != NULL]]
                                                                 forKeys:@[@"has_public", @"has_private"]];
            error = [[NSError alloc] initWithDomain:@"Encryptor" code:1 userInfo:userInfo];
        }
    }
    if(error){
        //handle error here, if you want
        @throw [[NSException alloc] initWithName:[error localizedDescription] reason:[error localizedFailureReason] userInfo:nil];
    }
}

@end