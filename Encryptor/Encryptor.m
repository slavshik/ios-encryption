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
        
        publicKey = [self getPublicKeyRef];
        privateKey = [self getPrivateKeyRef];
    }
    return self;
}

- (NSString *) encrypt:(NSString *)str error:(NSError**)e
{
    OSStatus status = noErr;
    NSLog(@"enctypt");
    
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

#pragma mark -

- (SecKeyRef) getPublicKeyRef {
    OSStatus resultCode = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if(publicKey == NULL) {
        NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
        
        // Set the public key query dictionary.
        [queryPublicKey setObject:(__bridge id)kSecClassKey         forKey:(__bridge id)kSecClass];
        [queryPublicKey setObject:publicTag                         forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA   forKey:(__bridge id)kSecAttrKeyType];
        [queryPublicKey setObject:[NSNumber numberWithBool:YES]     forKey:(__bridge id)kSecReturnRef];
        
        // Get the key.
        resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        NSLog(@"getPublicKey: result code: %ld", resultCode);
        
        if(resultCode != noErr)
        {
            publicKeyReference = NULL;
        }
    } else return publicKey;
    
    return publicKeyReference;
}

- (SecKeyRef) getPrivateKeyRef {
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if(privateKey == NULL) {
        NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
        
        // Set the private key query dictionary.
        [queryPrivateKey setObject:(__bridge id)kSecClassKey        forKey:(__bridge id)kSecClass];
        [queryPrivateKey setObject:privateTag                       forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA  forKey:(__bridge id)kSecAttrKeyType];
        [queryPrivateKey setObject:[NSNumber numberWithBool:YES]    forKey:(__bridge id)kSecReturnRef];
        
        // Get the key.
        resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
        NSLog(@"getPrivateKey: result code: %ld", resultCode);
        
        if(resultCode != noErr)
        {
            privateKeyReference = NULL;
        }
        
    } else return privateKey;
    
    return privateKeyReference;
}

@end