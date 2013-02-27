//
//  Created by Alexander Slavschik on 25.02.13.
//

#import "Encryptor.h"
#import "NSData+AESCrypt.h"

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
    
    NSMutableData* encryptedData = [NSMutableData dataWithCapacity:0];
    NSInputStream *stream = [[NSInputStream alloc] initWithData:inputData];
    [stream open];
    while ([stream hasBytesAvailable]) {
        uint8_t buffer[cipherBufferSize];
        NSUInteger bytesRead = [stream read:buffer maxLength:cipherBufferSize];
        
        status = SecKeyEncrypt(publicKey, kSecPaddingNone, buffer, bytesRead, cipherBuffer, &cipherBufferSize);
        
        if(status != noErr){
            *e = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
            return nil;
        }
        
        [encryptedData appendBytes:cipherBuffer length:cipherBufferSize];
        
    }
    [stream close];
    free(cipherBuffer);
    
    return [encryptedData base64Encoding];
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
        
        status = SecKeyDecrypt(privateKey, kSecPaddingNone, buffer, bytesRead, cipherBuffer, &cipherBufferSize);
        
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
    
    if(publicKey != NULL) return publicKey;
    
    OSStatus resultCode = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    // Get the key.
    resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)[self queryFromTag:publicTag], (CFTypeRef *)&publicKeyReference);
    NSLog(@"getPublicKey: result code: %ld", resultCode);

    if(resultCode != noErr) publicKeyReference = NULL;
    
    return publicKeyReference;
}

- (SecKeyRef) getPrivateKeyRef {
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if(privateKey != NULL) return privateKey;
    
    // Get the key.
    resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)[self queryFromTag:privateTag], (CFTypeRef *)&privateKeyReference);
    NSLog(@"getPrivateKey: result code: %ld", resultCode);
    
    if(resultCode != noErr) privateKeyReference = NULL;
    
    return privateKeyReference;
}
- (NSMutableDictionary *) queryFromTag:(NSData *)tag
{
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    
    // Set the key query dictionary.
    [queryKey setObject:(__bridge id)kSecClassKey        forKey:(__bridge id)kSecClass];
    [queryKey setObject:tag                              forKey:(__bridge id)kSecAttrApplicationTag];
    [queryKey setObject:(__bridge id)kSecAttrKeyTypeRSA  forKey:(__bridge id)kSecAttrKeyType];
    [queryKey setObject:[NSNumber numberWithBool:YES]    forKey:(__bridge id)kSecReturnRef];
    
    return queryKey;
}
@end