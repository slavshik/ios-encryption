//
//  Created by Alexander Slavschik on 25.02.13.
//

#import "Encryptor.h"
#import "Base64.h"

const uint32_t PADDING = kSecPaddingPKCS1;

@implementation Encryptor
{
    SecKeyRef publicKey;
    SecKeyRef privateKey;
	NSString *publicKeyTag;
	NSString *privateKeyTag;
}
- (NSString *) encrypt:(NSString *)str withPublicKey:(NSString *)public_key
{

    //convert String to NSDate
    NSData* inputData = [str dataUsingEncoding:NSUTF8StringEncoding];
    //- (NSString *) encryptData:(NSData *)data withPublicKey:(NSString *)public_key;
     NSData* outputData=[self encryptData:inputData withPublicKey:public_key];
    //convert NSDate to String
    return  [outputData base64EncodedString];

}

- (NSString *) decrypt:(NSString *)str withPrivateKey:(NSString *) private_key;
{
    //Convert cipher string to NSDate
    NSData *inputData = [NSData dataWithBase64EncodedString:str];
    //- (NSString *) decryptData:(NSData *)data withPrivateKey:(NSString *) private_key;
    NSData *outputData =   [self decryptData:inputData withPrivateKey:private_key];
    //convert the decrypted NSDate to String
    return [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding];


}
//- (NSString *) convertTypeOfFile:(NSString*)type  andPathFile:(NSString*)path{
//    path = [[NSBundle mainBundle] pathForResource:path ofType:type];
//    NSData *myData = [NSData dataWithContentsOfFile:path];
//}
#pragma mark - ِDATA ENCRYPTION DECREPTION
//the method encypt the NSData object using Public Key
- (NSData *) encryptData:(NSData *)inputData withPublicKey:(NSString *)public_key{
    
    
    OSStatus status = noErr;
    NSLog(@"encrypt");
    //  Allocate a buffer
	SecKeyRef publicKeyRef = [self getPublicKeyRef:public_key];
	size_t keyBlockSize = SecKeyGetBlockSize(publicKeyRef);
	__unused size_t bufferSize = keyBlockSize;
	if(PADDING == kSecPaddingPKCS1)	{
		bufferSize = keyBlockSize - 12;
	}
    //
	size_t cipherBufferSize = keyBlockSize;
    //create buffer that used to save plain data and Cipher data
    uint8_t *buffer = malloc(cipherBufferSize);//buffer to plain/cipher data
    //init object from NSMutableData to save cipher data
    NSMutableData* encryptedData = [NSMutableData dataWithCapacity:0];
    //convert Plain String ===>NSData====>now we will convert it to STREAM
    NSInputStream *stream = [NSInputStream inputStreamWithData:inputData];
    [stream open];
    //+++++++The Code In While statment
    //beging stream from plain data and fill the buffer and encrypt it and set it to buffer again
    while ([stream hasBytesAvailable] && status == noErr) {
		cipherBufferSize = keyBlockSize;
        //uint8_t buffer[blockSizeMinusPadding];
        NSUInteger bytesRead = [stream read:buffer maxLength:bufferSize];
        //the method of encrypt and it's parameters
        //status @result A result code. See "Security Error Codes" (SecBase.h).
        
        //status = SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen);
        //encrypt the plain text in buffer and set it to buffer again
        //the size of plain bytes set it to bytesRead and the size of cipher bytes to cipherBufferSize
        status = SecKeyEncrypt(publicKeyRef, PADDING, buffer, bytesRead, buffer, &cipherBufferSize);
        
        //append the buffer cipher data to encryptedData that prepered before
        [encryptedData appendBytes:buffer length:cipherBufferSize];
        
    }
    [stream close];
    free(buffer);
    
	if(status != noErr){
		NSLog(@"encryption failed with status %d", (int)status);
		return nil;
	}
    
    return encryptedData ;
}
- (NSData *) decryptData:(NSData *)data withPrivateKey:(NSString *) private_key{
    
    OSStatus status = noErr;

    //  Allocate a buffer
	SecKeyRef privateKeyRef = [self getPrivateKeyRef:private_key];
	size_t keyBlockSize = SecKeyGetBlockSize(privateKeyRef);
    size_t plainTextLen = keyBlockSize;
    uint8_t *plainText = malloc(plainTextLen);
    //init object from NSMutableData to save plain data after decryption
    NSMutableData* decryptedData = [NSMutableData dataWithCapacity:0];
    //convert Cipher String ===>NSData====>now we will convert it to STREAM
    NSInputStream *stream = [NSInputStream inputStreamWithData:data];
    [stream open];
    //+++++++The Code In While statment
    //beging stream from cipher data and fill the buffer and dencrypt it and set it to buffer again
    while ([stream hasBytesAvailable] && status == noErr) {
		plainTextLen = keyBlockSize;
        uint8_t buffer[plainTextLen];
        NSUInteger bytesRead = [stream read:buffer maxLength:plainTextLen];
        //the method of dencrypt and it's parameters
        //status @result A result code. See "Security Error Codes" (SecBase.h).
        
        //status = SecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, &lainTextLen);
        //dencrypt the cipher text in buffer and set the plain text  to buffer again
        //the size of cipher bytes set it to bytesRead and the size of plain bytes to plainTextLen
        status = SecKeyDecrypt(privateKeyRef, PADDING, buffer, bytesRead, plainText, &plainTextLen);
        //append the buffer plain data to decryptedData that prepered before
        [decryptedData appendBytes:plainText length:plainTextLen];
    }
    [stream close];
    free(plainText);
	
    if(status != noErr){
		NSLog(@"Decryption failed with status %d", (int)status);
		return nil;
	}
    return decryptedData;
}
#pragma mark - GET THE KEYS


- (SecKeyRef) getPublicKeyRef:(NSString *)keyTag {

	if(publicKey != nil && [publicKeyTag isEqualToString:keyTag]) return publicKey;

	publicKeyTag = keyTag;

    OSStatus resultCode = noErr;
    SecKeyRef publicKeyReference = NULL;

	NSData *keyTagData = [keyTag dataUsingEncoding:NSUTF8StringEncoding];

    
        NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
        
        // Set the public key query dictionary.
        [queryPublicKey setObject:(__bridge id)kSecClassKey         forKey:(__bridge id)kSecClass];
        [queryPublicKey setObject:keyTagData                        forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA   forKey:(__bridge id)kSecAttrKeyType];
        [queryPublicKey setObject:[NSNumber numberWithBool:YES]     forKey:(__bridge id)kSecReturnRef];

        // Get the key.
        resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        NSLog(@"getPublicKeyRef: result code: %d %@", (int)resultCode, publicKeyReference);
		
        if(resultCode != noErr)
        {
            publicKeyReference = NULL;
        }
    
    
    return publicKeyReference;
}

- (SecKeyRef) getPrivateKeyRef:(NSString *)keyTag {

	if(privateKey != nil && [privateKeyTag isEqualToString:keyTag]) return privateKey;

	privateKeyTag = keyTag;
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    NSData *keyTagData = [keyTag dataUsingEncoding:NSUTF8StringEncoding];


	NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
	
	// Set the private key query dictionary.
	[queryPrivateKey setObject:(__bridge id)kSecClassKey        forKey:(__bridge id)kSecClass];
	[queryPrivateKey setObject:keyTagData                       forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA  forKey:(__bridge id)kSecAttrKeyType];
	[queryPrivateKey setObject:[NSNumber numberWithBool:YES]    forKey:(__bridge id)kSecReturnRef];

	// Get the key.
	resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
	NSLog(@"getPrivateKey: result code: %d %@", (int)resultCode, privateKeyReference);
	
	if(resultCode != noErr)
	{
		privateKeyReference = NULL;
	}

	privateKey = privateKeyReference;
    
    return privateKey;
}

@end