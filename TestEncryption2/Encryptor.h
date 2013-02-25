#import <UIKit/UIKit.h>
#import <Security/Security.h>

@interface Encryptor : NSObject
{
    SecKeyRef publicKey;
    SecKeyRef privateKey;
    NSData *publicTag;
    NSData *privateTag;
}
- (id)initWithPublicKey:(NSString *) public_key andPrivateKey:(NSString *) private_key;
- (void) encryptWithPublicKey:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer;
- (void) decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer;

- (NSString *) encrypt:(NSString *)str;
- (NSString *) decrypt:(NSString *)str;
@end