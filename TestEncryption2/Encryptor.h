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

- (NSString *) encrypt:(NSString *)str;
- (NSString *) decrypt:(NSString *)str;
@end