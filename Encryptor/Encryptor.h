//
//  Created by Alexander Slavschik on 25.02.13.
//

#import <UIKit/UIKit.h>
#import <Security/Security.h>

@interface Encryptor : NSObject
- (NSString *) encrypt:(NSString *)str withPublicKey:(NSString *)public_key;
- (NSString *) decrypt:(NSString *)str withPrivateKey:(NSString *) private_key;

- (NSString *) convertTypeOfFile:(NSString*)type  andPathFile:(NSString*)path;


- (NSData *) encryptData:(NSData *)data withPublicKey:(NSString *)public_key;
- (NSData *) decryptData:(NSData *)data withPrivateKey:(NSString *) private_key;
@end