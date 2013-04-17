//
//  Created by Alexander Slavschik on 25.02.13.
//

#import <UIKit/UIKit.h>
#import <Security/Security.h>

@interface Encryptor : NSObject
- (NSString *) encrypt:(NSString *)str withPublicKey:(NSString *)public_key;
- (NSString *) decrypt:(NSString *)str withPrivateKey:(NSString *) private_key;
@end