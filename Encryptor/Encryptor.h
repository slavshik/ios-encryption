//
//  Created by Alexander Slavschik on 25.02.13.
//

#import <UIKit/UIKit.h>
#import <Security/Security.h>

@interface Encryptor : NSObject

- (id)initWithPublicKey:(NSString *) public_key andPrivateKey:(NSString *) private_key;
- (NSString *) encrypt:(NSString *)str error:(NSError **)e;
- (NSString *) decrypt:(NSString *)str error:(NSError **)e;
@end