//
//  Created by Alexander Slavschik on 25.02.13.
//

#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import "Encryptor.h"

@interface SymmetricEncryptor : NSObject <Encryptor>

- (id)initWithKey:(NSString *) key;
- (NSString *) encrypt:(NSString *)str error:(NSError **)e;
- (NSString *) decrypt:(NSString *)str error:(NSError **)e;
@end