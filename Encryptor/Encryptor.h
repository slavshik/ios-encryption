//
//  Created by Alexander Slavschik on 04.03.13.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@protocol Encryptor <NSObject>
@required
- (NSString *) encrypt:(NSString *)str error:(NSError **)e;
- (NSString *) decrypt:(NSString *)str error:(NSError **)e;
@end
