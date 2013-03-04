//
//  EncryptorTest.h
//  EncryptorTest
//
//  Created by Alexander Slavschik on 26.02.13.
//

#import "EncryptorTest.h"
#import "SymmetricEncryptor.h"

@implementation EncryptorTest
{
    SymmetricEncryptor *encryptor;
}
- (void)setUp
{
    [super setUp];
    NSString *public_key = @"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFhZ4yM1bdm+m6pQhrtACraeM9UvCd5ROteiyt4CJ+mU1eY/rmD4mkRJdnny23jKm1RgO91dAXOekEY1MdQ/Xfx7LZY9Vv4NXwGjGWsXvZJoZVLBKJhgeM2RLZmMKVuTbN6xyBb7/3cx0C2yYQ70DeEsAffLWFERbf8QdHe8iM1QIDAQAB-----END PUBLIC KEY-----";

    encryptor = [[SymmetricEncryptor alloc] initWithKey:public_key];
    
}
- (void)testWrongCreation
{
    STAssertThrows([self wrongCreation], @"wrong initialisation should throw exception");
}
- (void) wrongCreation
{
    __unused SymmetricEncryptor* encryptor = [[SymmetricEncryptor alloc] init];
}
- (void)testSimpleEncyption
{
    NSError *error = nil;
    NSString *encrypted = [encryptor encrypt:@"simple string for encrypt" error:&error];
    NSLog(@"encrypted %@", encrypted);
    STAssertNil(error, @"encrypt shouldn't return error");
}
- (void)testLargeEncyption
{
    NSError *error = nil;
    NSString *text = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce commodo vestibulum arcu sed rutrum. In hac habitasse platea dictumst. Nunc velit elit, congue eu lacinia id, dignissim sagittis neque. Morbi hendrerit lectus vel sem fermentum nec cursus neque blandit. Duis laoreet tincidunt venenatis. Ut eget neque elit. Proin erat lorem, aliquam sit amet pulvinar vitae, rhoncus eget nisi. Integer metus tellus, mattis at varius id, venenatis quis purus. Suspendisse quis dui non risus mollis vestibulum sit amet at dolor. Aenean vel nulla nulla, id fermentum nulla.";
    NSString *encrypted = [encryptor encrypt:text error:&error];
    NSLog(@"encrypted %@", encrypted);
    STAssertNil(error, @"encrypt shouldn't return error");
}

- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}
@end
