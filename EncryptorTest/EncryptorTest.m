//
//  EncryptorTest.h
//  EncryptorTest
//
//  Created by Alexander Slavschik on 26.02.13.
//

#import "EncryptorTest.h"
#import "Encryptor.h"

@implementation EncryptorTest
{
    Encryptor *encryptor;
}
- (void)setUp
{
    [super setUp];
    
    NSBundle *bundle = [NSBundle bundleForClass:[Encryptor class]];
    NSString *publicKeyPath = [bundle pathForResource:@"key" ofType:@"pub"];
    NSString *privateKeyPath = [bundle pathForResource:@"key" ofType:@""];
    
    NSString *public_key = [[NSString alloc] initWithContentsOfFile:publicKeyPath encoding:NSUTF8StringEncoding error:nil];
    NSString *private_key = [[NSString alloc] initWithContentsOfFile:privateKeyPath encoding:NSUTF8StringEncoding error:nil];
    
    encryptor = [[Encryptor alloc] initWithPublicKey:public_key andPrivateKey:private_key];
    
}
- (void)testWrongCreation
{
    STAssertThrows([self wrongCreation], @"wrong initialisation should throw exception");
}
- (void) wrongCreation
{
    __unused Encryptor* encryptor = [[Encryptor alloc] init];
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
