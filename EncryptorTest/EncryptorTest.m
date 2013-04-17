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
    Encryptor *decryptor;
	NSString *public_key;
    NSString *private_key;
}
- (void)setUp
{
    [super setUp];
    
    NSBundle *bundle = [NSBundle bundleForClass:[Encryptor class]];
    NSString *publicKeyPath = [bundle pathForResource:@"key" ofType:@"pub"];
    NSString *privateKeyPath = [bundle pathForResource:@"key" ofType:@""];
    
    public_key = [[NSString alloc] initWithContentsOfFile:publicKeyPath encoding:NSUTF8StringEncoding error:nil];
    private_key = [[NSString alloc] initWithContentsOfFile:privateKeyPath encoding:NSUTF8StringEncoding error:nil];

	//public_key = @"";
	//private_key = @"";
	
	if(public_key == nil) STFail(@"Public key is nil");
	if(private_key == nil) STFail(@"Private key is nil");
	
	encryptor = [[Encryptor alloc] init];
    decryptor = [[Encryptor alloc] init];
}
- (void)testSimpleEncyption
{
    NSError *error = nil;
    NSString *encrypted = [encryptor encrypt:@"simple string for encrypt" withPublicKey:public_key];
    NSLog(@"encrypted %@", encrypted);
    STAssertNil(error, @"encrypt shouldn't return error");
}
- (void)testLargeEncyption
{
    NSError *error = nil;
    NSString *text = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce commodo vestibulum arcu sed rutrum. In hac habitasse platea dictumst. Nunc velit elit, congue eu lacinia id, dignissim sagittis neque. Morbi hendrerit lectus vel sem fermentum nec cursus neque blandit. Duis laoreet tincidunt venenatis. Ut eget neque elit. Proin erat lorem, aliquam sit amet pulvinar vitae, rhoncus eget nisi. Integer metus tellus, mattis at varius id, venenatis quis purus. Suspendisse quis dui non risus mollis vestibulum sit amet at dolor. Aenean vel nulla nulla, id fermentum nulla.";
    NSString *encrypted = [encryptor encrypt:text withPublicKey:public_key];
    NSLog(@"encrypted %@", encrypted);
    STAssertNil(error, @"encrypt shouldn't return error");
}
- (void)testEncryptionAndDecryption
{
    NSError *error = nil;
    NSString *text = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce commodo vestibulum arcu sed rutrum. In hac habitasse platea dictumst. Nunc velit elit, congue eu lacinia id, dignissim sagittis neque. Morbi hendrerit lectus vel sem fermentum nec cursus neque blandit. Duis laoreet tincidunt venenatis. Ut eget neque elit. Proin erat lorem, aliquam sit amet pulvinar vitae, rhoncus eget nisi. Integer metus tellus, mattis at varius id, venenatis quis purus. Suspendisse quis dui non risus mollis vestibulum sit amet at dolor. Aenean vel nulla nulla, id fermentum nulla.";
    NSString *encrypted = [encryptor encrypt:text withPublicKey:public_key];
    NSLog(@"encrypted %@", encrypted);
    STAssertNil(error, @"encrypt shouldn't return error");
    
    NSString *decrypted = [decryptor decrypt:encrypted withPrivateKey:private_key];
    NSLog(@"decrypted %@", decrypted);
    STAssertNil(error, @"decrypt shouldn't return error");
    STAssertTrue([decrypted isEqualToString:text], @"Wrong decryption");
}

- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}
@end
