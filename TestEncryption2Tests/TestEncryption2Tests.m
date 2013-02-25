//
//  TestEncryption2Tests.m
//  TestEncryption2Tests
//
//  Created by Alexander Slavschik on 25.02.13.
//  Copyright (c) 2013 Monterosa Productions Ltd. All rights reserved.
//

#import "TestEncryption2Tests.h"
#import "Encryptor.h"

@implementation TestEncryption2Tests
{
    Encryptor *encryptor;
}
- (void)setUp
{
    [super setUp];
    
    NSString *public_key = @"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFhZ4yM1bdm+m6pQhrtACraeM9UvCd5ROteiyt4CJ+mU1eY/rmD4mkRJdnny23jKm1RgO91dAXOekEY1MdQ/Xfx7LZY9Vv4NXwGjGWsXvZJoZVLBKJhgeM2RLZmMKVuTbN6xyBb7/3cx0C2yYQ70DeEsAffLWFERbf8QdHe8iM1QIDAQAB-----END PUBLIC KEY-----";
    NSString *private_key = @"-----BEGIN RSA PRIVATE KEY-----MIICXAIBAAKBgQDFhZ4yM1bdm+m6pQhrtACraeM9UvCd5ROteiyt4CJ+mU1eY/rmD4mkRJdnny23jKm1RgO91dAXOekEY1MdQ/Xfx7LZY9Vv4NXwGjGWsXvZJoZVLBKJhgeM2RLZmMKVuTbN6xyBb7/3cx0C2yYQ70DeEsAffLWFERbf8QdHe8iM1QIDAQABAoGAdVGt6sdPmwUWSIPpgn9Bvo6AKFZxEHeVvn5It2XfVy6bI6tixO8JpAYRn7yOHO1xh3f0lPbASGtfGfoczc8l5B8IxHK98uNR2ajUXTThZaFG45IuK/QfBbPAmBwYpbjsiEq38vec8JqZPvtthIT0sgTb2s/y7lWw0DHkfcFKNakCQQDycdFVgJmcQlm4R1iEiJievtNlwN53MJlKJc+WVWgx71iiGPS5q9KalcC80HeTt6+wRiJTGOxGleVb58P7y6iHAkEA0JDPDavO4W+vnnIaBcNRjy5fSw/6/OERPWnxQ4r1Mj4E8vAf3ygYiZji4ppCR8+wWp/6N6/xeo0lcau6jCDiwwJAUA7Hik1p7BB44gIlN7aHdzwaQGp8y6zvoW106/aN7pdTlEtbXIhhhgxXVcIdCllImZO/N+Nt+iz7TOrua5IntwJBAJ7l1Hmr7Z/fQUNL1vuRBTA6uisr76J9rm7FqiQ1V/2BNrAHtaCEob0jF6hgsiKX3toMi8ulZipiIqbpmORtoZUCQErSpG0hQlj97PtM2bN8C309oEkJ9bYiR7qVvWaU73TKuFbEHR+TBy7ZpeSqHjYZ91x6nWVylp3h1I3BOhedGRk=-----END RSA PRIVATE KEY-----";
    
    encryptor = [[Encryptor alloc] initWithPublicKey:public_key andPrivateKey:private_key];
}
- (BOOL) validateString:(NSString *) inputString
{
    NSString *encrypted = [encryptor encrypt:inputString];
    NSString *decrypted = [encryptor decrypt:encrypted];
    return [inputString isEqualToString:decrypted];
}

- (void)test1
{
    STAssertTrue([self validateString:@"test test test!"], @"Strings should be equals");
    STAssertTrue([self validateString:@"Hello world!"], @"Strings should be equals");
    STAssertTrue([self validateString:@"Third string!"], @"Strings should be equals");
    STAssertTrue([self validateString:@"First strign!"], @"Strings should be equals");
    STAssertTrue([self validateString:@"Second string!"], @"Strings should be equals");
}

- (void)tearDown
{
    encryptor = nil;
    [super tearDown];
}
@end
