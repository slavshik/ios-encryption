//
//  ViewController.m
//  TestEncryption2
//
//  Created by Alexander Slavschik on 25.02.13.
//  Copyright (c) 2013 Monterosa Productions Ltd. All rights reserved.
//

#import "ViewController.h"
#import "Encryptor.h"

@interface ViewController ()
{
    Encryptor *encryptor;
}
@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    [_testBtn addTarget:self action:@selector(test) forControlEvents:UIControlEventTouchUpInside];
    
    NSString *public_key = @"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFhZ4yM1bdm+m6pQhrtACraeM9UvCd5ROteiyt4CJ+mU1eY/rmD4mkRJdnny23jKm1RgO91dAXOekEY1MdQ/Xfx7LZY9Vv4NXwGjGWsXvZJoZVLBKJhgeM2RLZmMKVuTbN6xyBb7/3cx0C2yYQ70DeEsAffLWFERbf8QdHe8iM1QIDAQAB-----END PUBLIC KEY-----";
    NSString *private_key = @"-----BEGIN RSA PRIVATE KEY-----MIICXAIBAAKBgQDFhZ4yM1bdm+m6pQhrtACraeM9UvCd5ROteiyt4CJ+mU1eY/rmD4mkRJdnny23jKm1RgO91dAXOekEY1MdQ/Xfx7LZY9Vv4NXwGjGWsXvZJoZVLBKJhgeM2RLZmMKVuTbN6xyBb7/3cx0C2yYQ70DeEsAffLWFERbf8QdHe8iM1QIDAQABAoGAdVGt6sdPmwUWSIPpgn9Bvo6AKFZxEHeVvn5It2XfVy6bI6tixO8JpAYRn7yOHO1xh3f0lPbASGtfGfoczc8l5B8IxHK98uNR2ajUXTThZaFG45IuK/QfBbPAmBwYpbjsiEq38vec8JqZPvtthIT0sgTb2s/y7lWw0DHkfcFKNakCQQDycdFVgJmcQlm4R1iEiJievtNlwN53MJlKJc+WVWgx71iiGPS5q9KalcC80HeTt6+wRiJTGOxGleVb58P7y6iHAkEA0JDPDavO4W+vnnIaBcNRjy5fSw/6/OERPWnxQ4r1Mj4E8vAf3ygYiZji4ppCR8+wWp/6N6/xeo0lcau6jCDiwwJAUA7Hik1p7BB44gIlN7aHdzwaQGp8y6zvoW106/aN7pdTlEtbXIhhhgxXVcIdCllImZO/N+Nt+iz7TOrua5IntwJBAJ7l1Hmr7Z/fQUNL1vuRBTA6uisr76J9rm7FqiQ1V/2BNrAHtaCEob0jF6hgsiKX3toMi8ulZipiIqbpmORtoZUCQErSpG0hQlj97PtM2bN8C309oEkJ9bYiR7qVvWaU73TKuFbEHR+TBy7ZpeSqHjYZ91x6nWVylp3h1I3BOhedGRk=-----END RSA PRIVATE KEY-----";
    
    encryptor = [[Encryptor alloc] initWithPublicKey:public_key andPrivateKey:private_key];
    [self test];
}
-(void)test
{
    int tests = 100;
    int stats = tests;
    BOOL pass = YES;
    for (int i = 0; i < tests; i++) {
        pass = [self validateString:@"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."];
        if(pass){
            stats--;
        }else{
            break;
        }
    }
    NSLog(@"%i out of %i lost", stats, tests);
}
- (BOOL) validateString:(NSString *) inputString
{
    NSString *encrypted = [encryptor encrypt:inputString];
    NSLog(@"encrypted:\n%@", encrypted);
    NSString *decrypted = [encryptor decrypt:encrypted];
    NSLog(@"decrypted:\n%@",decrypted);
    return [decrypted isEqualToString:inputString];
}

@end
