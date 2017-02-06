//
//  LibwallyCoreUnitTest.m
//  libwally-core-ios-example
//
//  Created by isidoro carlo ghezzi on 11/10/16.
//  Copyright © 2016 isidoro carlo ghezzi. All rights reserved.
//

#import "LibwallyCoreUnitTest.h"
#import "libwally-core-ios/libwally_core_ios.h"

@interface NSString (NSStringHexToBytes)
-(NSData*) hexToBytes ;
@end



@implementation NSString (NSStringHexToBytes)
-(NSData*) hexToBytes {
	NSMutableData* data = [NSMutableData data];
	int idx;
	for (idx = 0; idx+2 <= self.length; idx+=2) {
		NSRange range = NSMakeRange(idx, 2);
		NSString* hexStr = [self substringWithRange:range];
		NSScanner* scanner = [NSScanner scannerWithString:hexStr];
		unsigned int intValue;
		[scanner scanHexInt:&intValue];
		[data appendBytes:&intValue length:1];
	}
	return data;
}
@end


@interface LibwallyCoreUnitTest ()
@property (weak, nonatomic) UITextView *fDebugTextView;
@property (strong, nonatomic) NSDictionary *fLanguagesDictionary;
@property (strong, nonatomic) NSDictionary *fVectorsDictionary;
@end

@implementation LibwallyCoreUnitTest

- (instancetype)initWithDebugView:(UITextView *) theDebugView {
	self = [self init];
	if(self) {
		self.fDebugTextView = theDebugView;
		self.fLanguagesDictionary = @{
			@"en": @"english",
			@"es": @"spanish",
			@"fr": @"french",
			@"it": @"italian",
			@"jp": @"japanese",
			@"zhs": @"chinese_simplified",
			@"zht": @"chinese_traditional"
		};
		
		NSFileManager * aFileManager = [NSFileManager defaultManager];
		NSString* filePath = [[NSBundle mainBundle] pathForResource:@"vectors"
															 ofType:@"json"];
		NSData * aData = [aFileManager contentsAtPath:filePath];
		NSError *error;
		self.fVectorsDictionary = [NSJSONSerialization JSONObjectWithData:aData options:NSJSONReadingAllowFragments error:&error];
		NSAssert (nil != self.fVectorsDictionary, @"nil != self.fVectorsDictionary");
	}
	return self;
}

-(NSArray *) get_languages{
	char * aLanguages = NULL;
	const int aBip39_get_languages = bip39_get_languages (&aLanguages);
	NSLog (@"aBip39_get_languages: %@, aLanguages: %s", @(aBip39_get_languages), aLanguages);
	NSString * aLanguagesString = [NSString stringWithUTF8String:aLanguages];
	wally_free_string (aLanguages);
	NSArray * aLanguagesArray = [aLanguagesString componentsSeparatedByString: @" "];
	return aLanguagesArray;
}

-(void) test_all_langs{
	NSArray * aLanguagesArray = [self get_languages];
	for (NSString * aLanguage in aLanguagesArray){
		NSAssert (nil != self.fLanguagesDictionary [aLanguage], @"nil != self.fLanguagesDictionary [aLanguage]");
	}
	NSAssert (self.fLanguagesDictionary.allKeys.count == aLanguagesArray.count, @"self.fLanguagesDictionary.allKeys.count == aLanguagesArray.count");
}

-(const struct words *) get_wordlist:(NSString *) theLang{
	const struct words * aWords = NULL;
	const char * aCKey = [theLang cStringUsingEncoding:NSUTF8StringEncoding];
	const int aBip39_get_wordlist = bip39_get_wordlist (aCKey, &aWords);
	NSAssert (WALLY_OK == aBip39_get_wordlist, @"WALLY_OK == aBip39_get_wordlist");
	return aWords;
}

-(NSArray *) test_load_word_list{
	NSMutableArray * aLogArray = [[NSMutableArray alloc] init];

	NSArray * aLanguagesArray = [self get_languages];
	
	for (NSString * aKey in aLanguagesArray){
		const struct words * aWords = [self get_wordlist:aKey];
		for (size_t i = 0; i < aWords->len && i < 3; ++i){
			NSString * aString = [NSString stringWithUTF8String:aWords->indices [i]];
			NSString * aLog = [NSString stringWithFormat:@"%@/%@ - %@ - %@;", @(i+1), @(aWords->len), aKey, aString];
			[aLogArray addObject:aLog];
		}
	}
	return aLogArray;
}

- (void) test_bip39_vectors{
	// ported from 'src/test/test_bip39.py'
	const struct words * aWordList = [self get_wordlist:nil];
	for (NSArray * aCase in self.fVectorsDictionary [@"english"]){
		//NSLog (@"%@", aCase.description);
		NSString * aHexInputString = aCase [0];
		NSString  * aMenemonic = aCase [1];
		NSData * aBuf = [aHexInputString hexToBytes];
		char * aOutput = NULL;
		const void * aBufBytes = [aBuf bytes];
		const int aBip39_mnemonic_from_bytes = bip39_mnemonic_from_bytes (aWordList, aBufBytes, aBuf.length, &aOutput);
		NSAssert(WALLY_OK == aBip39_mnemonic_from_bytes, @"WALLY_OK == aBip39_mnemonic_from_bytes");
		NSString * aOutputString = [NSString stringWithUTF8String:aOutput];
		NSAssert (YES == [aMenemonic isEqualToString:aOutputString], @"YES == [aMenemonic isEqualToString:aOutputString]");
		NSData * aData = [aMenemonic dataUsingEncoding:NSUTF8StringEncoding];
		NSMutableData * aMutableData = [NSMutableData dataWithData:aData];
		const char aZero = 0;
		[aMutableData appendBytes:&aZero length:1];
		const int aBip39_mnemonic_validate = bip39_mnemonic_validate (aWordList, [aMutableData bytes]);
		NSAssert (WALLY_OK == aBip39_mnemonic_validate, @"0 == aBip39_mnemonic_validate");


		unsigned char * aOutBuf = malloc (aBuf.length);
		NSAssert (NULL != aOutBuf, @"NULL != aBytesOut");
		memset(aOutBuf, 0, aBuf.length);
		
		size_t aWritten = 0;
		const int aBip39_mnemonic_to_bytes = bip39_mnemonic_to_bytes (aWordList, aOutput, aOutBuf, aBuf.length, &aWritten);
		NSAssert(WALLY_OK == aBip39_mnemonic_to_bytes, @"WALLY_OK == aBip39_mnemonic_to_bytes");
		NSAssert (aBuf.length == aWritten, @"aHexInputData.length == aWritten");

		NSAssert (0 == memcmp (aBufBytes, aOutBuf, aWritten), @"0 == memcmp (aBufBytes, aOutBuf, aWritten)");
		wally_free_string (aOutput);
		free (aOutBuf);
		aOutBuf = NULL;
	}
}
-(void) test_288{
	// ported from 'src/test/test_bip39.py'
	const char * mnemonic = "panel jaguar rib echo witness mean please festival " \
		"issue item notable divorce conduct page tourist "    \
		"west off salmon ghost grit kitten pull marine toss " \
		"dirt oak gloom";
	NSLog (@"strlen (mnemonic): %@", @(strlen (mnemonic)));
	const int aBip39_mnemonic_validate = bip39_mnemonic_validate (NULL, mnemonic);
	NSAssert (WALLY_OK == aBip39_mnemonic_validate, @"WALLY_OK == aBip39_mnemonic_validate");

	unsigned char * aOutBuf = malloc (36);
	NSAssert (NULL != aOutBuf, @"NULL != aOutBuf");
	size_t aWritten = 0;
	const int aBip39_mnemonic_to_bytes = bip39_mnemonic_to_bytes (NULL, mnemonic, aOutBuf, 36, &aWritten);
	NSAssert (WALLY_OK == aBip39_mnemonic_to_bytes, @"WALLY_OK == aBip39_mnemonic_to_bytes");
	NSAssert (36 == aWritten, @"36 == aWritten");

	NSString * expectedString = @"9F8EE6E3A2FFCB13A99AA976AEDA5A2002ED" \
		"3DF97FCB9957CD863357B55AA2072D3EB2F9";
	NSData * expectedData = [expectedString hexToBytes];
	const char * expected = [expectedData bytes];
	NSAssert (0 == memcmp (expected, aOutBuf, aWritten), @"0 == memcmp (expected, aOutBuf, aWritten)");

	free (aOutBuf);
	aOutBuf = NULL;
}

//bip38: start
#define K_MAIN  0
#define K_TEST  7
#define K_COMP  256
#define K_EC    512
#define K_CHECK 1024
#define K_RAW   2048
#define K_ORDER 4096

- (void) test_bip38_vectors{
    NSLog(@"BIP38");
    
    NSMutableArray *cases = [NSMutableArray arrayWithObjects:
                             @[@"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",@"TestingOneTwoThree", @K_MAIN, @"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"],
                             @[@"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",@"Satoshi", @K_MAIN, @"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq"],
                             @[@"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",@"TestingOneTwoThree", @(K_MAIN + K_COMP), @"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo"],
                             @[@"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",@"Satoshi", @(K_MAIN + K_COMP + K_RAW), @"0142E00B76EA60B62F66F0AF93D8B5380652AF51D1A3902EE00726CCEB70CA636B5B57CE6D3E2F"],
                             @[@"3CBC4D1E5C5248F81338596C0B1EE025FBE6C112633C357D66D2CE0BE541EA18",@"jon", @(K_MAIN + K_COMP + K_RAW + K_ORDER), @"0142E09F8EE6E3A2FFCB13A99AA976AEDA5A2002ED3DF97FCB9957CD863357B55AA2072D3EB2F9"],  nil];
    
    //NSLog(@"%@",cases);
    
    for (id aCase in cases) {
        
        if([aCase isKindOfClass:[NSArray class]]){
            NSString* priv_key = aCase[0];
            NSString* passwd = aCase[1];
            
            int flags = [aCase[2] intValue];
            
            NSData * priv = [priv_key hexToBytes];
            NSData * pass = [passwd hexToBytes];
            char * aOutput = NULL;
            if (flags > K_RAW){
                //
                //
            }else{
#if 0
                //problem area
				// TODO: resolve link error:
				/*
				 Undefined symbols for architecture x86_64:
				 "_secp256k1_schnorr_verify", referenced from:
				 _wally_ec_sig_verify in liblibwally-core-ios.a(sign.o)
				 "_secp256k1_schnorr_sign", referenced from:
				 _wally_ec_sig_from_bytes in liblibwally-core-ios.a(sign.o)
				 ld: symbol(s) not found for architecture x86_64
				*/
                const int aBip38_mnemonic_from_bytes = bip38_from_private_key([priv bytes], priv.length, [pass bytes], pass.length, flags, &aOutput);
                
                NSAssert(WALLY_OK == aBip38_mnemonic_from_bytes, @"WALLY_OK == aBip38_mnemonic_from_bytes");

#endif
            }
            
        }
        
    }
}
//bip38: end



//AES: start

- (void) test_aes{
    
    NSMutableArray *cases =
    [NSMutableArray arrayWithObjects:
     @[@128,
       @"000102030405060708090a0b0c0d0e0f",
       @"00112233445566778899aabbccddeeff",
       @"69c4e0d86a7b0430d8cdb78070b4c55a" ],
     @[@192,
       @"000102030405060708090a0b0c0d0e0f1011121314151617",
       @"00112233445566778899aabbccddeeff",
       @"dda97ca4864cdfe06eaf70a0ec0d7191"],
     @[@256,
       @"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
       @"00112233445566778899aabbccddeeff",
       @"8ea2b7ca516745bfeafc49904b496089" ],
     /*AES-ECB test vectors from NIST sp800-38a.*/
     @[@128,
       @"2b7e151628aed2a6abf7158809cf4f3c",
       @"6bc1bee22e409f96e93d7e117393172a",
       @"3ad77bb40d7a3660a89ecaf32466ef97" ],
     @[@128,
       @"2b7e151628aed2a6abf7158809cf4f3c",
       @"ae2d8a571e03ac9c9eb76fac45af8e51",
       @"f5d3d58503b9699de785895a96fdbaaf" ],
     @[@128,
       @"2b7e151628aed2a6abf7158809cf4f3c",
       @"30c81c46a35ce411e5fbc1191a0a52ef",
       @"43b1cd7f598ece23881b00e3ed030688" ],
     @[@128,
       @"2b7e151628aed2a6abf7158809cf4f3c",
       @"f69f2445df4f9b17ad2b417be66c3710",
       @"7b0c785e27e8ad3f8223207104725dd4" ],
     @[@192,
       @"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
       @"6bc1bee22e409f96e93d7e117393172a",
       @"bd334f1d6e45f25ff712a214571fa5cc" ],
     @[@192,
       @"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
       @"ae2d8a571e03ac9c9eb76fac45af8e51",
       @"974104846d0ad3ad7734ecb3ecee4eef" ],
     @[@192,
       @"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
       @"30c81c46a35ce411e5fbc1191a0a52ef",
       @"ef7afd2270e2e60adce0ba2face6444e" ],
     @[@192,
       @"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
       @"f69f2445df4f9b17ad2b417be66c3710",
       @"9a4b41ba738d6c72fb16691603c18e0e" ],
     @[@256,
       @"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
       @"6bc1bee22e409f96e93d7e117393172a",
       @"f3eed1bdb5d2a03c064b5a7e3db181f8" ],
     @[@256,
       @"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
       @"ae2d8a571e03ac9c9eb76fac45af8e51",
       @"591ccb10d410ed26dc5ba74a31362870" ],
     @[@256,
       @"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
       @"30c81c46a35ce411e5fbc1191a0a52ef",
       @"b6ed21b99ca6f4f9f153e7b1beafed1d" ],
     @[@256,
       @"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
       @"f69f2445df4f9b17ad2b417be66c3710",
       @"23304b7a39f9f3ff067d8d8f9e24ecc7" ],
     nil];

    
    for (id aCase in cases) {
     
        if([aCase isKindOfClass:[NSArray class]]){
            
            NSInteger keyType = [[aCase objectAtIndex:0] integerValue];
            //int keyType = aCase[0];
            NSString* key = aCase[1];
            NSString* plain = aCase[2];
            NSString* cypher = aCase[3];
            
            [self aes_enc_dec:keyType key:key plain:plain cypher:cypher];
            
        }//if
        
    }//for
}

- (void) aes_enc_dec:(NSInteger)type key:(NSString*) key plain:(NSString*) plain cypher:(NSString*) cypher{
 
    unsigned char *charKey = (unsigned char *) [key UTF8String];
    unsigned char *charPlain = (unsigned char *) [plain UTF8String];
    //unsigned char *charCypher = (unsigned char *) [cypher UTF8String];
    
    NSData * keyData = [key hexToBytes];
    NSData * plainData = [plain hexToBytes];
    NSData * cypherData = [cypher hexToBytes];
    
    NSString* out_buf = [@"" stringByPaddingToLength: 2*cypherData.length withString:@"00" startingAtIndex:0];
    unsigned char *charOut = (unsigned char *) [out_buf UTF8String];
    
    NSData * outData = [out_buf hexToBytes];
    int enc = wally_aes(charKey, keyData.length, charPlain, plainData.length, AES_FLAG_ENCRYPT, charOut, outData.length);
    
    NSAssert (WALLY_OK == enc, @"WALLY_OK == wally_aes, ENCRYPT");
    
    /*if(WALLY_OK == enc)
        NSLog(@"AES%ld ENCRYPT: %d",(long)type, enc);*/
    
    
    int dec = wally_aes(charKey, keyData.length, charPlain, plainData.length, AES_FLAG_DECRYPT, charOut, outData.length);
    NSAssert (WALLY_OK == dec, @"WALLY_OK == wally_aes, DECRYPT");
    
    /*if(WALLY_OK == dec)
        NSLog(@"AES%ld DECRYPT: %d",(long)type, dec);*/

    
}

//AES: end


//MNEMONIC: start
#define LEN  ((int) 16)
#define PHRASES (int)(LEN * 8 / 11) //11 bits per phrase : 11
#define PHRASES_BYTES (int)(PHRASES * 11 + 7) / 8 // 8 # Bytes needed to store : 16

- (void) test_mnemonic{
    
    if(LEN == PHRASES_BYTES){
        
        size_t written = LEN;
        NSString *phrase = @"";
        unsigned char *buffer_out = (unsigned char *)calloc(LEN, sizeof(unsigned char));

        //reading file
        NSString* filePath = [[NSBundle mainBundle] pathForResource:@"english" ofType:@"txt"];
        NSString *fileContents = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
        
        NSArray* words_list = [fileContents componentsSeparatedByCharactersInSet: [NSCharacterSet newlineCharacterSet]];
        
        NSString *wordsString = [words_list componentsJoinedByString:@" "];
        const struct words * w = NULL;
        w = wordlist_init ([wordsString UTF8String]);
        

        for (int i = 0; i < (words_list.count - PHRASES); i++)
        {
            phrase = [self phrase_building:i end: (i + PHRASES) wordsList:words_list];
            
            const char *mnemonic = (const char *) [phrase UTF8String];
            
            int ret = mnemonic_to_bytes(w, mnemonic, buffer_out, sizeof(buffer_out), &written);
            NSAssert (WALLY_OK == ret, @"WALLY_OK == mnemonic_to_bytes");
            
            /*if( ret == WALLY_OK){
                NSLog(@"Success");
            }else if( ret == WALLY_ERROR){
                NSLog(@"General error");
            }else if( ret == WALLY_EINVAL){
                NSLog(@"Invalid argument");
            }else if( ret == WALLY_ENOMEM){
                NSLog(@"malloc() failed");
            }*/
            
        }//for
    }//if
}

- (NSString *) phrase_building: (int)start end: (int)end wordsList: (NSArray*) wl{
    
    NSString *phrase = @"";
    for (int i = start; i <end; i++){
        phrase = [phrase stringByAppendingString:[wl objectAtIndex: i] ];
        phrase = [phrase stringByAppendingString:@" "];
    }
    
    return phrase;
}


//MNEMONIC: end

//scrypt: start
- (void) test_scrypt{
    
    NSMutableArray *cases =
    [NSMutableArray arrayWithObjects:
     @[@"",@"",@16,@1,@1,@64,
       @"77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97 \
       f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42 \
       fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17 \
       e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06"],
     @[@"password",@"NaCl",@1024, @8, @16, @64,
       @"fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe \
       7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62 \
       2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da \
       c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40"],
     @[@"pleaseletmein", @"SodiumChloride",@16384, @8, @1, @64,
       @"70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb \
       fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2 \
       d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9 \
       e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87"],
     @[@"pleaseletmein", @"SodiumChloride",@1048576, @8, @1, @64,
       @"21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81 \
       ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47 \
       8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3 \
       37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4"],nil];
    
    
    
    for (id aCase in cases) {
        
        if([aCase isKindOfClass:[NSArray class]]){
            
            NSString* passwd    = aCase[0];
            NSInteger length    = [[aCase objectAtIndex:5] integerValue];
            NSString* expected  = [aCase[6] stringByReplacingOccurrencesOfString:@" " withString:@""];
            
            if([expected length] == (length*2)){
                
                uint32_t cost = (uint32_t) [[aCase objectAtIndex:2] integerValue];
                uint32_t block = (uint32_t) [[aCase objectAtIndex:3] integerValue];
                uint32_t parallelism = (uint32_t) [[aCase objectAtIndex:4] integerValue];
                
                NSData * expectedData = [expected hexToBytes];
                NSString* out_buf = [@"" stringByPaddingToLength: expectedData.length withString:@"0" startingAtIndex:0];
                unsigned char *pass = (unsigned char *) [passwd UTF8String];
                unsigned char *salt = (unsigned char *) [aCase[1] UTF8String];
                unsigned char *outBuf = (unsigned char *) [out_buf UTF8String];
                
                int ret = wally_scrypt(pass, sizeof(pass), salt, sizeof(salt), cost, block, parallelism, outBuf, sizeof(outBuf));
                NSAssert (WALLY_OK == ret, @"WALLY_OK == wally_scrypt");
                
                /*if( ret == WALLY_OK){
                    NSLog(@"Success");
                }else if( ret == WALLY_ERROR){
                    NSLog(@"General error");
                }else if( ret == WALLY_EINVAL){
                    NSLog(@"Invalid argument");
                }else if( ret == WALLY_ENOMEM){
                    NSLog(@"malloc() failed");
                }*/
            }
        }//if
        
    }//for
}
//scrypt: end

//hmac: start
- (void) test_hmac{
    
    NSMutableArray *cases =
    [NSMutableArray arrayWithObjects:
     
     @[@"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", @"4869205468657265",
      
      @"b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7",
      @"87aa7cdea5ef619d4ff0b4241a1d6cb0 2379f4e2ce4ec2787ad0b30545e17cde\
      daa833b7d6b8a702038b274eaea3f4e4 be9d914eeb61f1702e696c203a126854"],
     
     @[@"4a656665", @"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      
      @"5bdcc146bf60754e6a042426089575c7 5a003f089d2739839dec58b964ec3843",
      @"164b7a7bfcf819e2e395fbe73b56e0a3 87bd64222e831fd610270cd7ea250554\
      9758bf75c05a994a6d034f65f8f0e6fd caeab1a34d4a6b4b636e070a38bce737"],
     
     @[@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      @"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
      dddddddddddddddddddddddddddddddddddd",
      
      @"773ea91e36800e46854db8ebd09181a7 2959098b3ef8c122d9635514ced565fe",
      @"fa73b0089d56a284efb0f0756c890be9 b1b5dbdd8ee81a3655f83e33b2279d39\
      bf3e848279a722c806b485a47e67c807 b946a337bee8942674278859e13292fb"],
     
     @[@"0102030405060708090a0b0c0d0e0f10111213141516171819",
      @"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
      cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      
      @"82558a389a443c0ea4cc819899f2083a 85f0faa3e578f8077a2e3ff46729665b",
      @"b0ba465637458c6990e5a8c5f61d4af7 e576d97ff94b872de76f8050361ee3db\
      a91ca5c11aa25eb4d679275cc5788063 a5f19741120c4f2de2adebeb10a298dd"],
     
     @[@"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      @"546573742057697468205472756e636174696f6e",
      
      @"a3b6167473100ee06e0c796c2955552b",
      @"415fad6271580a531d4179bc891d87a6"],
     
     @[@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      aaaaaa",
      @"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a\
      65204b6579202d2048617368204b6579204669727374",
      
      @"60e431591ee0b67f0d8a26aacbf5b77f 8e0bc6213728c5140546040f0ee37f54",
      @"80b24263c7c1a3ebb71493c1dd7be8b4 9b46d1f41b4aeec1121b013783f8f352\
      6b56d037e05f2598bd0fd2215d6a1e52 95e64f73f63f0aec8b915a985d786598"],
     
     @[@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      aaaaaa",
      @"5468697320697320612074657374207573696e672061206c6172676572207468\
      616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074\
      68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565\
      647320746f20626520686173686564206265666f7265206265696e6720757365\
      642062792074686520484d414320616c676f726974686d2e",
      
      @"9b09ffa71b942fcb27635fbcd5b0e944 bfdc63644f0713938a7f51535c3a35e2",
      @"e37b6a775dc87dbaa4dfa9f96e5e3ffd debd71f8867289865df5a32d20cdc944\
      b6022cac3c4982b10d5eeb55c3e4de15 134676fb6de0446065c97440fa8c6a58"]
     ,nil];
    
    for (id aCase in cases) {
        
        if([aCase isKindOfClass:[NSArray class]]){
            
            //NSString* key    = aCase[0];
            unsigned char *key = (unsigned char *) [aCase[0] UTF8String];
            //NSString* msg  = aCase[1];
            unsigned char *msg = (unsigned char *) [aCase[1] UTF8String];
            
            NSData * keyData = [aCase[0] hexToBytes];
            NSData * msgData = [aCase[1] hexToBytes];
            
            //NSString* s256  = aCase[2];
            //NSString* sha512  = aCase[3];
            
            NSString* out_buf = [@"" stringByPaddingToLength: 32 withString:@" " startingAtIndex:0];
            unsigned char *outBuff = (unsigned char *) [out_buf UTF8String];
            NSData * outData = [out_buf hexToBytes];
            
            int ret= wally_hmac_sha256(key, keyData.length, msg, msgData.length, outBuff, outData.length);
            NSLog(@"%d",ret);
            //NOTE: how to pass aCase[2] withnwally_hmac_sha256???
            
        }
    }
    
}
//hmac: end


//hex: start
- (void) test_hex{
    
    //int wally_base58_from_bytes(const unsigned char *bytes_in, size_t len_in,uint32_t flags, char **output)
    
    
    //to
    /*NSString* buffStr = [@"" stringByPaddingToLength: 4 withString:@"00" startingAtIndex:0];
    unsigned char *buff = (unsigned char *) [buffStr UTF8String];
    NSData * buffData = [buffStr hexToBytes];
    size_t written =  4;
    for(int i=0; i<256; i++){
        NSString* hexUpper = [@"" stringByPaddingToLength: 4 withString:[NSString stringWithFormat:@"%02X", i] startingAtIndex:0];
        NSLog(@"%@",hexUpper);
        const char *hex = (const char *) [hexUpper UTF8String];
        int ret = wally_hex_to_bytes(hex, buff, buffData.length, &written);
    }*/
    
    //from

    /*NSString* outChar = [@"" stringByPaddingToLength: 8 withString:@" " startingAtIndex:0];
    const char *ochar = (const char *) [outChar UTF8String];
    
    for(int i=0; i<256; i++){
        NSString* hexStr = [@"" stringByPaddingToLength: 8 withString:[NSString stringWithFormat:@"%02x", i] startingAtIndex:0];
        NSLog(@"%@",hexStr);
        const char *hex = (const char *) [hexStr UTF8String];
        NSData * bufData = [hexStr hexToBytes];
        
        //int ret = wally_hex_to_bytes(hex, buff,buffData.length, &written);
        //NSLog(@"%d",ret);
        //int wally_hex_to_bytes(const char *hex, unsigned char *bytes_out, size_t len, size_t *written)
    
        //NSString* buffStr = [@"" stringByPaddingToLength: 4 withString:@"00" startingAtIndex:0];
        //unsigned char *buff = (unsigned char *) [buffStr UTF8String];
        
        int ret = wally_hex_from_bytes(hex, bufData.length, ochar);
        NSLog(@"%d",ret);
    }*/
    
}
//hex: end

//base58: start
- (void) test_base58{
    
    //reading file
    NSString* filePath = [[NSBundle mainBundle] pathForResource:@"address_vectors" ofType:@"txt"];
    NSString *fileContents = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    NSArray* lines = [fileContents componentsSeparatedByCharactersInSet: [NSCharacterSet newlineCharacterSet]];
    
    //preparing test cases
    NSMutableArray *tempCase = [NSMutableArray array];
    NSMutableArray *cases = [NSMutableArray array];
    
    for(NSString* line in lines){
        NSString * newString = [line stringByReplacingOccurrencesOfString:@" " withString:@""];
        if(newString.length != 0){
            //NSLog(@"%@",aCase);
            [tempCase addObject: newString];
        }else{
            NSMutableDictionary *dict = [NSMutableDictionary dictionary];
            [dict setObject:[tempCase objectAtIndex:4] forKey:@"ripemd_network"];
            [dict setObject:[tempCase objectAtIndex:8] forKey:@"checksummed"];
            [dict setObject:[tempCase objectAtIndex:9] forKey:@"base58"];
            [cases addObject: dict];
        }
    }
    
    //for decode
    NSString* bufStr = [@"" stringByPaddingToLength: 1024 withString:@"00" startingAtIndex:0];
    NSData * bufData = [bufStr hexToBytes];
    unsigned char *buf = (unsigned char *) [bufStr UTF8String];
    
    for(NSMutableDictionary* aCase in cases){
        NSString* checksummedStr = [aCase objectForKey:@"checksummed"];
        unsigned char *checksummed = (unsigned char *) [checksummedStr UTF8String];
        NSData * buffData = [checksummedStr hexToBytes];
        char *output = (char *) [[aCase objectForKey:@"base58"] UTF8String];
        uint32_t flags = 0;
        
        // Checksummed should match directly in base 58
        int ret = wally_base58_from_bytes(checksummed, buffData.length, flags, &output);
        NSAssert (WALLY_OK == ret, @"WALLY_OK == wally_base58 ENCODE");
        //NSLog(@"%d",ret);
        
        //Decode it and make sure it matches checksummed again
        char *str_in = (char *) [[aCase objectForKey:@"base58"] UTF8String];
        size_t written = bufData.length;
        int retD = wally_base58_to_bytes(str_in, flags, buf, bufData.length, &written);
        NSAssert (WALLY_OK == retD, @"WALLY_OK == wally_base58 DECODE");
        //NSLog(@"%d",retD);
        
    }

}
//base58: end

-(void) test{
	self.fDebugTextView.text = @"";
	NSMutableArray * aLogArray = [[NSMutableArray alloc] init];
	[aLogArray addObject: @"begin test…"];
	[aLogArray addObject:[libwally_core_ios staticTest]];
	libwally_core_ios * aObject = [[libwally_core_ios alloc] init];
	[aLogArray addObject: [aObject objectTest]];
	self.fDebugTextView.text = [aLogArray componentsJoinedByString:@";\n"];
	
	// Testing wally_bip39
	[aLogArray addObject:@"testing wally_bip39 (ported from 'src/test/test_bip39.py')"];
	[self test_all_langs];
	[aLogArray addObjectsFromArray:[self test_load_word_list]];
	[self test_bip39_vectors];
	[self test_288];
	NSString * testOK = @"#libwally-core-ios.bip39 OK";
	[aLogArray addObject:testOK];
	NSLog (@"%@", testOK);
    //mnemonic_to_bytes

    [aLogArray addObject:@"\n"];
    [aLogArray addObject:@"testing aes (ported from 'src/test/test_aes.py')"];
    [self test_aes];
    testOK = @"#libwally-core-ios.aes OK";
    [aLogArray addObject:testOK];
    
    [aLogArray addObject:@"\n"];
    [aLogArray addObject:@"testing mnemonic (ported from 'src/test/test_mnemonic.py')"];
    [self test_mnemonic];
    testOK = @"#libwally-core-ios.mnemonic OK";
    [aLogArray addObject:testOK];

    [aLogArray addObject:@"\n"];
    [aLogArray addObject:@"testing scrypt (ported from 'src/test/test_scrypt.py')"];
    [self test_scrypt];
    testOK = @"#libwally-core-ios.scrypt OK";
    [aLogArray addObject:testOK];

    [aLogArray addObject:@"\n"];
    [aLogArray addObject:@"testing scrypt (ported from 'src/test/test_base58.py')"];
    [self test_base58];
    testOK = @"#libwally-core-ios.base58 OK";
    [aLogArray addObject:testOK];
    
    
	self.fDebugTextView.text = [aLogArray componentsJoinedByString:@"\n"];
}
@end
