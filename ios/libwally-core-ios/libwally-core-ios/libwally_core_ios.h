//
//  libwally_core_ios.h
//  libwally-core-ios
//
//  Created by isidoro carlo ghezzi on 11/8/16.
//  Copyright © 2016 isidoro carlo ghezzi. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "wally_bip39.h"
#import "wally_bip38.h"
#import "wordlist.h"
#include "aes.h"



@interface libwally_core_ios : NSObject
+ (NSString *) staticTest;
- (NSString *) objectTest;
@end
