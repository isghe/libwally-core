//
//  libwally_core_ios.m
//  libwally-core-ios
//
//  Created by isidoro carlo ghezzi on 11/8/16.
//  Copyright © 2016 isidoro carlo ghezzi. All rights reserved.
//

#import "libwally_core_ios.h"

@implementation libwally_core_ios
+(NSString *) staticTest{
	NSDate * aDate = [[NSDate alloc] init];
	return aDate.description;
}

- (NSString *) objectTest{
	return self.description;
}

@end
