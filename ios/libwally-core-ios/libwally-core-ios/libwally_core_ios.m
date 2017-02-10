//
//  libwally_core_ios.m
//  libwally-core-ios
//
//  Created by isidoro carlo ghezzi on 11/8/16.
//  Copyright © 2016 isidoro carlo ghezzi. All rights reserved.
//

#import "libwally_core_ios.h"
#import "pbkdf2.c"
#import "hmac.c"
#import "hex.c"





@implementation libwally_core_ios
+(NSString *) staticTest{
	NSDate * aDate = [[NSDate alloc] init];
	return aDate.description;
}

- (NSString *) objectTest{
	return self.description;
}

+ (int) hmac:(const unsigned char *)key key_len: (size_t) key_len bytes_in:
(const unsigned char *)bytes_in len_in: (size_t) len_in bytes_out:
(unsigned char *)bytes_out len: (size_t) len{
    int ret = 0;
    
    ret = wally_hmac_sha256(key, key_len, bytes_in, len_in, bytes_out, len);
    //TODO: same way have to check 512
    //wally_hmac_sha512(const unsigned char *key, size_t key_len, const unsigned char *bytes_in, <#size_t len_in#>, unsigned char *bytes_out, size_t len)
    
    //wally_hex_from_bytes(const unsigned char *bytes_in, size_t len_in, char **output)
    
    return ret;
}

+ (int) pbkdf2:(const unsigned char *)pass pass_len: (size_t)pass_len salt_in_out: (unsigned char *)salt_in_out salt_len: (size_t) salt_len flags: (uint32_t) flags cost: (uint32_t) cost bytes_out: (unsigned char *)bytes_out len: (size_t) len type: (size_t) type{
    
    int ret = 0;
    if(type == 256){
        
        ret = wally_pbkdf2_hmac_sha256(pass, pass_len, salt_in_out, salt_len, flags, cost, bytes_out, len);
    }
    else
        ret = wally_pbkdf2_hmac_sha512(pass, pass_len, salt_in_out, salt_len, flags, cost, bytes_out, len);

    return ret;
}

//hex


+ (int) hex_encode_test:(const unsigned char *)bytes_in len_in: (size_t) len_in output: (char **)output{    
    return wally_hex_from_bytes(bytes_in, len_in, output);
}

+ (int) doHash:(size_t) type bytes_in:(const unsigned char *)bytes_in len_in:(size_t)len_in bytes_out:(unsigned char *)bytes_out len: (size_t) len{
    
    if(type == 256){
        return wally_sha256(bytes_in, len_in, bytes_out, len);
    }
    else if(type == 512)
        return wally_sha512(bytes_in, len_in, bytes_out, len);
    else
        return wally_sha256d(bytes_in, len_in, bytes_out, len);
}
/*+ (int) doHash:(NSString*)key values: (NSArray*)values{

    //offset = 0
    NSString* buffStr = [@"" stringByPaddingToLength: 32 withString:@" " startingAtIndex:0];
    NSData * buffData = [buffStr hexToBytes];
    unsigned char *bytes_out = (unsigned char *) [buffStr UTF8String];
    size_t len = buffData.length;
    
    //in_bytes, in_bytes_len = make_cbuffer(hex_in)
    const unsigned char *bytes_in = (const unsigned char *) [key UTF8String];
    NSData * inButesData = [key hexToBytes];
    size_t len_in = inButesData.length;
    
    int ret = wally_sha256(bytes_in, len_in, bytes_out, len);
    
    //offset = 1
    
    
    //wally_sha512(const unsigned char *bytes_in, size_t len_in, unsigned char *bytes_out, size_t len)
    
    //wally_sha256d(const unsigned char *bytes_in, size_t len_in, unsigned char *bytes_out, size_t len)
    
    return 0;
}*/

@end
