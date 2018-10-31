#include <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>


// iOS中对文件进行Hash, 主要用到<CommonCrypto/CommonDigest.h>库。
// 它是一个加密算法库，里面有许多不同的加密算法如MD5，SHA1等等都有.


// 计算SHA256 Hash, 32 bytes
void mu_sha256(const void* data, unsigned int len, unsigned char* outHash)
{
    CC_SHA256(data, len, outHash);
}

// compute hash -SHA256, 32 bytes
NSData *mu_sha256_nsdata(NSData *data)
{
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, data.length, digest);
    NSData *hash = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    return hash;
}

// 计算SHA1 Hash, 20 bytes
void mu_sha1(const void* data, unsigned int len, unsigned char* outHash)
{
    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, data, len);
    CC_SHA1_Final(outHash, &ctx);
}


NSData *mu_sha1_nsdata(NSData *data)
{
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, data.length, digest);
    NSData *hash = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    return hash;
}


// 计算文件内容的SHA1 Hash
NSString* mu_file_sha1(NSString *filePath)
{
    if ([[NSFileManager defaultManager] fileExistsAtPath:filePath])
    {
        NSUInteger digestLength = CC_SHA1_DIGEST_LENGTH;
        unsigned char result[digestLength];

        // get file content data
        NSData *data = [[NSData alloc] initWithContentsOfURL:[NSURL URLWithString:filePath]];
        
        // apply sha1 hash
        CC_SHA1_CTX sha_ctx;
        CC_SHA1_Init(&sha_ctx);
        CC_SHA1_Update(&sha_ctx, [data bytes], (unsigned int)[data length]);
        CC_SHA1_Final(result, &sha_ctx);

        // print out hash as string
        NSMutableString *hash = [NSMutableString string];
        for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) 
        {
            [hash appendFormat:@"%02x", result[i]];
        }
        return [hash lowercaseString];
    }

    return nil;
}