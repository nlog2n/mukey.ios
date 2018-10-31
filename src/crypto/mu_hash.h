#ifndef __MUKEY_HASH_H__
#define __MUKEY_HASH_H__


#ifdef __cplusplus
extern "C" {
#endif
    
    void mu_sha256(const void* data, unsigned int len, unsigned char* outHash);
    NSData *mu_sha256_nsdata(NSData *data);
    
    void mu_sha1(const void* data, unsigned int len, unsigned char* outHash);
    NSData *mu_sha1_nsdata(NSData *data);
    
    NSString* mu_file_sha1(NSString *filePath);
    
    
#ifdef __cplusplus
}
#endif

#endif




