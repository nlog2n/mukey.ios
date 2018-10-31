

int get_dyld_cache_file();

unsigned char* extract_lib_bytes_from_cache(const char* dli_fname,
                                            int fd_cache,
                                            off_t offset,
                                            size_t count);