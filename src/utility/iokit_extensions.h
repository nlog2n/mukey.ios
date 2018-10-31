



// input: identifier - name string
//        identifierCategory - data type, data or string
// output:   IOSInfo
// return:  length, 0 - fail

int get_iokit_info(unsigned char* outIOSInfo,
                                const char* serviceName,
                                const char* identifier,
                                int identifierCategory);