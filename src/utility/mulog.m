

#include <stdarg.h>

#import <Foundation/Foundation.h>

void muLog(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *formatStr = [[NSString alloc] initWithCString:format encoding:NSASCIIStringEncoding];
    NSString *str = [[NSString alloc] initWithFormat:formatStr arguments:args];
    NSLog(@"%@", str);
    va_end(args);
}