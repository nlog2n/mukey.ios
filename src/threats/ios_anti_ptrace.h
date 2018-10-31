#include <dlfcn.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include "macro.h"
#include "anti_debug.h"


#ifdef __LP64__
#define SVCALL0(number, rettype, signature)         \
__attribute__((always_inline))                      \
static rettype signature() {                        \
    register rettype retVal asm("x0");              \
    register int _p16 asm("x16") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (retVal)                   \
                  :[i] "i" (_p16)                   \
                  : "x0");                          \
    return retVal;                                  \
}
#define SVCALL1(number, rettype, signature, p1_t )  \
__attribute__((always_inline))                      \
static rettype signature(p1_t p1) {                 \
    register p1_t _p1 asm("x0") = p1;               \
    register int _p16 asm("x16") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (_p1)                      \
                  :[i] "i" (_p16), [a] "r" (_p1)    \
                  : "x0");                          \
    return (rettype)_p1;                            \
}
#define SVCALL2(number, rettype, signature, p1_t, p2_t) \
__attribute__((always_inline))                      \
static rettype signature(p1_t p1, p2_t p2) {        \
    register p1_t _p1 asm("x0") = p1;               \
    register p2_t _p2 asm("x1") = p2;               \
    register int _p16 asm("x16") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (_p1)                      \
                  :[i] "i" (_p16), [a] "r" (_p1), [b] "r" (_p2) \
                  : "x0");                          \
    return (rettype)_p1;                            \
}
#define SVCALL3(number, rettype, signature, p1_t, p2_t, p3_t) \
__attribute__((always_inline))                      \
static rettype signature(p1_t p1, p2_t p2, p3_t p3) {  \
    register p1_t _p1 asm("x0") = p1;               \
    register p2_t _p2 asm("x1") = p2;               \
    register p3_t _p3 asm("x2") = p3;               \
    register int _p16 asm("x16") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (_p1)                      \
                  :[i] "r" (_p16), [a] "r" (_p1), [b] "r" (_p2), [c] "r" (_p3) \
                  : "x0");                          \
    return (rettype)_p1;                            \
}
#define SVCALL4(number, rettype, signature, p1_t, p2_t, p3_t, p4_t) \
__attribute__((always_inline))                      \
static rettype signature(p1_t p1, p2_t p2, p3_t p3, p4_t p4) {  \
    register p1_t _p1 asm("x0") = p1;               \
    register p2_t _p2 asm("x1") = p2;               \
    register p3_t _p3 asm("x2") = p3;               \
    register p4_t _p4 asm("x3") = p4;               \
    register int _p16 asm("x16") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (_p1)                      \
                  :[i] "r" (_p16), [a] "r" (_p1), [b] "r" (_p2), [c] "r" (_p3), [d] "r" (_p4) \
                  : "x0");                          \
    return (rettype)_p1;                            \
}
#else
#define SVCALL0(number, rettype, signature)         \
__attribute__((always_inline))                      \
static rettype signature() {                        \
    register rettype retVal asm("r0");              \
    register int _p12 asm("r12") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (retVal)                   \
                  :[i] "i" (_p12)                   \
                  : "r0");                          \
    return retVal;                                  \
}
#define SVCALL1(number, rettype, signature, p1_t )  \
__attribute__((always_inline))                      \
static rettype signature(p1_t p1) {                 \
    register p1_t _p1 asm("r0") = p1;               \
    register int _p12 asm("r12") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (_p1)                      \
                  :[i] "i" (_p12), [a] "r" (_p1)    \
                  : "r0");                          \
    return (rettype)_p1;                            \
}
#define SVCALL2(number, rettype, signature, p1_t, p2_t) \
__attribute__((always_inline))                      \
static rettype signature(p1_t p1, p2_t p2) {        \
    register p1_t _p1 asm("r0") = p1;               \
    register p2_t _p2 asm("r1") = p2;               \
    register int _p12 asm("r12") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (_p1)                      \
                  :[i] "i" (_p12), [a] "r" (_p1), [b] "r" (_p2) \
                  : "r0");                          \
    return (rettype)_p1;                            \
}
#define SVCALL3(number, rettype, signature, p1_t, p2_t, p3_t) \
__attribute__((always_inline))                      \
static rettype signature(p1_t p1, p2_t p2, p3_t p3) {  \
    register p1_t _p1 asm("r0") = p1;               \
    register p2_t _p2 asm("r1") = p2;               \
    register p3_t _p3 asm("r2") = p3;               \
    register int _p12 asm("r12") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (_p1)                      \
                  :[i] "r" (_p12), [a] "r" (_p1), [b] "r" (_p2), [c] "r" (_p3) \
                  : "r0");                          \
    return (rettype)_p1;                            \
}
#define SVCALL4(number, rettype, signature, p1_t, p2_t, p3_t, p4_t) \
__attribute__((always_inline))                      \
static rettype signature(p1_t p1, p2_t p2, p3_t p3, p4_t p4) {  \
    register p1_t _p1 asm("r0") = p1;               \
    register p2_t _p2 asm("r1") = p2;               \
    register p3_t _p3 asm("r2") = p3;               \
    register p4_t _p4 asm("r3") = p4;               \
    register int _p12 asm("r12") = number;          \
    asm volatile (                                  \
                  "svc #0x80"                       \
                  : "=r" (_p1)                      \
                  :[i] "r" (_p12), [a] "r" (_p1), [b] "r" (_p2), [c] "r" (_p3), [d] "r" (_p4) \
                  : "r0");                          \
    return (rettype)_p1;                            \
}
#endif
 
// Macro Overloading. Based on: http://stackoverflow.com/questions/11761703/overloading-macro-on-number-of-arguments
#define GET_SVCMACRO(_0, _n, _r, _s, _p1, _p2, _p3, _p4, NAME, ...) NAME
#define SVCALL(...) GET_SVCMACRO(_0, ##__VA_ARGS__, SVCALL4, SVCALL3, SVCALL2, SVCALL1, SVCALL0)(__VA_ARGS__)


   SVCALL(26, int, my_ptrace, int, int, int, int)
	
void my_anti_debug_spam_func_4()
{

	my_ptrace(31, 0, 0, 0);
}	

///////////////////////////////////////////////////

inline long __my_syscall4(n, a, b, c, d)
{
  register long r7 __asm__("r7") = n;
  register long r0 __asm__("r0") = a;
  register long r1 __asm__("r1") = b;
  register long r2 __asm__("r2") = c;
  register long r3 __asm__("r3") = d;
 
  do { 
	  __asm__ __volatile__ ( "svc 0" : "=r"(r0) : "r"(r7), "0"(r0), 
"r"(r1), "r"(r2), "r"(r3): "memory"); return r0; } 
while (0);
}


void my_anti_debug_spam_func_3()
{
	_my_syscall4(26,31,0,0,0);
}


// equivalent to ptrace(PT_DENY_ATTACH, 0, 0, 0);
void my_anti_debug_spam_func_5a()
{
asm volatile(
             "push {r0,r1,r2,r3,r12}\n"
             "mov r0, #31\n"
             "mov r1, #0\n"
             "mov r2, #0\n"
             "mov r3, #0\n"
             "mov r12, #26\n"
             "svc #0x80\n"
             "pop {r0,r1,r2,r3,r12}\n"
             :::"r0","r1","r2","r3","r12"
             );
}

void my_anti_debug_spam_func_5b()
{
asm volatile(
             "push {r0,r1,r2,r3,r12}\n"
             "mov r1, #31\n"
             "mov r0, r1\n"
             "mov r1, #0\n"
             "mov r2, #0\n"
             "mov r3, #26\n"
             "mov r12, r3\n"
             "mov r12, #0\n"
             "svc #0x80\n"
             "pop {r0,r1,r2,r3,r12}\n"
             :::"r0","r1","r2","r3","r12"
             );
}

__attribute__((__annotate__(("spam")))) void my_syscall_1()
{
    DEBUG_BASIC_PRINT("Hello from obfuscator 1...\n");
    syscall(26,31,0,0,0);
    
}

