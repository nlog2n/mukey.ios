

// check simulator in compile time

// As of iOS 8 and Xcode 6.1.1 the TARGET_OS_IPHONE is true on the simulator.
// but you can still use TARGET_IPHONE_SIMULATOR


#include "TargetConditionals.h"

// example:
/*
#if TARGET_IPHONE_SIMULATOR
NSLog(@"Running in Simulator - no app store or giro");
#endif
*/



// check simulator in run-time
void check_simulator(void);