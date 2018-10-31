#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>

#include "utility/filetool.h"
#include "profile/appstatus.h"

// 该方法能检测Airplay mirroring.但不能检测 QuickTime mirroring
// Using the mirroredScreen property to determine if the display is being mirrored.
// refer to: http://developer.apple.com/library/ios/#qa/qa1738/_index.html
// refer to: https://developer.apple.com/library/ios/documentation/WindowsViews/Conceptual/WindowAndScreenGuide/UsingExternalDisplay/UsingExternalDisplay.html


int is_screen_mirrored(void)
{
    UIScreen *aScreen;
    NSArray *screens = [UIScreen screens];
    for (aScreen in screens)
    {
        // Note: On iOS 4.3, you can use the UIScreen mirroredScreen property to directly determine
        // if mirroring is active.
        // On earlier releases of iOS, mirroring is not supported, so check for the availability of this property
        if ([aScreen respondsToSelector:@selector(mirroredScreen)]
            && [aScreen mirroredScreen] == [UIScreen mainScreen])
        {
            // The main screen is being mirrored.
            //
            // mirroredScreen will reference the main screen if you access the property
            // on a secondary screen that actually is the mirrored screen.
            //NSLog(@"%@", aScreen.mirroredScreen); // will reference the mainScreen
            
            printf("main screen is being mirrored by airplay.\n");
            set_screenrecord_status(1);
            return 1;
        }
        else
        {
            // The main screen is not being mirrored, or
            // you are not running on a compatible device.
            
            // btw: the mirrorScreen property of main screen is nil
        }
    }
    
    set_screenrecord_status(0);
    return 0;
}



// 该代码与上面有冗余，仅放此参考
/*
int check_second_screen(void)
{
    if ([[UIScreen screens] count] > 1)
    {
        printf("found second screen.\n");
        set_screenrecord_status();
        
        // Get the screen object that represents the external display.
        UIScreen *secondScreen = [[UIScreen screens] objectAtIndex:1];
        
        // Get the screen's bounds so that you can create a window of the correct size.
        CGRect screenBounds = secondScreen.bounds;

        // create a window for alternative display
        UIWindow* secondWindow = [[UIWindow alloc] initWithFrame:screenBounds];
        secondWindow.screen = secondScreen;
        
        // Show the window.
        secondWindow.hidden = NO;

        return 1;
    }
    
    return 0;
}
*/