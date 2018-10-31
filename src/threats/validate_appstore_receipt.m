#include <stdlib.h>
#include <stdio.h>
#include <string.h>


//#import <Foundation/Foundation.h>
@import Foundation;
@import UIKit;

#include "profile/appstatus.h"


#define IS_OS_5_OR_LATER    ([[[UIDevice currentDevice] systemVersion] floatValue] >= 5.0)
#define IS_OS_6_OR_LATER    ([[[UIDevice currentDevice] systemVersion] floatValue] >= 6.0)
#define IS_OS_7_OR_LATER    ([[[UIDevice currentDevice] systemVersion] floatValue] >= 7.0)
#define IS_OS_8_OR_LATER    ([[[UIDevice currentDevice] systemVersion] floatValue] >= 8.0)
#define IS_OS_9_OR_LATER    ([[[UIDevice currentDevice] systemVersion] floatValue] >= 9.0)


// return:  0-OK, others-Faillure
int validate_appstore_receipt()
{
    int status = 0;
    
    // do stuff for iOS 7 and newer, or call macro above
	if ((NSFoundationVersionNumber >= NSFoundationVersionNumber_iOS_7_0))
	{
		// iOS7及以上获取receipt的方法, OS X 10.7 或之后
        
        // It's now iOS 8.4 and Xcode 6.4 so maybe history is different, but I find this method call always returns nil when running in the simulator. On a real device it works as documented by Apple: The path to where the app receipt is intended to be stored is returned -- with no guarantee that either there is a receipt there nor that it is a valid receipt.

        // 只是先检查该receiptUrl字符串, 并不意味着对应的路径存在于simulator &device.
        // i tested on xcode ios 8 simulator&device with developer app (free?).
		NSURL *receiptUrl = [[NSBundle mainBundle] appStoreReceiptURL];
        NSString *urlString = [receiptUrl absoluteString];
        NSLog(@"receipt url: %@", urlString);
        if (!receiptUrl || [urlString rangeOfString:@"Simulator"].location != NSNotFound )
        {
            printf("Error: appStoreReceiptURL check failed, either null or in simulator.\n");
            status = 1;
            if (!receiptUrl)
            {
                set_appstore_receipt_status();
            }
            else
            {
                set_simulator_status(STATUS_SIMULATOR_APP_RECEIPT);
            }
            return 1;
        }
        
        // detect at runtime that an application has been installed
        // through TestFlight Beta (submitted through iTunes Connect) vs the App Store
		if ([[NSFileManager defaultManager] fileExistsAtPath:[receiptUrl path]])
        ////
        // NSError *receiptError;
        // BOOL isPresent = [receiptUrl checkResourceIsReachableAndReturnError:&receiptError];
        // if (isPresent)
		{
            // get receipt data then
			NSData *ios7ReceiptData = [NSData dataWithContentsOfURL:receiptUrl];
            if(!ios7ReceiptData) {
                printf("Warning: no local receipt.\n");
            }
            
            // or
            /*
            NSURLRequest *urlRequest = [NSURLRequest requestWithURL:receiptUrl];
            NSError *error = nil;
            NSData *receiptData = [NSURLConnection sendSynchronousRequest:urlRequest returningResponse:nil error:&error];
            if (!receiptData)
            {
                printf("Warning: did not get receipt data.\n");
            }
            */
            
            // 更多的validation可参考: 收据验证 http://objccn.io/issue-17-3/
            
            //NSString *jsonObjectString = [ios7ReceiptData base64EncodedStringWithWrapWidth:0];
            //NSLog(@"receipt data: %@", jsonObjectString);
		}
		else
		{
			printf("Warning: actual path for app receipt url not exists!\n");
		}
	}
	else
	{
        printf("bypass app store receipt check for ios6 and below.\n");
		// iOS6及以下获取receipt的方法, 两者格式不一样
		/*
        NSData *receiptData = transaction.transactionReceipt;
        NSString *jsonObjectString = [self encodeBase64:(uint8_t *)transaction.transactionReceipt.bytes
                                                 length:transaction.transactionReceipt.length];
        */
	}

    return status;
}

