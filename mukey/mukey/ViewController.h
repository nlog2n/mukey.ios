//
//  ViewController.h
//  mukey
//
//  Created by Hui Fang on 28/3/16.
//  Copyright © 2016 Hui Fang. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController {


IBOutlet UILabel *MyLabel;
IBOutlet UITextField *MyTextField;
IBOutlet UITextView *MyTextView;

    IBOutlet UIButton  *ButtonDeviceInfo;
    IBOutlet UIButton  *ButtonAppStatus;
    IBOutlet UIButton  *ButtonTrustedService;

}

@property (nonatomic, retain) UIButton *ButtonDeviceInfo;
@property (nonatomic, retain) UIButton *ButtonAppStatus;
@property (nonatomic, retain) UIButton *ButtonTrustedService;

@property (nonatomic, retain) UILabel *MyLabel;
@property (nonatomic, retain) UITextField *MyTextField;
@property (nonatomic, retain) UITextView *MyTextView;


-(IBAction)showDeviceInfo;
-(IBAction)showAppStatus;
-(IBAction)showTrustedService;



@end

