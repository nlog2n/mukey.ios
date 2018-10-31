//
//  ViewController.m
//  mukey
//
//  Created by Hui Fang on 28/3/16.
//  Copyright © 2016 Hui Fang. All rights reserved.
//

#import "ViewController.h"

#import "api/muapi.h"

@interface ViewController ()

@end

@implementation ViewController

@synthesize MyLabel;
@synthesize MyTextField;
@synthesize MyTextView;
@synthesize ButtonDeviceInfo;
@synthesize ButtonAppStatus;
@synthesize ButtonTrustedService;



-(IBAction)showDeviceInfo {
    // device info
    NSString *message =   show_device_info();
    
    self.MyTextView.text = message;
}


-(IBAction)showAppStatus {
    // threat check
    overall_check();
    
    // collect status
    NSString *message =   print_app_status();
    
    //self.MyLabel.text = message;
    self.MyTextView.text = message;
}

-(IBAction)showTrustedService {
    // device info
    NSString *message =   @"One Time Password=null";
    
    self.MyTextView.text = message;
}



- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
