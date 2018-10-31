#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <dirent.h>


#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>

// Add AssetsLibrary.framework and Photos.framework to your project
#include <AssetsLibrary/AssetsLibrary.h>
#include <Photos/Photos.h>

#include "profile/appstatus.h"


// 直接DCIM目录访问在iOS上被禁止.
// output:
// stat folder ok.
// opendir error: Operation not permitted
// looks that it was sandboxed

/*

// Photo folder,  *.PNG format
// "opendir" failed
#define ios_photo_folder  "/private/var/mobile/Media/DCIM/100APPLE"

// This is a preview image that is written every time a screenshot is taken.
// "stat" failed
#define ios_preview_image "/private/var/mobile/Media/PhotoData/MISC/PreviewWellImage.tiff"

void read_preview(void)
{
    struct stat info;
    if ( stat(ios_preview_image, &info) == 0) // success
    {
        printf("stat file %s ok.\n", ios_preview_image);
    }
    else
    {
        printf("stat file %s failed.\n", ios_preview_image);
        return;
    }
    
    printf("size=%d, last modified time=%ld.\n", (int) info.st_size, info.st_mtime);
}


// for Linux and BSD
int read_camera_folder_files(void)
{
    
    read_preview();
    
	struct stat info;
	if ( stat(ios_photo_folder, &info) == 0) // success
	{
		printf("stat folder ok.\n");
	}
	else
	{
		printf("read folder failed.\n");
	}


	int file_count = 0;
	DIR* dirp;
	struct dirent * entry;

	dirp = opendir(ios_photo_folder); 
    if (dirp == NULL)
    {
    	// error handling
    	printf("opendir error: %s\n", strerror(errno));
    	return 0;
    }

    // 这里仅读取当前目录下文件个数，for递归可以多判断文件类型.
	while ((entry = readdir(dirp)) != NULL) 
	{
		if (entry->d_type == DT_REG) 
		{ // If the entry is a regular file
			file_count++;
		}
	}
	closedir(dirp);

    printf("number of files: %d\n", file_count);

	return 0;
}


void read_camera_folder_files_objc(void)
{
    int file_count = 0;
    
    NSFileManager *fileMgr = [NSFileManager defaultManager];
    NSString *path = @ios_photo_folder;
    NSDirectoryEnumerator *enumerator = [fileMgr enumeratorAtPath:path];
    
    NSString *entry; // as filename
    while ((entry = [enumerator nextObject]))
    {
        // file or directory?
        BOOL isDirectory;
        if ([fileMgr fileExistsAtPath:entry isDirectory:&isDirectory] && isDirectory)
            NSLog (@"Directory - %@", entry);
        else
        {
            NSLog (@"  File - %@", entry);
            file_count ++;
         
            //what i am looking for
            if ([entry hasSuffix:@".data"])
            {
                // Do work here
                NSLog(@"Files in resource folder: %@", entry);
            }
        }
    }
    
    printf("number of photo files: %d\n", file_count);
}

*/



// method 1: use iOS UIApplicationUserDidTakeScreenshotNotification

// 初始化的时候执行, 加入事件通知
// 不需要用户许可权限
void add_screenshot_notification(void)
{
    static int is_notification_added = 0;  // 标志位，只执行一次
    
    if (!is_notification_added)
    {
        NSOperationQueue *mainQueue = [NSOperationQueue mainQueue];
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationUserDidTakeScreenshotNotification
                                                    object:nil
                                                    queue:mainQueue
                                                    usingBlock:^(NSNotification *note)
                                                  {
                                                      // callback, executes after screenshot
                                                      set_screenshot_status(1);
                                                  }];
        
        is_notification_added = 1;
    }
}


// method 2: 读最后一张相片, 看是否符合snapshot尺寸并且在程序执行时间内. from ShotBlocker


static int is_screenshot(UIImage *image)
{
    CGFloat imageWidth = image.size.width;
    CGFloat imageHeight = image.size.height;
    
    CGFloat screenWidth = [UIScreen mainScreen].bounds.size.width;
    CGFloat screenHeight = [UIScreen mainScreen].bounds.size.height;
    
    NSLog(@"image wxh = %d x %d, screen wxh = %d x %d", (int)imageWidth, (int)imageHeight, (int)screenWidth, (int) screenHeight);
    
    // imageWidth/Height is in points; screenWidth/Height is in pixels
    // so on a retina device, screenWidth/Height is 2x.
    // fmodf takes care of the scale factor for us, so we just compare
    // widths and heights to see if either orientation matches.
    return (fmodf(imageWidth, screenWidth)  == 0 && fmodf(imageHeight, screenHeight) == 0)
            ||
           (fmodf(imageWidth, screenHeight) == 0 && fmodf(imageHeight, screenWidth)  == 0);
}


// compare if the snapshot time is inside the sensitive interval.
int is_happen_after_started(NSDate *now)
{
    static NSDate *startTime = nil;  // [NSDate date];
    if ( startTime == nil )
    {
        startTime = [NSDate date];
    }
    
    double nowTimeInterval = [now timeIntervalSince1970];   // in seconds
    double previousTimeInterval = [startTime timeIntervalSince1970];
    
    if(previousTimeInterval < nowTimeInterval)
    {
        NSLocale* currentLoc = [NSLocale currentLocale];
        NSLog(@"%@",[ now descriptionWithLocale:currentLoc]);
        
        return 1;
    }
    
    return 0;
}


// get the latest image from the camera roll
//  需要访问Photo权限
// Note: 由于采用了callback方式，一旦状态被设置为 "screenshot detected",则无法清除.
void check_last_screenshot(void)
{
    // PHPhotoLibrary_class will only be non-nil on iOS 8.x.x
    //Class PHPhotoLibrary_class = NSClassFromString(@"PHPhotoLibrary");
    //if (PHPhotoLibrary_class) {
        
    if ([PHAsset class])
    { // If this class is available, we're running iOS 8

        PHFetchOptions *fetchOptions = [[PHFetchOptions alloc] init];
        
        fetchOptions.sortDescriptors = @[[NSSortDescriptor sortDescriptorWithKey:@"creationDate" ascending:YES]];
        PHFetchResult *fetchResult = [PHAsset fetchAssetsWithMediaType:PHAssetMediaTypeImage options:fetchOptions];
        PHAsset *lastAsset = [fetchResult lastObject];
        
        //NSLog(@"photo creationDate: %@", lastAsset.creationDate);
        
        
        [[PHImageManager defaultManager] requestImageForAsset:lastAsset
                                                   targetSize: PHImageManagerMaximumSize
                                                  contentMode:PHImageContentModeDefault
                                                      options:nil
                                                resultHandler:^(UIImage *result, NSDictionary *info)
         {
             if ([info objectForKey:PHImageErrorKey] == nil && ![[info objectForKey:PHImageResultIsDegradedKey] boolValue])
             {
                 // Do something interesting with the AV asset.
                 NSLog(@"get latest photo thru photo library.");
                 UIImage *latestPhoto = result;
                 
                 if (is_screenshot(latestPhoto) && is_happen_after_started(lastAsset.creationDate))
                 {
                     // NSLog(@"detected screen shot.");
                     // callback
                     set_screenshot_status(2);
                 }
             }
         }];
    }
    else
    {
        // It's not iOS8. Use your previous implementation.
        
        ALAssetsLibrary *library = [[ALAssetsLibrary alloc] init];
        
        // Enumerate just Camera roll (photos and videos) group by using ALAssetsGroupSavedPhotos.
        [library enumerateGroupsWithTypes:ALAssetsGroupSavedPhotos usingBlock: ^ (ALAssetsGroup * group, BOOL * stop)
         {
             if (group && [group numberOfAssets] > 0)
             {
                 // Within the group enumeration block, filter to enumerate just photos.
                 [group setAssetsFilter:[ALAssetsFilter allPhotos]];
                 
                 // Chooses the photo at the last index
                 [group enumerateAssetsWithOptions:NSEnumerationReverse usingBlock:^(ALAsset *alAsset, NSUInteger index, BOOL *innerStop)
                 {
                     
                     // The end of the enumeration is signaled by asset == nil.
                     if (alAsset)
                     {
                         NSDate *myDate = [alAsset valueForProperty:ALAssetPropertyDate];
                         //NSLog(@"photo asset date: %@", myDate);
                         
                         
                         ALAssetRepresentation *representation = [alAsset defaultRepresentation];
                         
                         // get actual picture by fullResolutionImage, instead of fullScreenImage (for display)
                         //UIImage *latestPhoto = [UIImage imageWithCGImage:[representation fullScreenImage]];
                         ALAssetOrientation orientation = [representation orientation];
                         UIImage *latestPhoto = [UIImage imageWithCGImage:[representation fullResolutionImage] scale:[representation scale] orientation:(UIImageOrientation)orientation];
                         
                         
                         // Stop the enumerations
                         *stop = YES; *innerStop = YES;
                         
                         // Do something interesting with the AV asset.
                         NSLog(@"get latest photo thru asset library.");
                         if (is_screenshot(latestPhoto) && is_happen_after_started(myDate))
                         {
                             // NSLog(@"detected screen shot.");
                             // callback
                             set_screenshot_status(3);
                         }
                     }
                 }];
                 
             }
         }
        failureBlock: ^ (NSError * error)
         {
                 NSLog(@"Failed to access ALAssetsLibrary %@ with error: %@", library, error.localizedDescription);
         }];
    }
    
}



void check_screenshot(void)
{
    // 注册screenshot通知事件
    add_screenshot_notification();
    
    // 检查相片最后一张是否screenshot
    check_last_screenshot();
}

