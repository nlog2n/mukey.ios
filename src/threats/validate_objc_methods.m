#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <objc/objc.h>
#include <objc/runtime.h>

#define PRINT_DL_INFO(info)   \
{ \
    printf("dli_fname: %s\n", info.dli_fname);  \
    printf("dli_sname: %s\n", info.dli_sname);  \
    printf("dli_fbase: %p\n", info.dli_fbase);  \
    printf("dli_saddr: %p\n", info.dli_saddr);  \
} 


/*
static int validate_all_objc_classes(void) __attribute__ ((always_inline));
static int validate_class(const char *cls,const char *fname) __attribute__ ((always_inline));
static int validate_class_method(const char *MyCriticalClass , const char *MyCriticalMethod, const char *fname) __attribute__((always_inline));
*/



// check address space
int validate_class_method(const char *MyCriticalClass , const char *MyCriticalMethod, const char *fname)
{
	Dl_info info;
	   char buf[512];
	   
	   
	IMP imp = class_getMethodImplementation(
		objc_getClass(MyCriticalClass),
		sel_registerName(MyCriticalMethod)
	);
    printf("validating [%s %s], pointer %p\n", MyCriticalClass, MyCriticalMethod, imp);
	if ( !imp )
	{
          printf("error: class_getMethodImplementation(%s) failed\n", MyCriticalMethod);
          return 2;
    }
	 
	if ( !dladdr(imp, &info))
	{
              printf("error:dladdr() failed for %s\n", MyCriticalMethod);
              return 3;
			
	} 
		
	if ( imp != info.dli_saddr )
	{
		printf("warning: dl_info nearest symbol is NOT equal to given one %p.\n", imp);
	PRINT_DL_INFO(info);	
	    return 0; // could happen	
	}	
	


	    
          /*Validate image path*/
          if(strcmp(info.dli_fname, fname))
  		{
  			// this could happen!! ignore
  			printf("warning: image path mismatch %s , %s.\n", info.dli_fname, fname);
  			//return 4;
  		}
       
          if (info.dli_sname != NULL && strcmp(info.dli_sname, "<redacted>") != 0) 
  		{
              /*Validate class name in symbol*/
              snprintf(buf, sizeof(buf), "[%s ", MyCriticalClass);
              if(strncmp(info.dli_sname + 1, buf, strlen(buf)))
  			{
                  snprintf(buf, sizeof(buf),"[%s(", MyCriticalClass);
                  if(strncmp(info.dli_sname + 1, buf, strlen(buf)))
  				{
  					printf("error: class name mismatch %s , %s\n", info.dli_sname, buf);
  				
  					return 5;
                      //goto FAIL;
  				}
              }
           
              /*Validate selector in symbol*/
              snprintf(buf, sizeof(buf), " %s]", MyCriticalMethod);
              if(strncmp(info.dli_sname + (strlen(info.dli_sname) - strlen(buf)), buf, strlen(buf)))
  			{
  				printf("error: method name mismatch %s , %s\n", info.dli_sname, buf);
  			
  				return 6;
                  //goto FAIL;
              }
          }else{
              printf("<redacted>  \n");
          }
       
      
		  return 0;
 }


// verify all methods in a given object-c class
// input:  class name and its image path
// return: error code, otherwise 0 is OK
int validate_class(const char *cls,const char *fname)
{
    Class aClass = objc_getClass(cls);
    Method *methods;
    unsigned int nMethods;
    Dl_info info;
    IMP imp;
    char buf[512];
    Method m;
   
    if(!aClass)
	{
		printf("error: no such class %s found.\n", cls);
        return 1;
	}
	
    methods = class_copyMethodList(aClass, &nMethods);
    while (nMethods--) 
	{
        m = methods[nMethods];
        //printf("validating [%s %s]\n",(const char *)class_getName(aClass),(const char *)method_getName(m));
       
        imp = method_getImplementation(m);
        //imp = class_getMethodImplementation(aClass, sel_registerName("allObjects"));
        if(!imp)
		{
            printf("error:method_getImplementation(%s) failed\n",(const char *)method_getName(m));
            free(methods);
            return 2;
        }
       
        if(!dladdr(imp, &info))
		{
            printf("error:dladdr() failed for %s\n",(const char *)method_getName(m));
            free(methods);
            return 3;
        }
       
		if ( imp != info.dli_saddr )
		{
			printf("warning: dl_info nearest symbol is NOT equal to given one %p.\n", imp);
		    PRINT_DL_INFO(info);
			continue; // could happen, no need to further compare names	
		    // return 0; // could happen	
		}	
	   
	   
        /*Validate image path*/
        if(strcmp(info.dli_fname, fname))
		{
			// this could happen!! ignore
			printf("warning: image path mismatch %s , %s.\n", info.dli_fname, fname);
			//PRINT_DL_INFO(info);	
			
			////free(methods);
			////return 4;
		}
       
        if (info.dli_sname != NULL && strcmp(info.dli_sname, "<redacted>") != 0) 
		{
            /*Validate class name in symbol*/
            snprintf(buf, sizeof(buf), "[%s ",(const char *) class_getName(aClass));
            if(strncmp(info.dli_sname + 1, buf, strlen(buf)))
			{
                snprintf(buf, sizeof(buf),"[%s(",(const char *)class_getName(aClass));
                if(strncmp(info.dli_sname + 1, buf, strlen(buf)))
				{
					printf("error: class name mismatch %s , %s\n", info.dli_sname, buf);
					free(methods);
						PRINT_DL_INFO(info);	
					return 5;
                    //goto FAIL;
				}
            }
           
            /*Validate selector in symbol*/
            snprintf(buf, sizeof(buf), " %s]",(const char*)method_getName(m));
            if(strncmp(info.dli_sname + (strlen(info.dli_sname) - strlen(buf)), buf, strlen(buf)))
			{
				printf("error: method name mismatch %s , %s\n", info.dli_sname, buf);
					PRINT_DL_INFO(info);	
				free(methods);
				return 6;
                //goto FAIL;
            }
        }else{
            printf("<redacted>  \n");
        }
       
    }
   
    free(methods);
    return 0;
}


int validate_all_objc_classes(void)
{
	int nClasses = objc_getClassList(NULL,0);
    Class *classes = (__unsafe_unretained Class*) calloc(sizeof(Class), nClasses);
    objc_getClassList(classes, nClasses);
    
    for (int i = 0; i < nClasses; ++i) {
        const char *cls = class_getName(classes[i]);
        const char *fname = class_getImageName(classes[i]);
        
		if ( validate_class(cls, fname) )
		{
			free(classes);
			return 1; // hooked
		}
		else {
			//printf("class [%s] path [%s] \t OK\n", cls, fname);
		}
	}
	
	free(classes);
	return 0; // normal
}



// compile: clang -o test test.m -framework Foundation -lobjc
// run:  ./test
// output:
/*
 pointer 0x7fff8a267260
 dli_fname: /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
 dli_sname: -[NSArray description]
 dli_fbase: 0x7fff8a116000
 dli_saddr: 0x7fff8a267260
 */

#ifdef  TEST_OBJC_HOOK

int main()
{
    if ( validate_class_method("NSArray", "description", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation") )
    {
        // hooked
    }
    
    if ( validate_class_method("MecabraCandidate", "surface", "/usr/lib/libmecabra.dylib"))
    {
        // hooked
    }
    
    //if ( validate_class("NSArray", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation") )
    {
        // hooked
    }
    
    //if ( validate_all_objc_classes())
    {
        // hooked
    }
    
    return 0;
}

#endif