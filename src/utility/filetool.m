#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>

// C functions like fopen(), stat(), or access() can be used to check file existence.
// return: 1 file existed, 0 non-existed
int is_file_existed(const char* filepath)
{
  struct stat stat_info;
  return ( stat(filepath, &stat_info) == 0 ); 
}