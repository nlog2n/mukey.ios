#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <dirent.h>

// this should be for Android, see anti_debug.h

#define proctaskPath                         "/proc/%d/task"
#define proctaskstatusPath                   "/proc/%d/task/%s/status"

int is_pflag_set(int pid)
{
   if (pid == -1)
        return -1;

    // check if /proc/PID/task/TASKID/status has T or t state
    char task[30];
    char line[300];
    char p_subtask[30];
    char p_status;
    struct dirent *de;
    sprintf(task, proctaskPath, pid);
    DIR *dir = opendir(task);
    if (dir == NULL)
    {
        printf("Unable to open %s", task);
        return -1;
    }
    
    while (((de = readdir(dir)) != NULL))
    {
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
        {
            sprintf(p_subtask, proctaskstatusPath, pid, de->d_name);
            FILE *fp = fopen(p_subtask, "r");
            if (fp == NULL)
            {
                closedir(dir);
                continue;
            }
            fgets(line, sizeof(line), fp); // Name: main
            fgets(line, sizeof(line), fp); // State: S (sleeping)
            sscanf(line,"%*s %c", &p_status);
            if (p_status == 't' || p_status == 'T')
            {
                // debugger found on pid
                printf("debugger found on pid = %d line = %s\n", pid, line);
                fclose(fp);
                return 1;
            }
            fclose(fp);
        }
    }
    closedir(dir);
    return 0;
}

int debugger_check()
{
    if (is_pflag_set(getpid()) == 1)
		return 1;
	
	return 0;
}
