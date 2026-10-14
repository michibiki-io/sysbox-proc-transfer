/* TEST ONLY: operator-supplied paths. Fail with EIO after the task-owned switch
 * appears, otherwise exec the production helper retaining the exact FDs. */
#ifndef TEST_HELPER
#define TEST_HELPER "/invalid/test-helper"
#endif
#ifndef TEST_TRIGGER
#define TEST_TRIGGER "/invalid/test-trigger"
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc;
    const char *helper=getenv("TEST_SYSFS_HELPER"), *trigger=getenv("TEST_SYSFS_TRIGGER");
    if (!helper || !trigger) {
        /* Production launches with an empty environment. Test build supplies
         * trusted paths as compiler definitions, never requester arguments. */
        helper=TEST_HELPER;
        trigger=TEST_TRIGGER;
    }
    if (!access(trigger,F_OK)) return EIO;
    argv[0]=(char *)helper;
    execv(helper,argv);
    perror("exec production sysfs helper");return EIO;
}
