/* TEST BINARY ONLY. The production helper is included without changing its
 * checks or mount operations. FD 200 is a private operator socket; this file
 * is excluded from the production Docker context. Never deploy this binary.
 * Pause before each actual pidfd poll, and after the final successful poll.
 * The latter forces a commit race without weakening any mount protection. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
static int checkpoint_poll(struct pollfd *, nfds_t, int);
#define poll checkpoint_poll
#define main production_main
#include "../../helper/proc-mount-helper.c"
#undef main
#undef poll
static void checkpoint(char c) {
    if (write(200, &c, 1) != 1)
        _exit(111);
    char ack;
    if (read(200, &ack, 1) != 1 || ack != 'A')
        _exit(111);
}
static int checkpoint_poll(struct pollfd *p, nfds_t n, int timeout) {
    static int stage, retry;
    if (!retry) {
        stage++;
        checkpoint(stage == 1 ? 'S' : 'T');
    }
    int result = poll(p, n, timeout);
    retry = result < 0 && errno == EINTR;
    if (stage == 2 && result == 0)
        checkpoint('C');
    return result;
}
int main(int argc, char **argv) { return production_main(argc, argv); }
