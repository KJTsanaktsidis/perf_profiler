#ifndef __PERF_HELPER_H
#define __PERF_HELPER_H

/* n.b. this is included from both the extension and the perf_helper,
 * so no Ruby includes here */

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

/*
 * The perf_helper program is a privileged helper program used by the profile.so extension
 * to do the actual work of calling perf and eBPF system calls.
 *
 * Normally, calling perf_event_open(2) requres CAP_PERFMON, and bpf(2) requires CAP_BPF.
 * We would like Ruby programs to be profilable even if they are not running with elevated
 * privileges, especially since these two capabilities can give a process quite a bit of
 * access to a system. The perf_helper program is the solution to this; it is a separate
 * helper program that is intended to be installed with the CAP_PERFMON and CAP_BPF file
 * capabilities set. The profile.so extension library can call this helper and set up
 * profiling for a Ruby program, without the Ruby program itself needing to be running
 * with this privileges.
 *
 * The helper and the profile.so extension communicate with the following protocol:
 *
 * - The profile.so extension calls socketpair() to set up a connected pair of
 *   SOCK_SEQPACKET sockets
 * - The profile.so extension forks & exec's the perf_helper, with:
 *     * FD #3 set up as its half of the socketpair
 *     * stderr captured in a buffer
 *     * stdout & stdin closed
 * - The perf_helper binary loops, waiting for messages on the socket
 * - profile.so begins by writing a message of type struct perf_helper_req_setup
 *   to the socket.
 *     * It must _ALSO_ include a SCM_CREDENTIALS ancillary message containing the
 *       sending process's pid (which, from the kernel's perspective is the tgid).
 *     * It must _ALSO_ include a SCM_RIGHTS ancillary message contianing a pidfd
 *       referring to the calling process (again, from the kernel's view, the tgid)
 * - In response, the perf_helper program will set up a dummy perf handle to act
 *   as the group leader & also configure all the eBPF maps. It will reply on the
 *   socket with a struct perf_helper_res_setup. It will also include a SCM_RIGHTS
 *   ancillary message with the following FDs.
 *     * A perf FD to act as the group leader
 *     * A FD for the eBPF ringbuffer map samples will be written to.
 * - As threads are created, profile.so will write messages of type struct
 *   perf_helper_req_newthread, for each new thread that is created in the program
 *   (or for existing threads that were around before profiling started).
 * - In response, the perf_helper program will set up a new perf handle for the
 *   specified thread, and attach the eBPF sample writer program to it. It will
 *   respond wiht perf_helper_res_newthread and an SCM_RIGHTS ancillary message
 *   with the following FDs.
 *     * A perf FD for the new thread
 *  - When threads are terminated, profile.so will send struct perf_helper_req_endthread.
 *  - And perf_helper will respond with perf_helper_res_endthread
 *  - When the socket is closed, perf_helper will stop profiling, unload the eBPF machinery,
 *    and exit.
 *  
 *  SECURITY NOTE:
 *
 *  The eBPF stack sampling program copies the Ruby stack from userspace memory to
 *  the eBPF sample ringbuffer map. The address of the ruby stack is provided in the
 *  perf_helper_req_newthread message. Therefore, the program set up by perf_helper could
 *  read any userspace memory belonging to any program!
 *
 *  perf_helper must be _incredibly_ careful to only allow a process to set up stack sampling
 *  for threads in its own process. It also needs to be incredibly vigilant against pid
 *  re-use bugs. Any failure in these checks could allow the priviliged perf_helper to act
 *  as a confused deputy that let any process read any memory of any other process!
 *
 *  Doing this correctly is also _incredibly_ tricky. The kernel guarantees that a pid
 *  sent in a SCM_CREDS ancillary message is correct at the time it was sent - BUT - it
 *  is possible that the sending process exited, and the pid was subsequently re-used, after
 *  the SCM_CREDS message was sent and before the message was received. Likewise, the
 *  pid received from SO_PEERCREDS is correct at the time the socketpair was created, but
 *  if the process exits & the pid is re-used, the pid from SO_PEERCREDS will now refer to
 *  this new process.
 *
 *  The correct sequence of checks that perf_helper needs to do is as follows:
 *  1. The calling program needs to send both an SCM_CREDENTIALS message (containing the
 *     program's PID) as well as an SCM_RIGHTS message containing a pidfd for itself,
 *     along with the initial perf_helper_req_setup message.
 *  2. perf_helper must validate that the pidfd actually _does_ refer to the same pid
 *     as from the SCM_CREDENTIALS message. It can do this by looking at /proc/self/fdinfo/#{fd}
 *     which contains the field "Pid:"
 *  3. perf_helper can be satisfied that the pidfd must have been actually sent by that process,
 *     because the kernel validates a pid sent in SCM_CREDENTIALS and so a process cannot lie.
 *  4. perf_helper can be satisfied that no pid re-use has happened by calling pidfd_send_signal(2)
  *    on the pidfd with a null signal and verifying that it succeeded. That means that the process
  *    that the pidfd describes must still exist, and so the pid can't have been re-used by some
  *    other process.
 */

typedef enum {
    PERF_HELPER_MSG_REQ_SETUP = 1,
    PERF_HELPER_MSG_RES_SETUP = 2,
    PERF_HELPER_MSG_REQ_NEWTHREAD = 3,
    PERF_HELPER_MSG_RES_NEWTHREAD = 4,
    PERF_HELPER_MSG_REQ_ENDTHREAD = 5,
    PERF_HELPER_MSG_RES_ENDTHREAD = 6,
} perf_helper_msg_type;

struct perf_helper_msg_body {
    perf_helper_msg_type type;
    union {
        struct perf_helper_req_setup {
            uint32_t max_threads; 
        } req_setup;
        struct perf_helper_res_setup { } res_setup;
        struct perf_helper_req_newthread {
            pid_t thread_tid;
            uintptr_t ruby_cfp_ptr;
            uintptr_t ruby_cfp_base_ptr;
            int interval_hz;
        } req_newthread;
        struct perf_helper_res_newthread {
            pid_t thread_tid;
            int success;
            char message[256];
            size_t message_len;
        } res_newthread;
        struct perf_helper_req_endthread {
            pid_t thread_tid;
        } req_endthread;
        struct perf_helper_res_endthread {
            pid_t thread_tid;
        } res_endthread;
    };
};

#define MAX_PERF_HELPER_FDS 16
struct perf_helper_msg_ancdata {
    struct ucred creds;
    bool have_creds;
    int fds[MAX_PERF_HELPER_FDS];
    size_t fd_count;
};

struct perf_helper_msg {
    struct perf_helper_msg_body body;
    struct perf_helper_msg_ancdata ancdata;
};

#endif
