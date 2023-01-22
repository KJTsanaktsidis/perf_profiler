#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <search.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include "stack_sample.bpf.h"
#include "stack_sample.skel.h"
#include "perf_helper.h"

#define SOCKET_FD 3

/* A normal xmalloc wrapper */
static void *
xmalloc(size_t n)
{
    void *r = malloc(n);
    if (!r) {
        abort();
    }
    return r;
}

/*
 * =============================================================================
 * numtable hash table impl
 * =============================================================================
 */

/* The numtable struct is a simple hashtable mapping int -> void *. It uses open
 * addressing with linear probing, and implements deletes with tombstones.
 * This is only nescessary because st.c can't really be used outside of the Ruby
 * interpreter - it _appears_ to have some pre-processor support for doing this,
 * but it no longer works it seems. */
struct numtable {
    struct numtable_impl {
        struct numtable_entry {
            bool occupied : 1;
            bool tombstone : 1;
            int key;
            uintptr_t value;
        } *entries;
        size_t capa;
        size_t len;
        size_t tombstone_count;
    } impl;
};

#define NUMTABLE_SLOT_NEW 0
#define NUMTABLE_SLOT_EXISTING 1
#define NUMTABLE_ITER_STOP 0
#define NUMTABLE_ITER_CONTINUE 1
#define NUMTABLE_NOT_FOUND 0
#define NUMTABLE_FOUND 1

static void
numtable_init(struct numtable *tab, size_t initial_capa)
{
    tab->impl.capa = initial_capa;
    tab->impl.len = 0;
    tab->impl.tombstone_count = 0;
    tab->impl.entries = xmalloc(sizeof(struct numtable_entry) * tab->impl.capa);
    memset(tab->impl.entries, 0, sizeof(struct numtable_entry) * tab->impl.capa);
}

/* I copied this hash algorithm from st.c */
static unsigned long
numtable_hash(int key)
{
    enum {s1 = 11, s2 = 3};
    unsigned long h = (unsigned long)((key>>s1|(key<<s2)) ^ (key>>s2));
    return h;
}

static int
numtable_find_slot(struct numtable_impl *tab, int key, struct numtable_entry **entry_out)
{
    unsigned long hash = numtable_hash(key);
    size_t i = hash % tab->capa;
    struct numtable_entry *slot;
    /* Termination guaranteed because we ensure the load factor is < 25% at all times; so,
     * there _MUST_ be !occupied && !tombstone slots somewhere */
    while (true) {
        slot = &tab->entries[i];
        if (slot->occupied && slot->key == key) {
            *entry_out = slot;
            return NUMTABLE_SLOT_EXISTING;
        }
        if (!slot->occupied && !slot->tombstone) {
            *entry_out = slot;
            return NUMTABLE_SLOT_NEW;
        }
        i++;
        if (i >= tab->capa) {
            i = 0;
        }
    }
}

static void
numtable_grow_if_required(struct numtable *tab)
{
    if ((tab->impl.len + tab->impl.tombstone_count) * 4 <= tab->impl.capa) {
        return;
    }

    struct numtable_impl new_impl = { 0 };
    struct numtable_impl *old_impl = &tab->impl;
    new_impl.capa = old_impl->capa * 2;
    new_impl.len = old_impl->len;
    new_impl.tombstone_count = 0;
    new_impl.entries = xmalloc(sizeof(struct numtable_entry) * new_impl.capa);
    memset(new_impl.entries, 0, sizeof(struct numtable_entry) * new_impl.capa);

    for (size_t i = 0; i < old_impl->capa; i++) {
        if (!old_impl->entries[i].occupied) {
            continue;
        }
        struct numtable_entry *new_slot;
        numtable_find_slot(&new_impl, old_impl->entries[i].key, &new_slot);
        new_slot->occupied = true;
        new_slot->tombstone = false;
        new_slot->key = old_impl->entries[i].key;
        new_slot->value = old_impl->entries[i].value;
    }

    free(old_impl->entries);
    tab->impl = new_impl;
}

static int
numtable_get(struct numtable *tab, int key, uintptr_t *val_out)
{
    struct numtable_entry *slot;
    int r = numtable_find_slot(&tab->impl, key, &slot);
    if (r == NUMTABLE_SLOT_EXISTING) {
        *val_out = slot->value;
        return NUMTABLE_FOUND;
    }
    return NUMTABLE_NOT_FOUND;
}

static int
numtable_set(struct numtable *tab, int key, uintptr_t new_val, uintptr_t *old_val)
{
    numtable_grow_if_required(tab);

    struct numtable_entry *slot;
    int r = numtable_find_slot(&tab->impl, key, &slot);
    if (r == NUMTABLE_SLOT_EXISTING) {
        if (old_val) {
            *old_val = slot->value;
        }
    }
    slot->occupied = true;
    slot->tombstone = false;
    slot->key = key;
    slot->value = new_val;
    return r;
}

static int
numtable_delete(struct numtable *tab, int key, uintptr_t *old_val)
{
    numtable_grow_if_required(tab);

    struct numtable_entry *slot;
    int r = numtable_find_slot(&tab->impl, key, &slot);
    if (r == NUMTABLE_SLOT_EXISTING) {
        *old_val = slot->value;
    }
    slot->occupied = false;
    slot->tombstone = true;
    return r;
    
}

typedef int (*numtable_iter_func)(int key, uintptr_t val, void *ctx);

static void
numtable_each(struct numtable *tab, numtable_iter_func iter_func, void *ctx)
{
    for (size_t i = 0; i < tab->impl.capa; i++) {
        struct numtable_entry *ent = &tab->impl.entries[i];
        if (ent->occupied && !ent->tombstone) {
            int r = iter_func(ent->key, ent->value, ctx);
            if (r == NUMTABLE_ITER_STOP) {
                break;
            }
        }
    }
}

/*
 * =============================================================================
 * Helper main data structures
 * =============================================================================
 */

#define EPOLL_FD_TYPE_SOCKET 1

/* Type of data we stash in epoll */
struct event_loop_epoll_data {
    int fd;
    int fd_type;
    pid_t tid;
};

struct thread_data {
    /* the thread being profiled */
    pid_t tid;

    /* perf_event_open handle for this thread */
    int perf_fd;
    /* open directory pointing to /proc/pid/tasks/tid */
    int meta_dirfd;

    /* libbpf link (attachment to perf_fd) */
    struct bpf_link *stack_sample_attachment;

    struct event_loop_epoll_data epoll_data;
};

struct prof_data {
    int epoll_fd;       /* main run-loop epoll descriptor */
    int socket_fd;      /* socket we communicate with the profiled process on */
    struct event_loop_epoll_data socket_fd_epoll_data;
    

    /* Information about the process on the other side of the socket */
    struct ucred caller_creds;  /* original creds from the socket */
    pid_t caller_pid;           /* remote pid (actually a thread-group-id) */
    int caller_pid_fd;          /* pidfd for pid */

    /* Configuration values sent to us by the peer in the setup
     * message */
    uint32_t max_threads;

    /* Profiling resources */
    struct stack_sample_bpf *stack_sample_skel; /* libbpf program handle */

    /* map of per-thread struct thread_data's */
    struct numtable thread_table;
};

struct strbuf {
    size_t len;
    char str[];
};

/*
 * =============================================================================
 * Syscall wrappers not provided by glibc
 * =============================================================================
 */

static int
perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static int
pidfd_open(pid_t pid, unsigned int flags)
{
    return syscall(SYS_pidfd_open, pid, flags);
}

static int
pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
    return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

/*
 * =============================================================================
 * Message i/o routines
 * =============================================================================
 */

/* Reads a message from the socket. Returns -1 on error, 0 if there is no
 * message to be read (either because the socket is nonblocking, or the
 * remote end is closed), and 1 if a message is returned. */
static int
read_socket_message(int socket_fd, struct perf_helper_msg *msg_out, struct strbuf *errbuf)
{
    char strerror_buf[256];
    union {
        struct cmsghdr align;
        char buf[
          /* space for a SCM_CREDENTIALS message */
          CMSG_SPACE(sizeof(struct ucred)) +
          /* space for SCM_RIGHTS */
          CMSG_SPACE(MAX_PERF_HELPER_FDS * sizeof(int))
        ];
    } cmsgbuf;
    memset(&cmsgbuf.buf, 0, sizeof(cmsgbuf.buf));

    struct iovec iov;
    iov.iov_base = &msg_out->body;
    iov.iov_len = sizeof(struct perf_helper_msg_body);

    struct msghdr socket_msg;
    socket_msg.msg_name = NULL;
    socket_msg.msg_namelen = 0;
    socket_msg.msg_iov = &iov;
    socket_msg.msg_iovlen = 1;
    socket_msg.msg_control = cmsgbuf.buf;
    socket_msg.msg_controllen = sizeof(cmsgbuf.buf);
    socket_msg.msg_flags = 0;

    int r;
    while (true) {
        r = recvmsg(socket_fd, &socket_msg, 0);
        if (r == -1 && errno == EINTR) {
            continue;
        }
        if (r == -1 && errno == EWOULDBLOCK) {
            return 0;
        }
        if (r == -1) {
            snprintf(errbuf->str, errbuf->len,
                     "error reading setup request message: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            return -1;
        }
        if (r == 0) {
            return 0;
        }
        break;
    }


    if (r < (int)sizeof(struct perf_helper_msg_body)) {
        snprintf(errbuf->str, errbuf->len,
                 "received message too small (%d bytes)", r);
        return -1;
    }

    msg_out->ancdata.have_creds = false;
    msg_out->ancdata.fd_count = 0;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&socket_msg);
    while (cmsg) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
            size_t body_len = cmsg->cmsg_len - sizeof(struct cmsghdr);
            if (body_len != sizeof(struct ucred)) {
                snprintf(errbuf->str, errbuf->len,
                         "size of SCM_CREDENTIALS message wrong (got %zu)", body_len);
                return -1;
            }
            memcpy(&msg_out->ancdata.creds, CMSG_DATA(cmsg), cmsg->cmsg_len);
            msg_out->ancdata.have_creds = true;
        } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            int num_fds = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);
            if (num_fds + msg_out->ancdata.fd_count > MAX_PERF_HELPER_FDS) {
                snprintf(errbuf->str, errbuf->len,
                         "too many fds in SCM_RIGHTS message(s)");
                return -1;
            }
            int *fd_mem = msg_out->ancdata.fds + msg_out->ancdata.fd_count;
            memcpy(fd_mem, CMSG_DATA(cmsg), cmsg->cmsg_len);
            msg_out->ancdata.fd_count += num_fds;
        }
        
        cmsg = CMSG_NXTHDR(&socket_msg, cmsg);
    }
    return 1;
}

/* Write a message to the socket. Returns 1 if the message was written,
 * -1 on error, or 0 if the message was not written because it would block
 *  & the socket is nonblocking (shouldn't be possible - we put the socket
 *  into blocking mode on startup */
static int
write_socket_message(int socket_fd, struct perf_helper_msg *msg, struct strbuf *errbuf)
{
    char strerror_buf[256];
    union {
        struct cmsghdr align;
        char buf[
          /* space for a SCM_CREDENTIALS message */
          CMSG_SPACE(sizeof(struct ucred)) +
          /* space for SCM_RIGHTS */
          CMSG_SPACE(MAX_PERF_HELPER_FDS * sizeof(int))
        ];
    } cmsgbuf;
    memset(&cmsgbuf.buf, 0, sizeof(cmsgbuf.buf));
    struct iovec iov;
    iov.iov_base = &msg->body;
    iov.iov_len = sizeof(struct perf_helper_msg_body);

    struct msghdr socket_msg;
    socket_msg.msg_name = NULL;
    socket_msg.msg_namelen = 0;
    socket_msg.msg_iov = &iov;
    socket_msg.msg_iovlen = 1;
    socket_msg.msg_control = cmsgbuf.buf;
    socket_msg.msg_controllen = sizeof(cmsgbuf.buf);
    socket_msg.msg_flags = 0;

    size_t controllen = 0;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&socket_msg);

    if (msg->ancdata.have_creds) {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_CREDENTIALS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
        memcpy(CMSG_DATA(cmsg), &msg->ancdata.creds, sizeof(struct ucred));
        controllen += CMSG_ALIGN(cmsg->cmsg_len);
        cmsg = CMSG_NXTHDR(&socket_msg, cmsg);
    }
    if (msg->ancdata.fd_count > 0 && msg->ancdata.fd_count < MAX_PERF_HELPER_FDS) {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        int data_len = msg->ancdata.fd_count * sizeof(int);
        cmsg->cmsg_len = CMSG_LEN(data_len);
        memcpy(CMSG_DATA(cmsg), msg->ancdata.fds, data_len);
        controllen += CMSG_ALIGN(cmsg->cmsg_len);
        cmsg = CMSG_NXTHDR(&socket_msg, cmsg);
    }
    socket_msg.msg_controllen = controllen;
    if (controllen == 0) {
        socket_msg.msg_control = NULL;
    }

    int r;
    while (true) {
        r = sendmsg(socket_fd, &socket_msg, 0);
        if (r == -1 && errno == EINTR) {
            continue;
        }
        if (r == -1 && errno == EWOULDBLOCK) {
            return 0;
        }
        if (r == -1) {
            snprintf(errbuf->str, errbuf->len,
                     "sendmsg(2) failed: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            return -1;
        }
        break;
    }
    return 1;
}

/*
 * =============================================================================
 * PID and credential validation routines
 * =============================================================================
 */

static int
validate_socket_peercred_matches_parent(int socket_fd, struct strbuf *errbuf)
{
    struct ucred creds;
    socklen_t sizeof_ucred = sizeof(struct ucred);
    int r = getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &creds, &sizeof_ucred);
    if (r == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "could not get percred from socket: %s", strerror(errno));
        return -1;
    }
    pid_t parent_pid = getppid();
    if (creds.pid != parent_pid) {
        snprintf(errbuf->str, errbuf->len,
                 "socket credentials pid %d did not match parent pid %d", creds.pid, parent_pid);
        return -1;
    }
    return 0;
}

__attribute__(( format(scanf, 3, 5) ))
static int
read_pattern_from_procfile(int at, const char *fname, const char *pattern, struct strbuf *errbuf, ...)
{
    va_list args;
    va_start(args, errbuf);
    int ret = 0, err = 0;
    FILE *f = NULL;
    int fd = openat(at, fname, O_RDONLY);
    if (fd == -1) {
        err = errno;
        snprintf(errbuf->str, errbuf->len,
                 "error opening %s: %s", fname, strerror(errno));
        ret = -1;
        goto out;
    }
    f = fdopen(fd, "r");
    bool partline = false;
    char linebuf[256];
    while (!feof(f)) {
        if (fgets(linebuf, sizeof(linebuf), f) == NULL) {
          snprintf(errbuf->str, errbuf->len,
                   "error reading file %s: %s", fname, strerror(ferror(f)));
          ret = -1;
          goto out;
        }
        if (!partline) {
            if (vsscanf(linebuf, pattern, args) > 0) {
                ret = 1;
                goto out;
            }
        }
        partline = !strchr(linebuf, '\n');
    }
out:
    va_end(args);
    if (f) {
        fclose(f);
    }
    errno = err;
    return ret; 
}

static int
pidfd_alive(int pidfd, pid_t pidfd_pid, struct strbuf *errbuf)
{
    if (pidfd_send_signal(pidfd, 0, NULL, 0) < 0) {
        /* means there could be pid re-use */
        snprintf(errbuf->str, errbuf->len,
                 "pidfd_send_signal(2) failed (pid %d exited?): %s", pidfd_pid, strerror(errno));
        return -1;
    }

    return 0;
}

static int
thread_metadata_dir_alive(int meta_dirfd, pid_t tid, struct strbuf *errbuf)
{
    int f = openat(meta_dirfd, "status", O_RDONLY);
    if (f == -1) {
        int err = errno;
        snprintf(errbuf->str, errbuf->len,
                 "openat(2) check on thread failed (thread %d exited?): %s", tid, strerror(errno));
        errno = err;
        return -1;
    }
    close(f);
    return 0;
}

static int
validate_pidfd_pid_matches(pid_t pid, int pidfd, struct strbuf *errbuf)
{
    /* First, need to find what pid this pidfd is for */
    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/self/fdinfo/%d", pidfd);
    pid_t pidfd_pid;
    int r = read_pattern_from_procfile(AT_FDCWD, fname, "Pid: %d", errbuf, &pidfd_pid);
    if (r == -1) {
        return r;
    } else if (r == 0) {
        snprintf(errbuf->str, errbuf->len,
                 "Pid: line not in %s (not a pidfd?)", fname);
        return -1;
    }

    if (pidfd_pid != pid) {
        snprintf(errbuf->str, errbuf->len,
                 "ucreds pid (%d) did not match pidfd pid (%d)", pid, pidfd_pid);
        return -1;
    }

    if (pidfd_alive(pidfd, pidfd_pid, errbuf) == -1) {
        return -1;
    }
    return 0;
}

static int
validate_creds_match_self(struct ucred creds, struct strbuf *errbuf)
{
    uid_t uid = getuid();
    if (creds.uid != uid) {
        snprintf(errbuf->str, errbuf->len,
                 "uid does not match requester (%u vs %u)", creds.uid, uid);
        return -1;
    }
    uid_t gid = getuid();
    if (creds.gid != gid) {
        snprintf(errbuf->str, errbuf->len,
                 "gid does not match requester (%u vs %u)", creds.gid, gid);
        return -1;
    }
    return 0; 
}

/* returns -2 if the directory doesn't exist, -1 in some other error case,
 * or the fd if sucessful */
static int
open_thread_metadata_dir(pid_t pid, pid_t tid, struct strbuf *errbuf)
{
    char meta_dirname[PATH_MAX];
    snprintf(meta_dirname, sizeof(meta_dirname), "/proc/%d/task/%d", pid, tid);
    int r = open(meta_dirname, O_RDONLY | O_DIRECTORY);
    if (r == -1) {
        int err = errno;
        snprintf(errbuf->str, errbuf->len,
                 "error opening %s: %s (thread exited?)", meta_dirname, strerror(errno));
        errno = err;
        return -1;
    }
    return r;
}

static int
get_thread_tgid(int meta_dirfd, pid_t *tgid_out, struct strbuf *errbuf)
{
    int r = read_pattern_from_procfile(meta_dirfd, "status", "Tgid: %d", errbuf, tgid_out);
    if (r == -1) {
        return -1;
    } else if (r == 0) {
        snprintf(errbuf->str, errbuf->len,
                 "no Tgid line for thread");
        return -1;
    }
    return 0;
}

/*
 * =============================================================================
 * Main message handling functions
 * =============================================================================
 */

static int
handle_thread_exit(struct prof_data *state, pid_t tid, struct strbuf *errbuf)
{
    uintptr_t th_data_entry;
    int r = numtable_delete(&state->thread_table, tid, &th_data_entry);
    if (r == NUMTABLE_SLOT_NEW) {
        /* it wasn't in here?? */
        return 0;
    }
    struct thread_data *thdata = (struct thread_data *)th_data_entry;
    if (thdata->stack_sample_attachment) {
        bpf_link__detach(thdata->stack_sample_attachment);
    }
    if (thdata->perf_fd != -1) {
        close(thdata->perf_fd);
    }
    if (thdata->meta_dirfd != -1) {
        close(thdata->meta_dirfd);
    }
    bpf_map__delete_elem(state->stack_sample_skel->maps.thread_data, &tid, sizeof(pid_t), 0);
    free(thdata);
    return 0;
}

static int
handle_message_setup(struct prof_data *state, struct perf_helper_msg msg, struct strbuf *errbuf)
{
    int ret;
    int caller_pid_fd = -1;
    struct stack_sample_bpf *stack_sample_skel = NULL;

    /* Validate the credentials present in the message */
    if (!msg.ancdata.have_creds) {
        snprintf(errbuf->str, errbuf->len,
                 "did not receive SCM_CREDENTIALS message");
        ret = -1;
        goto out;
    }
    if (msg.ancdata.fd_count != 1) {
        snprintf(errbuf->str, errbuf->len,
                 "received wrong number of FDs (got %zu)", msg.ancdata.fd_count);
        ret = -1;
        goto out;
    }
    caller_pid_fd = msg.ancdata.fds[0];
    /* validate that the pidfd we got really is for the caller's pid, and that it's still live
     * and thus that there has been no pid reuse */
    if (validate_pidfd_pid_matches(msg.ancdata.creds.pid, caller_pid_fd, errbuf) == -1) {
        ret = -1;
        goto out;
    }
    /* also validate uid/gid are the same - this _should_ be a no-op */
    if (validate_creds_match_self(msg.ancdata.creds, errbuf) == -1) {
        ret = -1;
        goto out;
    }

    stack_sample_skel = stack_sample_bpf__open();
    if (stack_sample_skel == NULL) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to open stack sample bpf program: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    int r = bpf_map__set_max_entries(stack_sample_skel->maps.thread_data, msg.body.req_setup.max_threads);
    if (r < 0) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to resize thread_pids bpf map: %s", strerror(-r));
        ret = -1;
        goto out;
    }

    r = stack_sample_bpf__load(stack_sample_skel);
    if (r < 0) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to load stack sample bpf program: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    /* move all resources over to state so they don't get freed by
     * the out: block below. */
    state->caller_pid_fd = caller_pid_fd;
    caller_pid_fd = -1;
    state->stack_sample_skel = stack_sample_skel;
    stack_sample_skel = NULL;
    state->max_threads = msg.body.req_setup.max_threads;
    state->caller_creds = msg.ancdata.creds;
    state->caller_pid = msg.ancdata.creds.pid;

    struct perf_helper_msg res = { 0 };
    res.body.type = PERF_HELPER_MSG_RES_SETUP;
    res.ancdata.fd_count = 1;
    res.ancdata.fds[0] = bpf_map__fd(state->stack_sample_skel->maps.events);
    r = write_socket_message(state->socket_fd, &res, errbuf);
    if (r == -1) {
        ret = -1;
        goto out;
    }
    ret = 0;

out:
    if (stack_sample_skel) {
        stack_sample_bpf__destroy(stack_sample_skel);
    }
    if (caller_pid_fd != -1) {
        close(caller_pid_fd);
    }
    return ret;
}

static int
handle_message_newthread(struct prof_data *state, struct perf_helper_msg msg, struct strbuf *errbuf)
{
    int ret;
    int thread_dirfd = -1;
    int perf_fd = -1;
    pid_t thread_tid = 0;
    struct bpf_link *stack_sample_link = NULL;
    struct perf_helper_msg res = { 0 };
    res.body.type = PERF_HELPER_MSG_RES_NEWTHREAD;

    if (msg.ancdata.fd_count != 0) {
        snprintf(errbuf->str, errbuf->len,
                 "received wrong number of FDs (got %zu)", msg.ancdata.fd_count);
        ret = -1;
        goto out;
    }

    /* Open the proc directory for the thread to get metadata... */
    thread_tid = msg.body.req_newthread.thread_tid;
    thread_dirfd = open_thread_metadata_dir(state->caller_pid, thread_tid, errbuf);
    if (thread_dirfd == -1 && errno == ENOENT) {
        /* means that the thread exited before we processed the message (or was totally bogus
         * to begin with, no way to know). Return a response. */
        msg.body.res_newthread.success = 0;
        msg.body.res_newthread.message_len = snprintf(msg.body.res_newthread.message,
                                                      sizeof(msg.body.res_newthread.message),
                                                      "thread %d appeared dead", thread_tid);
        goto out_respond;
    }
    if (thread_dirfd == -1) {
        ret = -1;
        goto out;
    }

    /* verify that this thread belongs to the same process as we're connected to */
    pid_t thread_tgid;
    int r = get_thread_tgid(thread_dirfd, &thread_tgid, errbuf);
    if (r == -1 && errno == ENOENT) {
        /* thread might have died between the previous check and this one */
        msg.body.res_newthread.success = 0;
        msg.body.res_newthread.message_len = snprintf(msg.body.res_newthread.message,
                                                      sizeof(msg.body.res_newthread.message),
                                                      "thread %d appeared alive then dead",
                                                      thread_tid);
        goto out_respond;
    } else if (r == -1) {
        ret = -1;
        goto out;
    }

    if (thread_tgid != state->caller_pid) {
        /* pid re-use might have happened; this thread ID might now belong to a different
         * process */
        msg.body.res_newthread.success = 0;
        msg.body.res_newthread.message_len = snprintf(msg.body.res_newthread.message,
                                                      sizeof(msg.body.res_newthread.message),
                                                      "thread %d now belongs to pid %d (expected %d); reuse?",
                                                      thread_tid, thread_tgid, state->caller_pid);
        goto out_respond;
    }

    /* Check if we already have a profiling handle for this thread id */
    uintptr_t existing_entry_ptr;
    r = numtable_get(&state->thread_table, thread_tid, &existing_entry_ptr);
    if (r == NUMTABLE_FOUND) {
        struct thread_data *existing_entry = (struct thread_data *)existing_entry_ptr;
        /* stat our directory & their directory and see if it's the same one */
        struct stat existing_stat;
        struct stat new_stat;
        int r1, r2;
        r1 = fstat(thread_dirfd, &new_stat);
        r2 = fstat(existing_entry->meta_dirfd, &existing_stat);
        if (r1 == -1 || r2 == -1) {
            msg.body.res_newthread.success = 0;
            msg.body.res_newthread.message_len = snprintf(msg.body.res_newthread.message,
                                                          sizeof(msg.body.res_newthread.message),
                                                          "thread %d stat failed\n",
                                                          thread_tid);
            goto out_respond;
        }
        if (existing_stat.st_dev == new_stat.st_dev && existing_stat.st_ino == new_stat.st_ino) {
            /* This means we're calling newthread for a thread we're already tracking */
            msg.body.res_newthread.success = 1;
            goto out_respond;
        }
        /* Otherwise they're different, close off the existing one */
        r = handle_thread_exit(state, thread_tid, errbuf);
        if (r == -1) {
            /* this is unexpected and fatal */
            ret = -1;
            goto out;
        }
    }

    struct perf_event_attr perf_attr = { 0 };
    perf_attr.size = sizeof(struct perf_event_attr);
    perf_attr.type = PERF_TYPE_SOFTWARE;
    perf_attr.config = PERF_COUNT_SW_TASK_CLOCK;
    perf_attr.sample_freq = msg.body.req_newthread.interval_hz;
    perf_attr.freq = 1;
    perf_fd = perf_event_open(&perf_attr, thread_tid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd == -1 && errno == ESRCH) {
        msg.body.res_newthread.success = 0;
        msg.body.res_newthread.message_len = snprintf(msg.body.res_newthread.message,
                                                      sizeof(msg.body.res_newthread.message),
                                                      "thread %d exited before perf_event_open",
                                                      thread_tid);
        goto out_respond; 
    }
    else if (perf_fd == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "perf_event_open(2) for software clock event failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    /* check now that the _thread id_ didn't get re-used (since the start of the function) */
    r = thread_metadata_dir_alive(thread_dirfd, thread_tid, errbuf);
    if (r == -1 && errno == ENOENT) {
        msg.body.res_newthread.success = 0;
        msg.body.res_newthread.message_len = snprintf(msg.body.res_newthread.message,
                                                      sizeof(msg.body.res_newthread.message),
                                                      "thread %d exited after perf_event_open",
                                                      thread_tid);
        goto out_respond; 
    } else if (r == -1) {
        ret = -1;
        goto out;
    }

    /* and also check that the _pid_ didn't (potentially _before_ the start of the function) */
    if (pidfd_send_signal(state->caller_pid_fd, 0, NULL, 0) < 0) {
        snprintf(errbuf->str, errbuf->len,
                 "pidfd_send_signal(2) failed (pid %d exited?): %s", state->caller_pid,
                 strerror(errno));
        ret = -1;
        goto out;
    }

    
    stack_sample_link = bpf_program__attach_perf_event(state->stack_sample_skel->progs.stack_sample, perf_fd);
    if (!stack_sample_link) {
        snprintf(errbuf->str, errbuf->len,
                 "bpf attach failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }


    struct stack_sample_thread_data map_data;
    map_data.pid = thread_tid;
    map_data.ruby_cfp_ptr = msg.body.req_newthread.ruby_cfp_ptr;
    map_data.ruby_cfp_base_ptr = msg.body.req_newthread.ruby_cfp_base_ptr;
    r = bpf_map__update_elem(state->stack_sample_skel->maps.thread_data, &thread_tid, sizeof(pid_t),
                             &map_data, sizeof(struct stack_sample_thread_data),
                             0);
    if (r < 0) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to update ebpf map: %s", strerror(-r));
        ret = -1;
        goto out;
      }


    /* If we got here, save the FDs and null them out so they don't get closed
     * by the out: block */
    struct thread_data *thdata = xmalloc(sizeof(struct thread_data));
    thdata->tid = thread_tid;
    thdata->perf_fd = perf_fd;
    perf_fd = -1;
    thdata->meta_dirfd = thread_dirfd;
    thread_dirfd = -1;
    thdata->stack_sample_attachment = stack_sample_link;
    stack_sample_link = NULL;
    numtable_set(&state->thread_table, thread_tid, (uintptr_t)thdata, NULL);

    res.body.res_newthread.success = 1;
out_respond:
    /* Send the response message */
    r = write_socket_message(state->socket_fd, &res, errbuf);
    if (r == -1) {
        ret = -1;
        goto out;
    }
    ret = 0;
out:
    if (ret == -1 && thread_tid != 0) {
        /* on error, ensure we removed any pid we added to the bpf map */
        bpf_map__delete_elem(state->stack_sample_skel->maps.thread_data, &thread_tid, sizeof(pid_t), 0);
    }
    if (stack_sample_link) {
        bpf_link__detach(stack_sample_link);
    }
    if (thread_dirfd != -1) {
        close(thread_dirfd);
    }
    if (perf_fd != -1) {
        close(perf_fd);
    }
    return ret;
}

static int
handle_message_endthread(struct prof_data *state, struct perf_helper_msg msg, struct strbuf *errbuf)
{
    if (msg.ancdata.fd_count != 0) {
        snprintf(errbuf->str, errbuf->len,
                 "received wrong number of FDs (got %zu)", msg.ancdata.fd_count);
        return -1;
    }

    int r = handle_thread_exit(state, msg.body.req_endthread.thread_tid, errbuf);
    if (r == -1) {
        return -1;
    }

    struct perf_helper_msg res = { 0 };
    res.body.type = PERF_HELPER_MSG_RES_ENDTHREAD;
    r = write_socket_message(state->socket_fd, &res, errbuf);
    if (r == -1) {
        return -1;
    }
    return 0;
}

static int
handle_message(struct prof_data *state, struct perf_helper_msg msg, struct strbuf *errbuf)
{
    switch (msg.body.type) {
      case PERF_HELPER_MSG_REQ_SETUP:
        return handle_message_setup(state, msg, errbuf);
      case PERF_HELPER_MSG_REQ_NEWTHREAD:
        return handle_message_newthread(state, msg, errbuf);
      case PERF_HELPER_MSG_REQ_ENDTHREAD:
        return handle_message_endthread(state, msg, errbuf);
      default:
        snprintf(errbuf->str, errbuf->len,
                 "unknown received message type %d", msg.body.type);
        return -1;
    }
}

/*
 * =============================================================================
 * Event loop handling
 * =============================================================================
 */

static int
setup_event_loop(struct prof_data *state, struct strbuf *errbuf)
{
    /* event loop fd */
    state->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (state->epoll_fd == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to call epoll_create1(2): %s", strerror(errno));
        return -1;
    }
    /* The unix socketpair we listen on needs to be passed in as FD 3 */
    state->socket_fd = SOCKET_FD;
    state->socket_fd_epoll_data.fd = state->socket_fd;
    state->socket_fd_epoll_data.fd_type = EPOLL_FD_TYPE_SOCKET;
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.ptr = &state->socket_fd_epoll_data;
    int r = epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->socket_fd, &ev);
    if (r == -1) {
        snprintf(errbuf->str, errbuf->len,
                 "failed to arm socket_fd with epoll_ctl(2): %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int
run_event_loop(struct prof_data *state, struct strbuf *errbuf)
{
    while (true) {
        struct epoll_event event;
        int r = epoll_wait(state->epoll_fd, &event, 1, -1);
        if (r == -1 && errno == EINTR) {
            continue;
        }
        if (r == -1) {
            snprintf(errbuf->str, errbuf->len,
                     "failed to poll epoll_wait(2): %s", strerror(errno));
            return -1;
        }

        /* What fd fired? */
        struct event_loop_epoll_data *evdata = event.data.ptr;
        struct perf_helper_msg msg;
        switch (evdata->fd_type) {
          case EPOLL_FD_TYPE_SOCKET:
            /* handle message on main socket */
            r = read_socket_message(evdata->fd, &msg, errbuf);
            if (r == -1) {
                return -1;
            } else if (r == 0) {
                /* ?? no message was available in the end ?? */
                break;
            }
            r = handle_message(state, msg, errbuf);
            if (r == -1) {
                return -1;
            }
            break;
        }
    }
    return 0;
}

/*
 * =============================================================================
 * Main function & friends
 * =============================================================================
 */

static void
init_state(struct prof_data *state)
{
    memset(state, 0, sizeof(struct prof_data));
    state->epoll_fd = -1;
    state->socket_fd = -1;
    state->caller_pid_fd = -1;
    numtable_init(&state->thread_table, 16);
}

static int 
cleanup_thread_state_iter(int key, uintptr_t val, void *ctx)
{
    struct thread_data *data = (struct thread_data *)val;
    if (data->stack_sample_attachment) {
        bpf_link__detach(data->stack_sample_attachment);
    }
    if (data->perf_fd != -1) {
        close(data->perf_fd);
    }
    free(data);
    return NUMTABLE_ITER_CONTINUE;
}

static void
cleanup_state(struct prof_data *state)
{
    numtable_each(&state->thread_table, cleanup_thread_state_iter, NULL);
    if (state->stack_sample_skel) {
        stack_sample_bpf__destroy(state->stack_sample_skel);
    }
    if (state->caller_pid_fd != -1) {
        close(state->caller_pid_fd);
    }
    if (state->epoll_fd != -1) {
        close(state->epoll_fd);
    }
}


int
main(int argc, char **argv)
{
    /* See the comment in perf_helper.h for a description of the security checks taken
     * by this program to ensure that a calling program can't ask to profile a thread in a
     * different program */

    /* Start with some normal defence-in-depth stuff which is good practice for suid programs */
    /* We have no need for a process environment at all */
    clearenv();
    /* We don't use stdin/stdout at all */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    /* Don't need SIGPIPE, we'll find out that the socket is closed by error handling */
    signal(SIGPIPE, SIG_IGN);

    /* TODO - detach from terminal */

    /* Our stderr & socket fds come through as O_NONBLOCK, but we actually expect
     * blocking behaviour in this program */
    int fds[2] = { STDERR_FILENO, SOCKET_FD };
    for (int i = 0; i < 2; i++) {
        int fl_flags = fcntl(fds[i], F_GETFL);
        if (fl_flags == -1) {
            fprintf(stderr, "error calling fcntl(2) F_GETFL: %s", strerror(errno));
            exit(1);
        }
        fl_flags &= ~O_NONBLOCK;
        if (fcntl(fds[i], F_SETFL, fl_flags) == -1) {
            fprintf(stderr, "error calling fcntl(2) F_GETFL: %s", strerror(errno));
            exit(1);
        }
    }

    /* Our socket needs the SO_PASSCRED option set to enable it to receive SCM_CREDENTIALS */
    int one = 1;
    if (setsockopt(SOCKET_FD, SOL_SOCKET, SO_PASSCRED, &one, sizeof(int)) == -1) {
        fprintf(stderr, "error calling setsockopt(2) for SO_PASSCRED: %s", strerror(errno));
        exit(1);
    }

    /* Zero out our state structure */
    struct prof_data state;
    init_state(&state);
    struct strbuf *errbuf = alloca(sizeof(struct strbuf) + 512);
    errbuf->len = 512;
    errbuf->str[0] = '\0';

    /* Sets up our event loop infrastructure */
    if (setup_event_loop(&state, errbuf) == -1) {
        fprintf(stderr, "%s\n", errbuf->str);
        exit(1);
    }

    /* This check is not strictly speaking needed, but included in the interests of defence
     * in depth. Ensure that the socket we received was actually bound by our parent process.
     * Note that this is not at all a sufficient check on its own because if our parent process
     * had a socket pair that came e.g. from init (pid1), and promptly exited after forking us,
     * we might conclude that our parent (init) owns the socket and all is OK */
    if (validate_socket_peercred_matches_parent(state.socket_fd, errbuf) == -1) {
        fprintf(stderr, "%s\n", errbuf->str);
        exit(1);
    }

    /* Loop waiting for messages or closed processes */
    int ret;
    if (run_event_loop(&state, errbuf) == -1) {
        fprintf(stderr, "%s\n", errbuf->str);
        ret = 1;
    } else {
        ret = 0;
    }

    cleanup_state(&state);
    exit(ret);
    return 0;
}
