#include "extconf.h"

#include <bpf/libbpf.h>
#include <errno.h>
#include <ruby.h>
#include <ruby/atomic.h>
#include <ruby/debug.h>
#include <ruby/io.h>
#include <ruby/thread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "profile.h"
#include "stack_sample.bpf.h"

VALUE cProfileSession;


struct ProfileSession {
    int event_loop_wakepipe_r_fd;
    int event_loop_wakepipe_w_fd;
    int ringbuffer_fd;
    rb_atomic_t flag_running;
    rb_atomic_t flag_exiting;
    rb_atomic_t flag_have_error;
    char eventloop_error[256];
};

static void
profile_session_mark(void *ctx)
{
    struct ProfileSession *sess = ctx;
}

static void
profile_session_compact(void *ctx)
{
    struct ProfileSession *sess = ctx;
}

static void
profile_session_free(void *ctx) {
    struct ProfileSession *sess = ctx;
    ruby_xfree(sess);
}

static size_t
profile_session_memsize(const void *ctx) {
    const struct ProfileSession *sess = ctx;
    return sizeof(*sess);
}

static const rb_data_type_t profile_session_data_type = {
    "Profile::Session",
    {
        profile_session_mark,
        profile_session_free,
        profile_session_memsize,
        profile_session_compact
    },
    0, 0, 0
};

static int
ringbuf_event_handler(void *ctx, void *data, size_t size)
{
    struct stack_sample_entry *entry = data;
    fprintf(stderr, "an event: pid %u tid %u, sample %llu\n", entry->pid, entry->tid, entry->sample_period);
    return 0;
}

static int
event_loop_drain_rpipe(struct ProfileSession *sess)
{
    char strerror_buf[128];
    while (true) {
        char buf[PIPE_BUF];
        int r = read(sess->event_loop_wakepipe_r_fd, buf, sizeof(buf));
        if (r == -1 && errno == EAGAIN) {
            return 0;
        }
        if (r == -1) {
            snprintf(sess->eventloop_error, sizeof(sess->eventloop_error),
                     "read(2) for wakepipe: %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            RUBY_ATOMIC_SET(sess->flag_have_error, 1);
            return -1;
        }
        if (r == 0) {
            return 0;
        }
   }
}

static void *
event_loop_thread_nogvl(void *ctxarg)
{
    struct ProfileSession *sess = ctxarg;
    char strerror_buf[128];
    int epoll_fd = -1;
    int ringbuf_epoll_fd = -1;
    int r;
    int is_running = 0;
    struct ring_buffer *ringbuf = NULL;


    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd == -1) {
        snprintf(sess->eventloop_error, sizeof(sess->eventloop_error),
                 "epoll_create1(2): %s", strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
        RUBY_ATOMIC_SET(sess->flag_have_error, 1);
        goto out;
    }

    struct epoll_event wakepipe_events;
    wakepipe_events.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    wakepipe_events.data.fd = sess->event_loop_wakepipe_r_fd;
    r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sess->event_loop_wakepipe_r_fd, &wakepipe_events);
    if (r == -1) {
        snprintf(sess->eventloop_error, sizeof(sess->eventloop_error),
                 "epoll_ctl(2) for wakepipe: %s",
                 strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
        RUBY_ATOMIC_SET(sess->flag_have_error, 1);
        goto out;
    }

    ringbuf = ring_buffer__new(sess->ringbuffer_fd, ringbuf_event_handler, sess, NULL);
    if (!ringbuf) {
        snprintf(sess->eventloop_error, sizeof(sess->eventloop_error),
                 "ring_buffer__new(3) failed: %s",
                 strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
        RUBY_ATOMIC_SET(sess->flag_have_error, 1);
        goto out;
    }
    ringbuf_epoll_fd = ring_buffer__epoll_fd(ringbuf);
    struct epoll_event ringbuf_events;
    ringbuf_events.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ringbuf_events.data.fd = ringbuf_epoll_fd;
    r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ringbuf_epoll_fd, &ringbuf_events);
    if (r == -1) {
        snprintf(sess->eventloop_error, sizeof(sess->eventloop_error),
                 "epoll_ctl(2) for ringbuf: %s",
                 strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
        RUBY_ATOMIC_SET(sess->flag_have_error, 1);
        goto out;
    }

    while (true) {
        struct epoll_event event;
        r = epoll_wait(epoll_fd, &event, 1, -1);
        if (r == -1) {
            snprintf(sess->eventloop_error, sizeof(sess->eventloop_error),
                     "epoll_wait(2): %s",
                     strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
            RUBY_ATOMIC_SET(sess->flag_have_error, 1);
            goto out;
        }
        if (event_loop_drain_rpipe(sess) == -1) {
            goto out;
        }

        /* check flags always */
        rb_atomic_t flag_running = RUBY_ATOMIC_FETCH_ADD(sess->flag_running, 0);
        rb_atomic_t flag_exiting = RUBY_ATOMIC_FETCH_ADD(sess->flag_exiting, 0);
        if (flag_exiting) {
            /* need to exit */
            break;
        }
        else if (flag_running && !is_running) {
            /* need to start */
        } else if (!flag_running && is_running) {
            /* need to stop */
        }

        if (event.data.fd == ringbuf_epoll_fd) {
            ring_buffer__poll(ringbuf, 0);
        }
    }

out:
    if (ringbuf) {
        ring_buffer__free(ringbuf);
    }
    if (epoll_fd != -1) {
        close(epoll_fd);
    }
    return NULL;
}

static void
event_loop_thread_wake(struct ProfileSession *sess)
{
    char wbuf[1] = { 'x' };
    write(sess->event_loop_wakepipe_w_fd, wbuf, 1);
}

static void
event_loop_thread_ubf(void *ctxarg)
{
    struct ProfileSession *sess = ctxarg;
    RUBY_ATOMIC_SET(sess->flag_exiting, 1);
    event_loop_thread_wake(sess);
}

static VALUE
event_loop_thread_main(void *ctxarg)
{
    struct ProfileSession *sess = ctxarg;
    rb_thread_call_without_gvl(event_loop_thread_nogvl, sess, event_loop_thread_ubf, sess);
    rb_atomic_t have_error = RUBY_ATOMIC_FETCH_ADD(sess->flag_have_error, 0);
    if (have_error) {
        rb_raise(rb_eRuntimeError, "error in event loop: %s", sess->eventloop_error);
    }
    return Qnil;
}

static VALUE
profile_session_s_alloc(VALUE klass)
{
    struct ProfileSession *sess;
    VALUE self = TypedData_Make_Struct(cProfileSession, struct ProfileSession,
                                       &profile_session_data_type, sess);

    return self;
}

static VALUE
profile_session_spawn_eventloop_thread(VALUE self)
{
    struct ProfileSession *sess;
    TypedData_Get_Struct(self, struct ProfileSession,
                         &profile_session_data_type, sess);

    VALUE rpipe = rb_ivar_get(self, rb_intern("@eventloop_wakepipe_r"));
    sess->event_loop_wakepipe_r_fd = RB_NUM2INT(rb_funcall(rpipe, rb_intern("fileno"), 0));
    VALUE wpipe = rb_ivar_get(self, rb_intern("@eventloop_wakepipe_w"));
    sess->event_loop_wakepipe_w_fd = RB_NUM2INT(rb_funcall(wpipe, rb_intern("fileno"), 0));
    VALUE ringbuf = rb_ivar_get(self, rb_intern("@ringbuffer_io"));
    sess->ringbuffer_fd = RB_NUM2INT(rb_funcall(ringbuf, rb_intern("fileno"), 0));

    RUBY_ATOMIC_SET(sess->flag_exiting, 0);
    RUBY_ATOMIC_SET(sess->flag_running, 0);
    return rb_thread_create(event_loop_thread_main, sess);
}

static VALUE
profile_session_signal_exit_eventloop_thread(VALUE self)
{
    struct ProfileSession *sess;
    TypedData_Get_Struct(self, struct ProfileSession,
                         &profile_session_data_type, sess);

    RUBY_ATOMIC_SET(sess->flag_exiting, 1);
    event_loop_thread_wake(sess);
    return Qnil;
}

static VALUE
profile_session_signal_start_eventloop_thread(VALUE self)
{
    struct ProfileSession *sess;
    TypedData_Get_Struct(self, struct ProfileSession,
                         &profile_session_data_type, sess);

    RUBY_ATOMIC_SET(sess->flag_running, 1);
    event_loop_thread_wake(sess);
    return Qnil;
}

static VALUE
profile_session_signal_stop_eventloop_thread(VALUE self)
{
    struct ProfileSession *sess;
    TypedData_Get_Struct(self, struct ProfileSession,
                         &profile_session_data_type, sess);

    RUBY_ATOMIC_SET(sess->flag_running, 0);
    event_loop_thread_wake(sess);
    return Qnil;
}

void init_profile_session(void)
{
    cProfileSession = rb_define_class_under(mProfile, "Session", rb_cObject);
    rb_define_alloc_func(cProfileSession, profile_session_s_alloc);
    rb_define_method(cProfileSession, "_spawn_eventloop_thread",
                     profile_session_spawn_eventloop_thread, 0);
    rb_define_method(cProfileSession, "_signal_exit_eventloop_thread",
                     profile_session_signal_exit_eventloop_thread, 0);
    rb_define_method(cProfileSession, "_signal_start_eventloop_thread",
                     profile_session_signal_start_eventloop_thread, 0);
    rb_define_method(cProfileSession, "_signal_stop_eventloop_thread",
                     profile_session_signal_stop_eventloop_thread, 0);
}
