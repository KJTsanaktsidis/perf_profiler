#include "extconf.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <linux/sched.h>
#include <ruby.h>
#include <ruby/atomic.h>
#include <ruby/debug.h>
#include <ruby/io.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "perf_helper.h"
#include "profile.h"

VALUE cPerfHelperProxy;

static VALUE
helper_proxy_pack_msg_setup(VALUE self, VALUE params)
{
    struct perf_helper_msg_body msg = { 0 };
    msg.type = PERF_HELPER_MSG_REQ_SETUP;

    VALUE max_threads = Qnil;
    if (RB_TEST(params)) {
        max_threads = rb_hash_aref(params, rb_id2sym(rb_intern("max_threads")));
    }

    if (RB_TEST(max_threads)) {
        msg.req_setup.max_threads = (uint32_t)RB_NUM2UINT(max_threads);
    }

    return rb_str_new((const char *)&msg, sizeof(struct perf_helper_msg_body));
}

static VALUE
helper_proxy_pack_msg_newthread(VALUE self, VALUE params)
{
    struct perf_helper_msg_body msg = { 0 };
    msg.type = PERF_HELPER_MSG_REQ_NEWTHREAD;

    VALUE interval_hz = Qnil;
    VALUE tid = Qnil;
    VALUE thread = Qnil;
    if (RB_TEST(params)) {
        interval_hz = rb_hash_aref(params, rb_id2sym(rb_intern("interval_hz")));
        tid = rb_hash_aref(params, rb_id2sym(rb_intern("tid")));
        thread = rb_hash_aref(params, rb_id2sym(rb_intern("thread")));
    }

    if (RB_TEST(interval_hz)) {
        msg.req_newthread.interval_hz = RB_NUM2INT(interval_hz);
    }
    if (RB_TEST(tid)) {
        msg.req_newthread.thread_tid = RB_NUM2INT(tid);
    }

    if (RB_TEST(thread)) {
        msg.req_newthread.ruby_cfp_ptr = rb_cfpbuf_get_cfp_ptr(thread);
        msg.req_newthread.ruby_cfp_base_ptr = rb_cfpbuf_get_cfp_base_ptr(thread);
    }

    return rb_str_new((const char *)&msg, sizeof(struct perf_helper_msg_body));
}

static VALUE
helper_proxy_pack_msg_endthread(VALUE self, VALUE params)
{
    struct perf_helper_msg_body msg = { 0 };
    msg.type = PERF_HELPER_MSG_REQ_ENDTHREAD;

    VALUE tid = Qnil;
    if (RB_TEST(params)) {
        tid = rb_hash_aref(params, rb_id2sym(rb_intern("tid")));
    }

    if (RB_TEST(tid)) {
        msg.req_newthread.thread_tid = RB_NUM2INT(tid);
    }

    return rb_str_new((const char *)&msg, sizeof(struct perf_helper_msg_body));
}

static VALUE
helper_proxy_get_ext_path(VALUE self)
{
    Dl_info info;
    int r = dladdr(init_perf_helper_proxy, &info);
    if (r == 0) {
        rb_raise(rb_eRuntimeError, "profile library couldn't be looked up with dladdr(3)");
    }
    return rb_str_new_cstr(info.dli_fname); 
}

void init_perf_helper_proxy(void)
{
    cPerfHelperProxy = rb_define_class_under(mProfile, "PerfHelperProxy", rb_cObject);
    rb_define_method(cPerfHelperProxy, "_pack_msg_setup", helper_proxy_pack_msg_setup, 1);
    rb_define_method(cPerfHelperProxy, "_pack_msg_newthread", helper_proxy_pack_msg_newthread, 1);
    rb_define_method(cPerfHelperProxy, "_pack_msg_endthread", helper_proxy_pack_msg_endthread, 1);
    rb_define_method(cPerfHelperProxy, "_get_ext_path", helper_proxy_get_ext_path, 0);
}
