#ifndef __PROFILE_H
#define __PROFILE_H

#include <ruby.h>

extern VALUE mProfile;
extern VALUE cPerfHelperProxy;
extern VALUE cProfileSession;
extern VALUE mProfileLinux;

/* Like ruby_xmalloc, but can be used outside GVL */
static inline void *
malloc_or_die(size_t n)
{
    void *r = malloc(n);
    if (!r) { abort(); }
    return r;
}

static inline void *
realloc_or_die(void *ptr, size_t sz)
{
    void *r = realloc(ptr, sz);
    if (!r) { abort(); }
    return r;
}

/* Wraps IO::for_fd(fd, autoclose: true); used to create a ruby VALUE that takes
 * ownership of (and responsibility for closing & freeing) the specified FD. */
static inline VALUE
profile_wrap_fd_in_io(int fd)
{
    VALUE for_fd_kwargs = rb_hash_new();
    rb_hash_aset(for_fd_kwargs, rb_intern("autoclose"), Qtrue);
    VALUE args[2];
    args[0] = RB_INT2NUM(fd);
    args[1] = for_fd_kwargs;
    return rb_funcallv_kw(rb_cIO, rb_intern("for_fd"), 2, args, RB_PASS_KEYWORDS);
}

void init_perf_helper_proxy(void);
void init_profile_session(void);
void init_profile_linux(void);

#endif

