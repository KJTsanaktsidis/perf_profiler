#include "extconf.h"

#include <errno.h>
#include <ruby.h>
#include <ruby/io.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "profile.h"

VALUE mProfileLinux;

static int
pidfd_open(pid_t pid, unsigned int flags)
{
    return syscall(SYS_pidfd_open, pid, flags);
}

static VALUE
profile_linux_s_pidfd_open(VALUE klass, VALUE pid_val)
{
    pid_t pid = NUM2PIDT(pid_val);
    int fd = pidfd_open(pid, 0);
    if (fd == -1) {
        rb_sys_fail("failed to call pidfd_open(2)");
    }
    return profile_wrap_fd_in_io(fd);
}


void
init_profile_linux(void)
{
    mProfileLinux = rb_define_module_under(mProfile, "Linux");
    rb_define_singleton_method(mProfileLinux, "pidfd_open", profile_linux_s_pidfd_open, 1);
}
