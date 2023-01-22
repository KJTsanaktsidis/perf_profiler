# frozen_string_literal: true
require 'mkmf'

$INCFLAGS << " -I."
$defs << '-D_GNU_SOURCE'
$objs = [
  "linux.#{$OBJEXT}",
  "profile.#{$OBJEXT}",
  "profile_session.#{$OBJEXT}",
  "perf_helper_proxy.#{$OBJEXT}"
]

dir_config 'libbpf'
have_library 'bpf'
have_header 'bpf/bpf_helpers.h'

append_cflags '-fvisibility=hidden'

create_header
create_makefile('perf_profiler') do |mk|
  mk << <<~MAKEFILE
    PERF_HELPER_BIN = $(TARGET_SO_DIR)perf_helper

    perf_helper.o: perf_helper.c stack_sample.skel.h perf_helper.h
    \t$(ECHO) compiling $(<)
    \t$(Q) $(CC) $(INCFLAGS) $(CPPFLAGS) $(CFLAGS) -D_GNU_SOURCE $(COUTFLAG)$@ -c $(CSRCFLAG)$<

    $(PERF_HELPER_BIN): perf_helper.o
    \t$(ECHO) linking perf_helper
    \t-$(Q)$(RM) $(@)
    \t$(Q) $(CC) -o $@ $^ -lbpf

    vmlinux.h:
    \tbpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

    %.bpf.o: %.bpf.c vmlinux.h
    \tclang -g -O2 -target bpf $(INCFLAGS) $(CPPFLAGS) -c -o $@ $<

    %.skel.h: %.bpf.o
    \tbpftool gen skeleton $< > $@

    .PHONY: install-perf-helper
    install-perf-helper: $(PERF_HELPER_BIN)
    \t$(INSTALL_PROG) $(PERF_HELPER_BIN) $(RUBYARCHDIR)

    all: $(PERF_HELPER_BIN)
    install: install-perf-helper


    linux.o: profile.h
    perf_helper.o: perf_helper.h
    profile_session.o: profile.h
    perf_helper_proxy.o: perf_helper.h profile.h
  MAKEFILE
end

require 'extconf_compile_commands_json'
ExtconfCompileCommandsJson.generate!
ExtconfCompileCommandsJson.symlink!

