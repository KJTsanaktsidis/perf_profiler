# frozen_string_literal: true

require 'socket'
require 'tempfile'

module Profile
  class PerfHelperProxy

    attr_reader :helper_pid

    def initialize
      @lock = Mutex.new
      @helper_socket, helper_socket_remote = Socket.socketpair :AF_UNIX, :SOCK_SEQPACKET
      # Use an unlinked tempfile, rather than a pipe, to capture stderr, so we don't
      # need to worry about draining the pipe in a thread or in the event loop.
      @helper_stderr = Tempfile.new('perf_helper_prox')
      @helper_stderr.unlink
      @helper_pid = Process.spawn(
        perf_helper_bin_path,
        in: File.open("/dev/null", "r"),
        out: File.open("/dev/null", "w"),
        err: @helper_stderr,
        3 => helper_socket_remote,
        close_others: true,
      )
    rescue
      close rescue nil
      raise
    ensure
      helper_socket_remote&.close
    end

    def close
      @helper_socket&.close
      @helper_socket = nil
      if @helper_pid
        Process.kill :TERM, @helper_pid
        _, status = Process.waitpid2 @helper_pid
        @helper_pid = nil

        @helper_stderr.rewind
        @errmsg = @helper_stderr.read
        if @errmsg.empty? && !status.success?
          @errmsg = "perf_helper exited with status #{status.inspect}"
        end
      end
      @helper_stderr&.close
      @helper_stderr = nil
    end


    def setup
      body_bytes = _pack_msg_setup({
        max_threads: 1024
      })
      self_pidfd = Profile::Linux.pidfd_open(Process.pid)
      creds_ancdata = Socket::Credentials.for_process.as_ancillary_data
      rights_ancdata = Socket::AncillaryData.unix_rights(self_pidfd)
      _, fds = do_req_res body_bytes, [creds_ancdata, rights_ancdata]
      # [0] is the bpf ringbuffer fd.
      fds[0]
    end

    def newthread(thread)
      body_bytes = _pack_msg_newthread({
        interval_hz: 50,
        tid: thread.native_thread_id
      })
      do_req_res body_bytes
    end

    def endthread(thread)
      body_bytes = _pack_msg_endthread({
        tid: thread.native_thread_id
      })
      do_req_res body_bytes
    end

    private

    def reap_and_raise
      close
      raise @errmsg unless @errmsg.empty?
      false
    end

    def do_req_res(req_body, ancdata = [])
      @lock.synchronize do
        begin
          @helper_socket.sendmsg req_body, 0, nil, *ancdata
          res_body, _, _, *recvd_ancdata = @helper_socket.recvmsg(scm_rights: true)
        rescue => e
          reap_and_raise or raise
        end
        if res_body.size == 0
          # means socket is closed
          reap_and_raise or raise "unexpected EOF when reading from perf_helper"
        end
        fds = recvd_ancdata.flat_map { _1.unix_rights }
        return res_body, fds
      end
    end

    def perf_helper_bin_path
      @perf_helper_bin_path ||= begin
        ext_dir = File.dirname(File.realpath(_get_ext_path))
        File.join(ext_dir, "perf_helper#{RbConfig::CONFIG['EXEEXT']}")
      end
    end
  end
end
