# frozen_string_literal: true

module Profile
  class Session
    def initialize
      @perf_helper = Profile::PerfHelperProxy.new
      # puts @perf_helper.instance_variable_get(:@helper_pid)
      # binding.irb
      @ringbuffer_io = @perf_helper.setup
      @eventloop_wakepipe_r, @eventloop_wakepipe_w = IO.pipe
      @eventloop_thread = _spawn_eventloop_thread
      @start_stop_lock = Mutex.new
    rescue
      close rescue nil
      raise
    end

    def close
      @eventloop_wakepipe_w&.close
      @eventloop_wakepipe_r&.close
      _signal_stop_eventloop_thread
      @eventloop_thread&.join
      @perf_helper&.close
      nil
    end

    def start
      @thread_begin_tp ||= TracePoint.new(:thread_begin, &method(:on_thread_begin))
      @thread_end_tp ||= TracePoint.new(:thread_end, &method(:on_thread_end))
      @thread_begin_tp.enable
      @thread_end_tp.enable
      Thread.list.each do |th|
        @start_stop_lock.synchronize do
          next if th.thread_variable_get(:profile_thread_terminating)
          next if th.thread_variable_get(:profile_thread_profiling)
          @perf_helper.newthread th 
        end
      end
    end

    def stop
      @thread_begin_tp&.disable
      @thread_end_tp&.disable
      Thread.list.each do |th|
        @start_stop_lock.synchronize do
          next unless th.thread_variable_get(:profile_thread_profiling)
          Thread.current.thread_variable_set(:profile_thread_profiling, false)
          @perf_helper.endthread th 
        end
      end
    end

    private

    def on_thread_begin(tracearg)
      @start_stop_lock.synchronize do
        return if Thread.current.thread_variable_get(:profile_thread_profiling)
        Thread.current.thread_variable_set(:profile_thread_profiling, true)
        @perf_helper.newthread Thread.current
      end
    end

    def on_thread_end(tracearg)
      @start_stop_lock.synchronize do
        Thread.current.thread_variable_set(:profile_thread_terminating, true)
        Thread.current.thread_variable_set(:profile_thread_profiling, false)
        @perf_helper.endthread Thread.current
      end
    end
  end
end
