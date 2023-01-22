require 'perf_profiler'

s = Profile::Session.new
$x = 2
t1 = Thread.new { loop { $x = rand } }
s.start
sleep 2
t2 = Thread.new { loop { $x = rand } }
sleep 2
t1.kill
sleep 2
s.stop

