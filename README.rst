Tail over HTTP(S).

Use cases
=========

When access to log file(s) is shared via HTTP, or when only the
last part of a large file should be retrieved without transfering it all.

Look & feel
===========

Mimics GNU tail_ (at least as of GNU coreutils 8.21), with hints of curl_
where needed (ex: CA certificates).

Differences:

- There is no line notion, only bytes, therefor there is no `-n` nor
  `--max-unchanged-stats` options.
  Fetches 1024 bytes by default, instead of 10 lines.

- Follow is obviously done by name, not by descriptor.

- File accesses being more expensive than with typical tail, quadratic delay
  is available by specifying `--sleep-max-interval`.

.. _tail: http://www.gnu.org/software/coreutils/manual/html_node/tail-invocation.html
.. _curl: http://curl.haxx.se/
