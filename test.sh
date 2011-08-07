#!/bin/sh
#
# The recurrent post-hack test (this is what "make check" would do in C).

base=./testbase
testconf=./test.conf
pidf=./test.pid
sock=./test.sock

set +e

rm -rf $base
mkdir -p $base

cat >$testconf <<EOF
[svc]
base = $base
socket = $sock
pidfile = $pidf
EOF

# XXX implement lockfile to make sure we do not start twice
# Without the rm we fail with "socket.error: [Errno 98] Address already in use".
rm -f $sock
# This rm helps to fail if the server fails to write a good pidfile.
rm -f $pidf
python ./svc/main.py "$testconf" &
svcpid=$!

# XXX is this enough? too much?
sleep 3

if [ \! -s "$pidf" ]; then
    echo "Empty or missing pidfile" >&2
    kill $svcpid
    exit 1
fi

if [ "$svcpid" != $(cat $pidf) ]; then
    echo "PID mismatch: shell $svcpid pidfile" $(cat pidf) >&2
    exit 1
fi

# WRITE TESTS HERE

kill $(cat $pidf)

exit 0
