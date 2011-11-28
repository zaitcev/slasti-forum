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

# XXX Generate a random admin password; it makes umask meaningful then.
umask 077

cat >$testconf <<EOF
[svc]
base = $base
socket = $sock
pidfile = $pidf
admin = testtest
EOF

# XXX implement lockfile to make sure we do not start twice
# Without the rm we fail with "socket.error: [Errno 98] Address already in use".
rm -f $sock
# This rm helps to fail if the server fails to write a good pidfile.
rm -f $pidf
PYTHONPATH=$(pwd) python ./svc/main.py "$testconf" &
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

cleanup () {
    kill $(cat $pidf)
}

# Test 1: basic operation
PYTHONPATH=$(pwd) python ./cli/main.py "$testconf" test1
if [ $? != 0 ]; then
    echo "FAILED: basic" >&2
    cleanup
    exit 1
fi

cleanup
exit 0
