#
# Slasti-Forum tool.
#
# Copyright (C) 2011 Pete Zaitcev
# See file COPYING for licensing information (expect GPL 2).
#

import socket
import struct
import sys
from iniparse import ConfigParser
from ConfigParser import NoSectionError, NoOptionError, ParsingError

TAG = "forum-cli"
USOCK = "/tmp/slasti-forum.sock"

class AppError(Exception):
    pass

def Usage():
    print >>sys.stderr, "Usage: "+TAG+" slasti-forum.conf"
    sys.exit(2)

# config()

class ConfigError(Exception):
    pass

def config(cfgname):
    cfg = { }
    cfgpr = ConfigParser()
    try:
        cfgpr.readfp(open(cfgname))
    except IOError, e:
        raise ConfigError(str(e))
    except ParsingError, e:
        # The str(e) may be multiline here, but oh well.
        raise ConfigError("Unable to parse: " + str(e))

    try:
        cfg["usock"] = cfgpr.get("svc", "socket")
    except NoOptionError, e:
        cfg["usock"] = USOCK

    return cfg

# Pull a string of size bytes out of the list of strings, copy it out.
def skb_pull_copy(mbufs, size):
    v = bytearray(size)
    mx = 0
    x = 0
    done = 0
    while done < size:
       mbuf = mbufs[mx]
       v[done] = mbuf[x]
       done += 1
       x += 1
       if x >= len(mbuf):
           x = 0
           mx += 1
    return str(v)

# Receive a FAP message, using the low-level framing.
def rec_msg(sock):
    mbufs = []
    done = 0
    while done < 4:
        mbuf = sock.recv(4096)
        if mbuf == None:
            # Curious.... XXX
            print >>sys.stderr, "Received None"
            sys.exit(1)
        mbufs.append(mbuf)
        done += len(mbuf)

    hdr = skb_pull_copy(mbufs, 4)
    # P3
    print "header[%d]:" % len(hdr), hdr

    # This produces a string:
    # length = hdr[1]*256*256 + hdr[2]*256 + hdr[3]
    length = struct.unpack("!I", hdr)[0] & 0xFFFFFF
    # P3
    print "body[%d]" % length

    while done < length:
        mbuf = sock.recv(4096)
        if mbuf == None:
            print >>sys.stderr, "Received None"
            sys.exit(1)
        mbufs.append(mbuf)
        done += len(mbuf)

    # P3
    print "done"

    # return skb_pull(mbufs)

def do(cfg, cmd):
    ssock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    ssock.connect(cfg["usock"])
    # P3
    print "connected"

    if cmd == None:
        # XXX Actually better error out or print server stats or something
        pass
    if cmd == "test1":
        rec_msg(ssock)
    else:
        print >>sys.stderr, "Unknown command '" + cmd + "'"
        sys.exit(1)

def main(args):
    argc = len(args)
    if argc == 1:
        cfgname = args[0]
        cmd = None
    elif argc == 2:
        cfgname = args[0]
        cmd = args[1]
    else:
        Usage()

    try:
        cfg = config(cfgname)
    except ConfigError, e:   # This is our exception. Other types traceback.
        print >>sys.stderr, "Error in config file '" + cfgname + "':", e
        sys.exit(1)

    try:
        do(cfg, cmd)
    except AppError, e:
        print >>sys.stderr, TAG+":", e
        sys.exit(1)
    except KeyboardInterrupt:
        # The stock exit code is also 1 in case of signal, so we are not
        # making it any worse. Just stubbing the traceback.
        sys.exit(1)

# http://utcc.utoronto.ca/~cks/space/blog/python/ImportableMain
if __name__ == "__main__":
    main(sys.argv[1:])
