#
# Slasti-Forum tool.
#
# Copyright (C) 2011 Pete Zaitcev
# See file COPYING for licensing information (expect GPL 2).
#

import base64
import binascii
import hashlib
import json
import os
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
    inisect = "svc"

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
        cfg["admin"] = cfgpr.get(inisect, "admin")
    except NoSectionError:
        raise ConfigError("Unable to find section '%s'" % inisect)
    except NoOptionError, e:
        raise ConfigError(str(e))

    try:
        cfg["usock"] = cfgpr.get(inisect, "socket")
    except NoOptionError, e:
        cfg["usock"] = USOCK

    return cfg

# XXX Find a way to share this with svc/.
# Pull a bytearray of size bytes out of the list of strings, copy it out.
def skb_pull_copy(mbufs, size):
    v = bytearray(size)
    mx = 0
    x = 0
    done = 0
    while done < size:
       mbuf = mbufs[mx]
       steplen = size - done
       if len(mbuf) < steplen:
           steplen = len(mbuf)
       v[done:done+steplen] = mbuf[x:x+steplen]
       done += steplen
       x += steplen
       if x >= len(mbuf):
           x = 0
           mx += 1
    return v

# Pull a bytearray from mbufs and (in the future XXX) remove from mbufs,
# in order to permit repeated pull calls when the message length is known.
# XXX For now, we just do nothing... so it's the same deal as skb_pull_copy.
def skb_pull(mbufs, size):
    return skb_pull_copy(mbufs, size)

# Receive a FAP message, using the low-level framing.
# XXX The rougue client can hang us by sending a partial message and no data.
def rec_msg(sock):
    mbufs = []
    rcvd = 0

    while rcvd < 4:
        mbuf = sock.recv(4096)
        if mbuf == None:
            # Curious - does it happen? XXX
            print >>sys.stderr, "Received None"
            sys.exit(1)
        mbufs.append(mbuf)
        rcvd += len(mbuf)

    hdr = skb_pull_copy(mbufs, 4)

    # This produces a string if hdr is an str. Works great for bytearray.
    length = hdr[1]*256*256 + hdr[2]*256 + hdr[3]
    # This works if hdr is a string, fails for bytearray with struct.error.
    # length = struct.unpack("!I", hdr)[0] & 0xFFFFFF

    while rcvd < 4 + length:
        mbuf = sock.recv(4096)
        if mbuf == None:
            print >>sys.stderr, "Received None"
            sys.exit(1)
        mbufs.append(mbuf)
        rcvd += len(mbuf)

    buf = skb_pull(mbufs, 4 + length)

    # Is this a double copy? Not very efficient, if so.
    return str(buf[4:])

def send_msg(sock, struc):
    jmsg = json.dumps(struc)
    jlen = len(jmsg)
    if jlen >= 0x1000000:
        raise AppError("message too long")
    msg = struct.pack("!I%ds"%jlen, jlen, jmsg)
    sock.send(msg)

def send_login(sock, chbin, user, password):
    loghash = hashlib.sha256()
    loghash.update(chbin+password)
    # We use hex instead of base64 because it's easy to test in shell.
    logstr = loghash.hexdigest()
    struc = { "type": 1, "hash": "sha256", "user": user, "login": logstr }
    send_msg(sock, struc)

def send_newsec(sock, sect, title, desc):
    # No bundle for now.
    struc = { "type": 4, "name": sect, "title": title, "desc": desc }
    send_msg(sock, struc)

def send_newthread(sock, sect, subj):
    name = binascii.hexlify(os.urandom(4))
    struc = { "type": 7, "section": sect, "name": name, "subject": subj }
    send_msg(sock, struc)
    return name

def send_newmsg(sock, sect, thread, body):
    name = binascii.hexlify(os.urandom(4))
    struc = { "type": 6, "section": sect, "thread": thread,
              "name": name, "body": body }
    send_msg(sock, struc)

def send_quit(sock):
    send_msg(sock, { "type": 5 })

def do(cfg, cmd):
    ssock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    ssock.connect(cfg["usock"])

    if cmd == None:
        # XXX Actually better error out or print server stats or something
        pass
    if cmd == "test1":
        ##
        ## Login
        ##
        msg = rec_msg(ssock)
        struc = json.loads(msg)
        if struc['type'] != 0:
            print >>sys.stderr, \
                  "Expected type 0, received", struc['type']
            sys.exit(1)

        # XXX if not struc.has_key('challenge'): --- something
        chbin = base64.b64decode(struc['challenge'])
        send_login(ssock, chbin, "admin", cfg['admin'])

        msg = rec_msg(ssock)
        struc = json.loads(msg)
        if struc['type'] != 2:
            print >>sys.stderr, \
                  "Expected type 2 after login, received", struc['type']
            sys.exit(1)

        ##
        ## Create a section
        ##
        secname = "/test"
        send_newsec(ssock, secname, "Test", "A test section")
        msg = rec_msg(ssock)
        struc = json.loads(msg)
        if struc['type'] == 3:
            print >>sys.stderr, \
                  "Expected type 2 after new section, received NAK `%s'" % \
                  struc['error']
            sys.exit(1)
        if struc['type'] != 2:
            print >>sys.stderr, \
                  "Expected type 2 after new section, received", struc['type']
            sys.exit(1)

        ##
        ## Create a thread
        ##
        thrname = send_newthread(ssock, secname, "Test subject")
        msg = rec_msg(ssock)
        # P3
        print "received[%d]: "%len(msg), msg
        struc = json.loads(msg)
        if struc['type'] != 2:
            print >>sys.stderr, \
                  "Expected type 2 after new message, received", struc['type']
            sys.exit(1)

        ##
        ## Create a message
        ##
        msgname = send_newmsg(ssock, secname, thrname, "test body")
        msg = rec_msg(ssock)
        # P3
        print "received[%d]: "%len(msg), msg
        struc = json.loads(msg)
        if struc['type'] != 2:
            print >>sys.stderr, \
                  "Expected type 2 after new message, received", struc['type']
            sys.exit(1)

        ## XXX has to check if anything was actually written

        ##
        ## Quit
        ##
        send_quit(ssock)

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
