#
# Slasti-Forum -- the utilities package
#
# Copyright (C) 2011 Pete Zaitcev
# See file COPYING for licensing information (expect GPL 2).
#

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

