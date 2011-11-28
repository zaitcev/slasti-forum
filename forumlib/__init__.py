#
# Slasti-Forum -- the utilities package
#
# Copyright (C) 2011 Pete Zaitcev
# See file COPYING for licensing information (expect GPL 2).
#

# Copy out a bytearray of size bytes out of the list of strings.
# For now, do not requiest the size that is larger than the size available.
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

# Pull a bytearray from mbufs, in order to permit repeated pull calls.
def skb_pull(mbufs, size):
    v = bytearray(size)
    x = 0
    done = 0
    while done < size:
       mbuf = mbufs[0]
       steplen = size - done
       if len(mbuf) < steplen:
           steplen = len(mbuf)
       v[done:done+steplen] = mbuf[x:x+steplen]
       done += steplen
       x += steplen
       if x >= len(mbuf):
           x = 0
           mbufs.pop(0)
    if x != 0:
       mbuf = mbufs[0]	# unnecessary but feels safer
       mbufs[0] = mbuf[x:]
    return v
