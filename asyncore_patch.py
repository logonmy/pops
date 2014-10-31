import asyncore
from asyncore import socket_map
from asyncore import readwrite
from asyncore import poll
from asyncore import poll2
from errno import EINTR
import select
import socket


def poll_epoll(timeout=-1, _socket_map=None):
    if _socket_map is None:
        _socket_map = socket_map

    if timeout is not None:
        # timeout is in seconds
        timeout = int(timeout)

    epoll = select.epoll()

    # print 'map', map

    if _socket_map:
        for fd, obj in _socket_map.items():
            marks = 0
            if obj.readable():
                marks |= select.EPOLLET | select.EPOLLIN
            # accepting sockets should not be writable
            if obj.writable() and not obj.accepting:
                marks |= select.EPOLLET | select.POLLOUT
            if marks:
                # Only check for exceptions if object was either readable
                # or writable.
                marks |= select.EPOLLERR | select.EPOLLHUP
                epoll.register(fd, marks)

        try:
            events = epoll.poll(timeout=timeout)
        except socket.error, ex:
            if ex.errno != EINTR:
                raise
            events = {}

        for fd, event in events:
            # print 'fd:%d, event:%d' % (fd, event)
            dispatcher_obj = _socket_map.get(fd)
            if dispatcher_obj is None:
                continue
            readwrite(dispatcher_obj, event)


def loop(timeout=30.0, use_select=False, _socket_map=None, count=None):
    if _socket_map is None:
        _socket_map = socket_map

    poll_poll = poll2
    poll_select = poll

    if use_select:
        poll_fun = poll_select
    elif hasattr(select, 'epoll'):
        poll_fun = poll_epoll
    elif hasattr(select, 'poll'):
        poll_fun = poll_poll
    else:
        poll_fun = poll_select

    if count is None:
        while _socket_map:
            poll_fun(timeout, _socket_map)
    else:
        while _socket_map and count > 0:
            poll_fun(timeout, _socket_map)
            count = count - 1

asyncore.loop = loop