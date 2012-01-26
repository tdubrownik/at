#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import logging
import sqlite3
import threading
import traceback
from datetime import datetime
from wsgiref import simple_server
from pesto import Response, dispatcher_app
from time import sleep, time
from collections import namedtuple
from jinja2 import Environment, FileSystemLoader 

import config

dispatcher = dispatcher_app()
logger = logging.getLogger()
env = Environment(loader=FileSystemLoader('templates'))
conn = None
updater = None

from functools import wraps
def render(filepath):
    def decorator(f):
        @wraps(f)
        def func(request, *a, **kw):
            template = env.get_template(filepath)
            data = f(request, *a, **kw)
            return Response([template.render(**data)])
        return func
    return decorator

def strfts(ts, format='%d/%m/%Y %H:%M'):
    return datetime.fromtimestamp(ts).strftime(format)
env.filters['strfts'] = strfts

def setup_db():
    conn = sqlite3.connect(config.db)
    conn.row_factory = sqlite3.Row
    return conn

DeviceInfo = namedtuple('DeviceInfo', ['hwaddr', 'owner', 'ignored'])
User = namedtuple('User', ['login', 'passwd', 'url'])

def get_device_info(conn, hwaddr):
    return list(get_device_infos(conn, (hwaddrs,)))[0]

def get_device_infos(conn, hwaddrs):
    stmt = '''select hwaddr, name, ignored, login, url from 
        devices left join users on devices.owner = users.userid
        where devices.hwaddr in (''' + ','.join(['?'] * len(hwaddrs)) + ')'
    for row in conn.execute(stmt, hwaddrs):
        owner = User(row['login'], None, row['url']) if row['login'] else None
        ignored = row['ignored']
        yield DeviceInfo(row['hwaddr'], owner, ignored)

class Updater(threading.Thread):
    def __init__(self, cap_file, timeout, *a, **kw):
        self.cap_file = cap_file
        self.timeout = timeout
        self.lock = threading.Lock()
        self.active = {}
        threading.Thread.__init__(self, *a, **kw)
    def purge_stale(self):
        now = time()
        for addr, atime in self.active.items():
            if now - atime > self.timeout:
                del self.active[addr]
    def get_active_devices(self):
        self.lock.acquire()
        self.purge_stale()
        r = dict(self.active)
        self.lock.release()
        return r
    def update(self, hwaddr):
        self.lock.acquire()
        self.active[hwaddr] = time()
        self.lock.release()
    def run(self):
        while True:
            try:
                f = open(self.cap_file, 'r', buffering=0)
                logger.info('Updater ready on cap file %s', self.cap_file)
                while True:
                    hwaddr = f.readline().strip()
                    if not hwaddr:
                        break
                    self.update(hwaddr)
                    logger.info('logged dhcp request from %s', hwaddr)
                logging.warning('Cap file %s closed, reopening', self.cap_file)
            except Exception as e:
                logging.error('Updater got an exception:\n' + \
                    traceback.format_exc(e))
                sleep(10.0)

@dispatcher.match('/', 'GET')
@render('main.html')
def now_at(request):
    devices = updater.get_active_devices()
    device_infos = list(get_device_infos(conn, devices.keys()))
    device_infos.sort(key=lambda di: devices.__getitem__)
    users = list(dict((info.owner, devices[info.hwaddr]) for info in device_infos 
        if info.owner and not info.ignored).iteritems())
    users.sort(key=lambda (u, a): a, reverse=True)
    unknown = set(devices.keys()) - set(d.hwaddr for d in device_infos)
    return dict(users=users, unknown=unknown)

port = 8080
if __name__ == '__main__':
    print env.list_templates()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    conn = setup_db()
    updater = Updater(config.cap_file, config.timeout)
    updater.start()
    server = simple_server.make_server('', port, dispatcher)
    server.serve_forever()
