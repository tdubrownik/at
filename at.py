#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import logging
import sqlite3
import threading
import traceback
import json
from datetime import datetime
from wsgiref import simple_server
from pesto import Response, dispatcher_app
from pesto.session import session_middleware
from pesto.session.memorysessionmanager import MemorySessionManager
from time import sleep, time
from collections import namedtuple
from jinja2 import Environment, FileSystemLoader 
from urllib import urlencode
from hashlib import sha256

import config

dispatcher = dispatcher_app()
app = session_middleware(MemorySessionManager())(dispatcher)
logger = logging.getLogger()
env = Environment(loader=FileSystemLoader('templates'),
    autoescape='html',
    extensions=['jinja2.ext.autoescape'])
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

def restrict_ip(prefix='', exclude=[], fail_response=Response(status=403)):
    def decorator(f):
        @wraps(f)
        def func(request, *a, **kw):
            r_addr = request.remote_addr
            if not r_addr.startswith(prefix) or r_addr in exclude:
                return fail_response
            return f(request, *a, **kw)
        return func
    return decorator

def strfts(ts, format='%d/%m/%Y %H:%M'):
    return datetime.fromtimestamp(ts).strftime(format)
env.filters['strfts'] = strfts

def setup_db():
    conn = sqlite3.connect(config.db)
    conn.row_factory = sqlite3.Row
    conn.isolation_level = None # for autocommit mode
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
    def __init__(self,  timeout, *a, **kw):
        self.timeout = timeout
        self.lock = threading.Lock()
        self.active = {}
        threading.Thread.__init__(self, *a, **kw)
    def purge_stale(self):
        now = time()
        for addr, (atime, ip, name) in self.active.items():
            if now - atime > self.timeout:
                del self.active[addr]
    def get_active_devices(self):
        self.lock.acquire()
        self.purge_stale()
        r = dict(self.active)
        self.lock.release()
        return r
    def get_device(self, ip):
        for hwaddr, (atime, dip, name) in \
            self.get_active_devices().iteritems():
            if ip == dip:
                return hwaddr, name
    def update(self, hwaddr, atime = None, ip = None, name = None):
        atime = atime or time()
        self.lock.acquire()
        self.active[hwaddr] = (atime, ip, name)
        self.lock.release()
        logger.info('updated %s with atime %s and ip %s',
            hwaddr, strfts(atime), ip)

class CapUpdater(Updater):
    def __init__(self, cap_file, *a, **kw):
        self.cap_file = cap_file
        Updater.__init__(self, *a, **kw)
    def run(self):
        while True:
            try:
                with open(self.cap_file, 'r', buffering=0) as f:
                    logger.info('Updater ready on cap file %s', self.cap_file)
                    while True:
                        hwaddr = f.readline().strip()
                        if not hwaddr:
                            break
                        self.update(hwaddr)
                logging.warning('Cap file %s closed, reopening', self.cap_file)
            except Exception as e:
                logging.error('Updater got an exception:\n' + \
                    traceback.format_exc(e))
                sleep(10.0)

class DnsmasqUpdater(Updater):
    def __init__(self, lease_file, lease_offset, *a, **kw):
        self.lease_file = lease_file
        self.lease_offset = lease_offset
        self.last_modified = 0
        Updater.__init__(self, *a, **kw)
    def run(self):
        import os
        while True:
            try:
                mtime = os.stat(self.lease_file).st_mtime
                if mtime > self.last_modified:
                    logger.info('Lease file changed, updating')
                    with open(self.lease_file, 'r') as f:
                        for line in f:
                            ts, hwaddr, ip, name, client_id = line.split(' ')
                            self.update(hwaddr, int(ts) - self.lease_offset, ip, name)
                self.last_modified = mtime
                sleep(3.0)
            except Exception as e:
                logging.error('Updater got an exception:\n' + \
                    traceback.format_exc(e))
                sleep(10.0)
                

@dispatcher.match('/', 'GET')
@render('main.html')
def main_view(request):
    return now_at(request)

@dispatcher.match('/api', 'GET')
def list_all(request):
    result = now_at(request)
    def prettify_user((user, atime)):
        return {
            'login': user.login,
            'timestamp': atime,
            'pretty_time': strfts(atime),
            'url': user.url,
        }
    result['users'] = map(prettify_user, result['users'])
    result['unknown'] = len(result['unknown'])
    del result['login']
    return Response(json.dumps(result))


def now_at(request):
    devices = updater.get_active_devices()
    device_infos = list(get_device_infos(conn, devices.keys()))
    device_infos.sort(key=lambda di: devices.__getitem__)
    users = list(dict((info.owner, devices[info.hwaddr][0]) for info in device_infos 
        if info.owner and not info.ignored).iteritems())
    users.sort(key=lambda (u, a): a, reverse=True)
    unknown = set(devices.keys()) - set(d.hwaddr for d in device_infos)
    return dict(users=users, unknown=unknown, login=request.session.get('login'))

restrict_to_hs = restrict_ip(prefix=config.claimable_prefix, 
    exclude=config.claimable_exclude)

@dispatcher.match('/register', 'GET')
@restrict_to_hs
@render('register.html')
def register_form(request):
    return request.form

@dispatcher.match('/register', 'POST')
@restrict_to_hs
def register(request):
    login = request['login']
    url = request['url']
    if 'wiki' in request.form:
        url = config.wiki_url % { 'login': login }
    try:
        conn.execute('insert into users (login, url, pass) values (?, ?, ?)',
            [login, url, sha256(request['password']).hexdigest()])
        return Response.redirect('/')
    except sqlite3.Error as e:
        request.form['error'] = 'Cannot add user - username taken?'
        return register_form(request)

@dispatcher.match('/login', 'GET')
@restrict_to_hs
@render('login.html')
def login_form(request):
    return request.form

def get_credentials(login, password):
    row = conn.execute('select userid from users where login = ? and pass = ?',
        [login, sha256(password).hexdigest()]).fetchone()
    return row and row['userid']

@dispatcher.match('/login', 'POST')
@restrict_to_hs
def login(request):
    login = request.get('login')
    pwd = request.get('password')
    goto = request.get('goto') or '/'
    userid = get_credentials(login, pwd)
    if userid:
        request.session['userid'] = userid
        request.session['login'] = login
        return Response.redirect(goto)
    else:
        request.form['error'] = 'Username or password invalid'
        return login_form(request)

@dispatcher.match('/logout', 'GET')
@restrict_to_hs
def logout(request):
    request.session.clear()
    return Response.redirect('/')

def login_required(f):
    @wraps(f)
    def func(request, *a, **kw):
        if 'userid' not in request.session:
            return Response.redirect('/login?' + 
                urlencode({'goto': request.path_info,
                    'error': 'You must log in to continue'}))
        return f(request, *a, **kw)
    return func

@dispatcher.match('/claim', 'GET')
@restrict_to_hs
@login_required
@render('claim.html')
def claim_form(request):
    hwaddr, name = updater.get_device(request.remote_addr)
    return { 'hwaddr': hwaddr, 'name': name, 
        'login': request.session['login'] }

@dispatcher.match('/claim', 'POST')
@restrict_to_hs
@login_required
@render('post_claim.html')
def claim(request):
    hwaddr, lease_name = updater.get_device(request.remote_addr)
    if not hwaddr:
        return { 'error': 'Invalid device.' }
    userid = request.session['userid']
    try:
        conn.execute('insert into devices (hwaddr, name, owner, ignored)\
            values (?, ?, ?, ?)', [hwaddr, request['name'], userid, False])
        return {}
    except sqlite3.Error as e:
        return { 'error': 'Could not add device! Perhaps someone claimed it?' }

port = 8080
if __name__ == '__main__':
    print env.list_templates()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    conn = setup_db()
    updater = DnsmasqUpdater(config.lease_file, config.lease_offset, config.timeout)
    updater.start()
    server = simple_server.make_server('', port, app)
    server.serve_forever()
