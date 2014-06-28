#!/usr/bin/python
import web

import re
import os
import dns.query
import dns.update
import dns.name
import dns.rcode
import dns.tsigkeyring

urls = (
    '/(add)', 'ddns_handler',
    '/(update)', 'ddns_handler',
    '/(delete)', 'ddns_handler',
    '(.*)', 'debug',
)

app = web.application(urls, globals(), autoreload=False)

domain="way-of-the-blade.com"

def read_session_key(filename):
    # Attempt to parse the bind session.key file.

    # Read the whole file (expected to be small).
    session_key_file = open(filename, "r")
    session_key = session_key_file.read()
    session_key_file.close()

    # Remove any comments.
    session_key = re.sub(re.compile(r'/\*.*?\*/', re.S), '', session_key)
    session_key = re.sub(re.compile(r'//.*$', re.M), '', session_key)
    session_key = re.sub(re.compile(r'#.*$', re.M), '', session_key)

    # Try to find the "key" statement and get the key_id and contents.
    m = re.search(r'(?:^|;)\s*key\s+((?:"[^"]+")|(?:[^"]\S*))\s*{(.*?)}\s*;', session_key, flags = re.S)

    if (m is None):
        raise Exception('No "key" statement found in %(file)s.' % { "file": filename })

    key_id = m.group(1).strip('"')
    key_contents = m.group(2)

    # Inside the key statement, try to find the "algorithm" value.
    m = re.search(r'(?:^|;)\s*algorithm\s+((?:"[^"]+")|(?:[^"]\S*))\s*;', key_contents)

    if (m is None):
        raise Exception('No "algorithm" statement found inside the "key" statement in %(file)s.' % { "file": filename})

    keyalgo = m.group(1).strip('"')

    # Inside the key statement, try to find the "secret" value.
    m = re.search(r'(?:^|;)\s*secret\s+((?:"[^"]+")|(?:[^"]\S*))\s*;', key_contents)

    if (m is None):
        raise Exception('No "secret" statement found inside the "key" statement in %(file)s.' % { "file": filename})

    secret = m.group(1).strip('"')

    keyring = dns.tsigkeyring.from_text({ key_id: secret })
    return (keyring, keyalgo)

def make_update(action, query):
    hostname = query.hostname.encode('ascii')
    D = dns.name.from_text(domain)
    H = dns.name.from_text(query.hostname)

    if H.is_subdomain(D):
        R = H.relativize(D)
    else:
        return "400 NOTAUTH %s\n" % H.to_text()

    keyring, algo = read_session_key("/var/run/named/session.key")
    update = dns.update.Update(D, keyring=keyring, keyalgorithm=algo)
    if action == 'update':
       update.present(R, 'a')
       update.replace(R, 300, 'a', query.ip.encode('ascii'))
    elif action == 'delete':
       update.present(R, 'a')
       update.delete(R, 'a')
    elif action == 'add':
       update.absent(R, 'a')
       update.add(R, 300, 'a', query.ip.encode('ascii'))
    response = dns.query.tcp(update, '127.0.0.1')

    if response.rcode() == 0:
        return "NOERROR %s\n" % H.to_text()
    else:
        return "%s %s\n" % (dns.rcode.to_text(response.rcode()), H.to_text())

class debug:
    def GET(self, URI=""):
       return "URI: %s\n\n" % URI

class ddns_handler:
    def GET(self, action):
        query=web.input(ip=web.ctx['ip'], hostname=None, _unicode=False)
        if query.hostname == None:
            return "NOHOST\n"
        return make_update(action, query)
    
    def POST(self, action):
        query=web.input(ip=web.ctx['ip'], hostname=None, _unicode=False)
        if query.hostname == None:
            return "400 NOHOST\n"
        return make_update(action, query)
        
if __name__ == "__main__":
    app.run()
else:
    application = app.wsgifunc()

