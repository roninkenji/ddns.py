from flask import Blueprint, request, current_app

import re
import os
import dns.query
import dns.update
import dns.name
import dns.rcode
import dns.tsigkeyring

bp = Blueprint('endpoints', __name__)

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

def make_update(action, hostname, record, data):
    # raise Exception('Domain is %s' % domainname)
    domain = current_app.config['DOMAIN'].encode('ascii')
    hostname = hostname.encode('ascii')
    D = dns.name.from_text(domain)
    H = dns.name.from_text(hostname)

    if H.is_subdomain(D):
        R = H.relativize(D)
    else:
        return "401 NOTAUTH %s - %s\n" % (D.to_text(), H.to_text()), 401

    keyring, algo = read_session_key("/etc/bind/keys/webapp.key")
    update = dns.update.Update(D, keyring=keyring, keyalgorithm=algo)
    if action == 'add':
       update.absent(R, record)
       update.add(R, 300, record, data.encode('ascii'))
    elif action == 'update':
       update.present(R, record)
       update.replace(R, 300, record, data.encode('ascii'))
    elif action == 'delete':
       update.present(R, record)
       update.delete(R, record)
    response = dns.query.tcp(update, '127.0.0.1')

    if response.rcode() == 0:
        return "NOERROR %s\n" % H.to_text(), 200
    else:
        return "%s %s\n" % (dns.rcode.to_text(response.rcode()), H.to_text())

@bp.route('/')
def _index():
    return "400 NOACTION %s" % current_app.config['DOMAIN'], 400

@bp.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'GET':
        r = request.args
    else:
        r = request.form
    hostname = r.get('hostname', '')
    if hostname == '' :
        return "400 NOHOSTNAME"
    record = r.get('record', 'a').lower()
    if record == 'a':
        data = r.get('ip', request.remote_addr)
    else:
        data = r.get('data', '')
    return make_update('add', hostname, record, data)

@bp.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == 'GET':
        r = request.args
    else:
        r = request.form
    hostname = r.get('hostname', '')
    if hostname == '' :
        return "400 NOHOSTNAME"
    record = r.get('record', 'a').lower()
    if record == 'a':
        data = r.get('ip', request.remote_addr)
    else:
        data = r.get('data', '')
    return make_update('update', hostname, record, data)

@bp.route('/delete', methods=['GET', 'POST'])
def delete():
    if request.method == 'GET':
        r = request.args
    else:
        r = request.form
    hostname = r.get('hostname', '')
    if hostname == '' :
        return "400 NOHOSTNAME"
    record = r.get('record', 'a').lower()
    # if record == 'a':
    #     data = r.get('ip', request.remote_addr)
    # else:
    #     data = r.get('data', '')
    return make_update('delete', hostname, record, '')

# if __name__ == "__main__":
#     app.run()
# else:
#     application = app.wsgifunc()
