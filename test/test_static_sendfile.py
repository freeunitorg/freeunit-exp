import os
import socket

from unit.applications.proto import ApplicationProto
from unit import port as port_map

client = ApplicationProto()

# Larger than a socket buffer, so the body takes more than one sendfile() call,
# and large enough that a truncated or mis-sized response is obvious.
BODY = 'abcdefghij' * 400_000


def conf(temp_dir):
    return client.conf(
        {
            'listeners': {'*:8080': {'pass': 'routes'}},
            'routes': [{'action': {'share': f'{temp_dir}/assets$uri'}}],
            'applications': {},
        }
    )


def prepare(temp_dir):
    os.makedirs(f'{temp_dir}/assets', exist_ok=True)

    with open(f'{temp_dir}/assets/big.bin', 'w', encoding='utf-8') as f:
        f.write(BODY)

    assert 'success' in conf(temp_dir), 'configure'


def test_static_sendfile_body(temp_dir):
    prepare(temp_dir)

    resp = client.get(url='/big.bin', buff_size=65536, read_timeout=60)
    assert resp['status'] == 200, 'status'
    assert len(resp['body']) == len(BODY), 'length'
    assert resp['body'] == BODY, 'body'


def test_static_sendfile_two_responses_one_connection(temp_dir):
    prepare(temp_dir)

    resp, sock = client.get(
        url='/big.bin',
        headers={'Host': 'localhost', 'Connection': 'keep-alive'},
        connection_close=False,
        start=True,
        framed=True,
        buff_size=65536,
        read_timeout=60,
    )
    assert resp['status'] == 200, 'first status'
    assert resp['body'] == BODY, 'first body'

    resp, sock = client.get(
        url='/big.bin',
        headers={'Host': 'localhost', 'Connection': 'keep-alive'},
        connection_close=False,
        sock=sock,
        start=True,
        framed=True,
        buff_size=65536,
        read_timeout=60,
    )
    assert resp['status'] == 200, 'second status'
    assert resp['body'] == BODY, 'second body'

    sock.close()


def test_static_sendfile_aborted_transfer(temp_dir):
    prepare(temp_dir)

    sock = socket.create_connection(
        ('127.0.0.1', port_map.port(port_map.base())), timeout=10
    )

    try:
        sock.sendall(b'GET /big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n')
        assert b'200' in sock.recv(1024), 'response started'

    finally:
        # Drop the connection in the middle of the body.  A file descriptor or a
        # pool the aborted response held shows up as the next request failing.
        sock.close()

    resp = client.get(url='/big.bin', buff_size=65536, read_timeout=60)
    assert resp['status'] == 200, 'request after the abort'
    assert resp['body'] == BODY, 'body after the abort'
