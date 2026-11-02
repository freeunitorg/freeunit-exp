import os

from unit.applications.tls import ApplicationTLS
from unit.option import option

prerequisites = {'modules': {'openssl': 'any'}}

client = ApplicationTLS()


def conf_ktls(value):
    return client.conf(
        {
            "listeners": {
                "*:8080": {
                    "pass": "routes",
                    "tls": {"certificate": "default", "ktls": value},
                }
            },
            "routes": [{"action": {"share": f'{option.temp_dir}/assets$uri'}}],
            "applications": {},
        }
    )


def test_tls_ktls_invalid():
    client.certificate()

    for value in ['true', 1, {}, [], None]:
        resp = conf_ktls(value)
        assert 'error' in resp, f'ktls {value!r} refused'
        assert resp['detail'].startswith(
            'The "ktls" value must be a boolean'
        ), f'ktls {value!r} detail'


def test_tls_ktls(temp_dir):
    client.certificate()

    os.makedirs(f'{temp_dir}/assets')

    # Larger than one TLS record, so the body takes several records.
    body = 'abcdefghij' * 100_000
    with open(f'{temp_dir}/assets/big', 'w', encoding='utf-8') as f:
        f.write(body)

    # The kernel "tls" module may be absent.  OpenSSL then keeps the
    # connection in user space, so only the response is checked.
    for value in [True, False]:
        assert 'success' in conf_ktls(value), f'ktls {value}'

        resp = client.get_ssl(url='/big', buff_size=65536)
        assert resp['status'] == 200, f'ktls {value} status'
        assert len(resp['body']) == len(body), f'ktls {value} length'
        assert resp['body'] == body, f'ktls {value} body'
