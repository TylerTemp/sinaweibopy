#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Python client SDK for SNS API using OAuth 2. Require Python 2.6/2.7.
'''

import gzip
import time
import json
import hmac
import hashlib
import logging
import mimetypes
import collections

try:
    from io import StringIO
except ImportError:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

try:
    from urllib.parse import quote
    from urllib.request import urlopen, Request
except ImportError:
    from urllib import quote
    from urllib2 import urlopen, Request

__version__ = '1.0.0'
__author__ = 'Liao Xuefeng (askxuefeng@gmail.com)'

try:
    unicode
except NameError:

    def is_unicode(s):
        return False

else:

    def is_unicode(s):
        return isinstance(s, unicode)


class JsonDict(dict):
    '''
    General json object that allows attributes to be bound to and also
    behaves like a dict.

    >>> jd = JsonDict(a=1, b='test')
    >>> jd.a
    1
    >>> jd.b
    'test'
    >>> jd['b']
    'test'
    >>> jd.c
    Traceback (most recent call last):
      ...
    AttributeError: 'JsonDict' object has no attribute 'c'
    >>> jd['c']
    Traceback (most recent call last):
      ...
    KeyError: 'c'
    '''
    def __getattr__(self, attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError(
                "'JsonDict' object has no attribute '%s'" % attr)

    def __setattr__(self, attr, value):
        self[attr] = value


class APIError(Exception):
    '''
    raise APIError if receiving json message indicating failure.
    '''
    def __init__(self, error_code, error, request):
        self.error_code = error_code
        self.error = error
        self.request = request
        super(APIError, self).__init__(error)

    def __str__(self):
        return 'APIError: %s: %s, request: %s' % (
            self.error_code, self.error, self.request)


def _parse_json(s):
    '''
    Parse json string into JsonDict.

    >>> r = _parse_json(r'{"name":"Michael","score":95}')
    >>> r.name
    u'Michael'
    >>> r['score']
    95
    '''
    return json.loads(
            s, object_hook=lambda pairs: JsonDict(pairs.items()))


def _encode_params(**kw):
    '''
    Do url-encode parameters

    >>> _encode_params(a=1, b='R&D')
    'a=1&b=R%26D'
    >>> _encode_params(a=u'\u4e2d\u6587', b=['A', 'B', 123])
    'a=%E4%B8%AD%E6%96%87&b=A&b=B&b=123'
    '''
    def _encode(L, k, v):
        if is_unicode(v):
            L.append('%s=%s' % (k, quote(v.encode('utf-8'))))
        elif isinstance(v, str):
            L.append('%s=%s' % (k, quote(v)))
        elif isinstance(v, collections.Iterable):
            for x in v:
                _encode(L, k, x)
        else:
            L.append('%s=%s' % (k, quote(str(v))))
    args = []
    for k, v in kw.items():
        _encode(args, k, v)
    return '&'.join(args)


def _encode_multipart(**kw):
    ' build a multipart/form-data body with randomly generated boundary '
    boundary = '----------%s' % hex(int(time.time() * 1000))
    data = []
    for k, v in kw.items():
        data.append('--%s' % boundary)
        if hasattr(v, 'read'):
            # file-like object:
            filename = getattr(v, 'name', '')
            content = v.read()
            data.append(('Content-Disposition: '
                         'form-data; name="%s"; filename="hidden"') % k)
            data.append('Content-Length: %d' % len(content))
            data.append('Content-Type: %s\r\n' % _guess_content_type(filename))
            data.append(content)
        else:
            data.append('Content-Disposition: form-data; name="%s"\r\n' % k)
            data.append(v.encode('utf-8') if isinstance(v, unicode) else v)
    data.append('--%s--\r\n' % boundary)
    return '\r\n'.join(data), boundary


def _guess_content_type(url):
    '''
    Guess content type by url.

    >>> _guess_content_type('http://test/A.HTML')
    'text/html'
    >>> _guess_content_type('http://test/a.jpg')
    'image/jpeg'
    >>> _guess_content_type('/path.txt/aaa')
    'application/octet-stream'
    '''
    OCTET_STREAM = 'application/octet-stream'
    n = url.rfind('.')
    if n == -1:
        return OCTET_STREAM
    return mimetypes.types_map.get(url[n:].lower(), OCTET_STREAM)


_HTTP_GET = 'GET'
_HTTP_POST = 'POST'
_HTTP_UPLOAD = 'UPLOAD'


def _read_http_body(http_obj):
    using_gzip = http_obj.headers.get('Content-Encoding', '') == 'gzip'
    body = http_obj.read()
    if using_gzip:
        gzipper = gzip.GzipFile(fileobj=StringIO(body))
        fcontent = gzipper.read()
        gzipper.close()
        return fcontent
    return body


def _http(method, url, headers=None, **kw):
    '''
    Send http request and return response text.
    '''
    boundary = None
    if method == 'UPLOAD':
        params, boundary = _encode_multipart(**kw)
    else:
        params = _encode_params(**kw)
    http_url = '%s?%s' % (url, params) if method == _HTTP_GET else url
    http_body = None if method == 'GET' else params
    logging.error('%s: %s' % (method, http_url))
    req = Request(http_url, data=http_body)
    req.add_header('Accept-Encoding', 'gzip')
    if headers:
        for k, v in headers.iteritems():
            req.add_header(k, v)
    if boundary:
        req.add_header(
                'Content-Type',
                'multipart/form-data; boundary=%s' % boundary)
    try:
        resp = urllib2.urlopen(req, timeout=5)
    except:
        return None
    else:
        return _read_http_body(resp)


class SNSMixin(object):

    def __init__(self, app_key, app_secret, redirect_uri):
        self._client_id = app_key
        self._client_secret = app_secret
        self._redirect_uri = redirect_uri

    def _prepare_api(self, method, path, access_token, **kw):
        raise NotImplementedError(
                "Subclass must implement '_prepare_api' method.")

    def on_http_error(self, e):
        try:
            r = _parse_json(_read_http_body(e))
        except:
            r = None
        if hasattr(r, 'error_code'):
            raise APIError(r.error_code, r.get('error', ''),
                           r.get('request', ''))
        raise e


class SinaWeiboMixin(SNSMixin):

    def get_authorize_url(self, redirect_uri, **kw):
        '''
        return the authorization url that the user should be redirected to.
        '''
        redirect = redirect_uri if redirect_uri else self._redirect_uri
        if not redirect:
            raise APIError('21305',
                           'Parameter absent: redirect_uri',
                           'OAuth2 request')
        response_type = kw.pop('response_type', 'code')
        return 'https://api.weibo.com/oauth2/authorize?%s' % _encode_params(
                client_id=self._client_id,
                response_type=response_type,
                redirect_uri=redirect, **kw)

    def _prepare_api(self, method, path, access_token, **kw):
        '''
        Get api url.
        '''
        headers = None
        if access_token:
            headers = {'Authorization': 'OAuth2 %s' % access_token}
        if '/remind/' in path:
            # sina remind api url is different:
            return (method,
                    'https://rm.api.weibo.com/2/%s.json' % path,
                    headers,
                    kw)
        if method == 'POST' and 'pic' in kw:
            # if 'pic' in parameter, set to UPLOAD mode:
            return ('UPLOAD',
                    'https://api.weibo.com/2/%s.json' % path,
                    headers,
                    kw)
        return method, 'https://api.weibo.com/2/%s.json' % path, headers, kw

    def request_access_token(self, code, redirect_uri=None):
        '''
        Return access token as a JsonDict: {"access_token":"your-access-token",
        "expires":12345678,"uid":1234}, expires is represented using standard
        unix-epoch-time
        '''
        redirect = redirect_uri or self._redirect_uri
        resp_text = _http('POST',
                          'https://api.weibo.com/oauth2/access_token',
                          client_id=self._client_id,
                          client_secret=self._client_secret,
                          redirect_uri=redirect,
                          code=code,
                          grant_type='authorization_code')
        r = _parse_json(resp_text)
        current = int(time.time())
        expires = r.expires_in + current
        remind_in = r.get('remind_in', None)
        if remind_in:
            rtime = int(remind_in) + current
            if rtime < expires:
                expires = rtime
        return JsonDict(access_token=r.access_token,
                        expires=expires,
                        uid=r.get('uid', None))

    def parse_signed_request(self, signed_request):
        '''
        parse signed request when using in-site app.

        Returns:
            dict object like {'uid': 12345, 'access_token': 'ABC123XYZ',
                              'expires': unix-timestamp},
            or None if parse failed.
        '''

        def _b64_normalize(s):
            appendix = '=' * (4 - len(s) % 4)
            return s.replace('-', '+').replace('_', '/') + appendix

        sr = str(signed_request)
        logging.info('parse signed request: %s' % sr)
        enc_sig, enc_payload = sr.split('.', 1)
        sig = base64.b64decode(_b64_normalize(enc_sig))
        data = _parse_json(base64.b64decode(_b64_normalize(enc_payload)))
        if data['algorithm'] != u'HMAC-SHA256':
            return None
        expected_sig = hmac.new(self.client_secret, enc_payload,
                                hashlib.sha256).digest()
        if expected_sig == sig:
            data.user_id = data.uid = data.get('user_id', None)
            data.access_token = data.get('oauth_token', None)
            expires = data.get('expires', None)
            if expires:
                data.expires = data.expires_in = time.time() + expires
            return data
        return None


class QQMixin(SNSMixin):

    def get_authorize_url(self, redirect_uri='', **kw):
        '''
        return the authorization url that the user should be redirected to.
        '''
        redirect = redirect_uri if redirect_uri else self._redirect_uri
        if not redirect:
            raise APIError('21305',
                           'Parameter absent: redirect_uri',
                           'OAuth2 request')
        response_type = kw.pop('response_type', 'code')
        return 'https://graph.qq.com/oauth2.0/authorize?%s' % _encode_params(
                client_id=self._client_id,
                response_type=response_type,
                redirect_uri=redirect,
                **kw)

    def _prepare_api(self, method, path, access_token, **kw):
        kw['access_token'] = access_token
        kw['oauth_consumer_key'] = self._client_id
        return method, 'https://graph.qq.com/%s' % path, None, kw

    def request_access_token(self, code, redirect_uri=None):
        '''
        Return access token as a JsonDict:
        {"access_token":"your-access-token","expires":12345678,"uid":1234},
        expires is represented using standard unix-epoch-time
        '''
        redirect = redirect_uri or self._redirect_uri
        resp_text = _http(
                'POST',
                'https://graph.qq.com/oauth2.0/token',
                client_id=self._client_id,
                client_secret=self._client_secret,
                redirect_uri=redirect,
                code=code,
                grant_type='authorization_code')

        return self._parse_access_token(resp_text)

    def refresh_access_token(self, refresh_token, redirect_uri=None):
        '''
        Refresh access token.
        '''
        redirect = redirect_uri or self._redirect_uri
        resp_text = _http(
                'POST',
                'https://graph.qq.com/oauth2.0/token',
                refresh_token=refresh_token,
                client_id=self._client_id,
                client_secret=self._client_secret,
                redirect_uri=redirect,
                grant_type='refresh_token')
        return self._parse_access_token(resp_text)
        # FIXME: get oauthid from
        # 'https://graph.z.qq.com/moc2/me?access_token=%s' % access_token

    def _parse_access_token(self, resp_text):
        '''parse access token from urlencoded str like
        access_token=abcxyz&expires_in=123000&other=true'''
        r = self._qs2dict(resp_text)
        access_token = r.pop('access_token')
        expires = time.time() + float(r.pop('expires_in'))
        return JsonDict(access_token=access_token, expires=expires, **r)

    def _qs2dict(self, text):
        qs = urlparse.parse_qs(text)
        return dict(((k, v[0]) for k, v in qs.iteritems()))

    def get_openid(self, access_token):
        resp_text = _http('GET',
                          'https://graph.z.qq.com/moc2/me',
                          access_token=access_token)
        r = self._qs2dict(resp_text)
        return r['openid']


class APIClient(object):
    '''
    API client using synchronized invocation.
    '''
    def __init__(self, mixin, app_key, app_secret, redirect_uri='',
                 access_token='', expires=0.0):
        self._mixin = mixin(app_key, app_secret, redirect_uri)
        self._access_token = str(access_token)
        self._expires = expires

    def set_access_token(self, access_token, expires):
        self._access_token = str(access_token)
        self._expires = float(expires)

    def get_authorize_url(self, redirect_uri='', **kw):
        '''
        return the authorization url that the user should be redirected to.
        '''
        return self._mixin.get_authorize_url(
                redirect_uri or self._mixin._redirect_uri, **kw)

    def request_access_token(self, code, redirect_uri=None):
        '''
        Return access token as a JsonDict:
        {
            "access_token": "your-access-token",
            "expires": 12345678, # represented using standard unix-epoch-time
            "uid": 1234 # other fields
        }
        '''
        r = self._mixin.request_access_token(code, redirect_uri)
        self._access_token = r.access_token
        return r

    def refresh_token(self, refresh_token):
        req_str = '%s%s' % (self.auth_url, 'access_token')
        r = _http('POST', req_str,
                  client_id=self.client_id,
                  client_secret=self.client_secret,
                  refresh_token=refresh_token,
                  grant_type='refresh_token')
        return self._parse_access_token(r)

    def is_expires(self):
        return not self.access_token or time.time() > self.expires

    def call_api(self, http_method, http_path, **kw):
        method, the_url, headers, params = self._mixin._prepare_api(
                http_method, http_path, self._access_token, **kw)
        logging.debug('Call API: %s: %s' % (method, the_url))
        try:
            resp = _http(method, the_url, headers, **params)
        except urllib2.HTTPError as e:
            return self._mixin.on_http_error(e)
        r = _parse_json(resp)
        if hasattr(r, 'error_code'):
            raise APIError(r.error_code,
                           r.get('error', ''),
                           r.get('request', ''))
        return r

    def __getattr__(self, attr):
        if hasattr(self._mixin, attr):
            return getattr(self._mixin, attr)
        return _Callable(self, attr)


class _Executable(object):

    def __init__(self, client, method, path):
        self._client = client
        self._method = method
        self._path = path

    def __call__(self, **kw):
        return self._client.call_api(self._method, self._path, **kw)

    def __str__(self):
        return '_Executable (%s %s)' % (self._method, self._path)

    __repr__ = __str__


class _Callable(object):

    def __init__(self, client, name):
        self._client = client
        self._name = name

    def __getattr__(self, attr):
        if attr == 'get':
            return _Executable(self._client, 'GET', self._name)
        if attr == 'post':
            return _Executable(self._client, 'POST', self._name)
        name = '%s/%s' % (self._name, attr)
        return _Callable(self._client, name)

    def __str__(self):
        return '_Callable (%s)' % self._name

    __repr__ = __str__


if __name__ == '__main__':
    import base64
    try:
        from io import BytesIO
    except ImportError:
        BytesIO = StringIO

    # import doctest
    # doctest.testmod()
    APP_KEY = '???'
    APP_SECRET = '???'
    access_token = '???'
    expires = 1393739173.5
    # c = APIClient(QQMixin, APP_KEY, APP_SECRET,
    #               'http://www.liaoxuefeng.com/auth/callback',
    #               access_token, expires)
    # print(c.get_openid(access_token))
    # r = c.user.get_user_info.get(openid=openid)
    #  test get:
    # r = c.statuses.home_timeline.get(count=10)
    # print(r)
    #  test post:
    # r = c.statuses.update.post(status=u'测试http post')
    # print(r)
    #  test upload:
    # r = c.statuses.upload.post(
    #   status='test upload pic',
    #   pic=StringIO(base64.b64decode(
    # '''iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAIAAAABc2X6AAAAGXRFWHRTb2Z0d2FyZQBBZG9
    # iZSBJbWFnZVJlYWR5ccllPAAALPBJREFUeNqEfAmYVOWV9t1qr67qpXql6W6gAdmVZgfFFXE
    # nGjXBKGPUmDijj8vEuCVqYsaMPnGNjtskOo8LiCbRRBExSDKKiiIq0DR023s3vVVvtd/1f79
    # zbhVO/sz/19MPdN+697vfd75z3vOe5V45u2KFZNuSosi5nOT1SrouGYbk8Uiq6gQC+BPH
    # 8YtsmjhHfGtZ+NbxenHE8XjEVaoqmaas6/hT0jQHf+JMHMGw9JWED67CgPSVjN8VxZFl2TAw
    # Dr4Sg8uyOM228R++EjPBNBxHnOA4+EaMJv6TxUHcF5fgh77CTfGPQ5eLC2lkcRxn4iuMiani
    # 1vjdMBRxP8tSMN1QyL3A55PpbDmdlnGNzyeuxBrwwbe4El9hRFqVGC6bxWyEdGi1Mi1exrcY
    # DQLC+RAEBsE8cByrxSzpRrhESaXE1DEViMPnc/x+sSj8sBwxGk1dpsWI2ePygoBwC/zgN
    # D5HUZRcTmYx0TrdO7K88C8JXcNBiYWHDwQP4eECHMS42IFQSOb9z2SwPLF4zJ7W6c4Di8QRWRZ7
    # jtFxHOPiIL7FUJmMWAaLD5MjGbMeyVghJoGDuJy2DpeLcfAnzsEEcBf8jgt5rpAsjrPK4E
    # +6o3uQhCvmBnlB3Hwj2nbWCPGD8UkjSAPxwzqD0bEw0mcxBEbExYYhp1JilrxRuFjThALTOa5
    # S4Bx MggbBjYUV4H6YE/7lGeOHF4ARsDB88C9Mg/cnPwc2LneikAj+py0VF/Iy+O7Y
    # f1yO33EVzuS74Ka4tSJ0VgxApuSQyFwtowkr7nZDGbJZh7/je2MZJEJsslNUBGUT68cmk
    # 9U5pA5sjQUR4Bcb36bTWIaSSGBMVg2HrMAdGUdwR5qB2BysnzUfIuPVYvN5nZgSjmMxLGX+k
    # OkKrQkGZVYEljt9xPkYHydDNxkL+CtIljECNixugyuxBllWsL34Ipt1zQBanUzCkoW
    # 2YDjMyTSV0VEX3khPXGvBPNjkfD6vBoUWuOJuC0+lYLrYB2wdxIezYM
    # Y4wurHukpw5d6OJirlcVHNZj0AC0iWrFSsgUGHAYUVmJbEB4+pNE0PC5FIHApLnaFInMTQ
    # B9vA4iGFcBjXeHRdy2TMbFYjDHN4W2DwZLcMsFiAYpp2IvF5KtWRyWDlEi0Sx2W2T
    # MJqcT62iFRDJvx04YcBgj9QK8IwiffKcVRFycryYV1PY2QWDYsPy8NN2ZuwkuNesGRWfl4UC
    # x3yxWmyrLnGAIHhB9JimyFFFYaqKFhkh2XtmDkzUF8/59Ch43t7GUv
    # cW7KzwcohfkX5fVmZ8rOf1Xg84Ycfjg0MWDgOqWHSsC5gPuMCBABpYt9wI+wn9hDX0hqE4mJA
    # lg5hIW4BA5vIZl9avLjirLOOdnU1bd0akGWbUZC8hkyKiam6fo5MVxwk2xS/E2KzMDXXBl
    # j2vC3kaYTWAaINw0yndy1ZcuZjj02NRgePHk1fcUUoHreKizGizB6P9FlxnOFcLvid72y44
    # AKMm2hpsZ55BgriEDyydblGhbuw5fO/hM9iWxiZyXmw8Qv/GQppivJRKLTm7rtPaGg
    # AHKVaW6UPPpCCQd46eXLS1QUWPfsXfOX3y2TJvIWuMgrQwqlEJ8QX7G+YcuB3Qp20ac46+
    # eRp0S
    # hsYkp1tX/2bCmTASaJZWAbgkGvZXlzOSiuR1Vrq6tZkEX4Cj+WBTX1ZjIQu8K6Q5h3jB
    # tgZrBqGA5tgrgvpgjgIN4iZplO29lscMaMOQ0NYvttO6Dr0GFhzMAaIkXCG2HNjNW0Ko
    # k8uUOI694lb3euwzzmrFn12bTIlsKyXN3cDE8idCWbVQ8fFvPDhHB+LvcXRRmvra2amC
    # jN5ToMI8TLkKTOcDiFBet6Ly4MBAABc2QZN7fZ1UP2BAHsHoWd094qRIkESvGHlBynlU
    # 9MZHM5P1YFBO3vZ67i+kUiSA6ZpOAUeZRiSxHnY3BmVhgZFirxSTgXaoxfgkHiHTJwX8
    # XsgczB4JS//tV4/nnvwoXSSy+pw8M2Rvf5sHvbwuHEnXcuXbYsPT7e09rq9fuXLF/OUy
    # 3btKlzxoyxoaGy6dMD4XA6lxvfsiW8bRu7pWMcEHMiIxRGjlky6kBdyaTZssCfAt3d40
    # ePFjc0OOSB2dbYoTL0sOG4rpugR6yFEZ4FhyPkO4UTFz4N/zJIwPt5PKosq6lUXNctyA
    # ZQ7ziT994LRbJNMwhAsm0tl4uYpm/dunVnnSWQoaxs3owZ0jc+RT7fyaed9s0j1uuvm6
    # xyRBgdJoYs6Dx7FfNjZ8FcQFHgjzAfr65DdhIWjIlZllrg5/jHNC0akMksVmFHoxhHwb
    # DM+XEv5t7kRDXmDxCk62CwQmhpLvdGWZm9enWktNQ2DBuKXVuL45rXa6VSmcHBXCoV6+
    # yc295uHD6s1tVJ5E6djg65pkaKRIRMW1udo0fFPY4ckVIp58sv7S++kBmZMAMYHvtP8n
    # NeQkqm8ZbjWMTDvB6PbpoDAELLata0GDktJxr9dMUKfdcuaN9oOFwiyzMmJsp9PtDUVC
    # YTgGu0LIOdHFE9l7GQAQs9gvHnFi2CbGzGNFyQyWi2vXnGjBm//vWy6dOl//2TlKTczT
    # dH33/frq0VwK5p6tdft6xfP+3BB+E2jI0bnb17MT/hjaC3uH006hTILXNSUjZvMNg8Nv
    # bl1Knlth0dHa00jCpsrNe717L2zJ5dvHIltlcpKzv/e9/z0rZPGEZXZ+fk2FhJRQW29+
    # iePXNffvnLVKp/xYq6gYHj9u2rg2IGAg5zCiKeQncYzDweTSKyjmkx/YC8rXh8Vn19E6
    # 8Wm3P4sJRMCkoEzccWjY9L06bJVVXheDzc34+vpI4ON3iQ5a6BgalMeKJRH9QP1hoIpM
    # DPsG+67ocJ+XymQAgK5jwenLN7cnLvpk3rr7wSujrY07O/s7P/nXfmffBByw9+cOlNN5
    # XnuVrhE/V4Fs6cWfhzYWPj8KFDdmnp1TfdNGGaB957L/7444t6ehxGZgpXZAoE2EVpTJ
    # iY2bsuKxKZv3evfsstSjKpdHVh/XBCKuSkaRYUAUbu9do1NfrQ0N/S6cSsWeXJZGxiwj
    # SMIUUZmT8/RPrTfe65n8XjxYnECFRx7lyoIzStaHLyhD17ai3LJgOGWg7r+v4LL/zhrb
    # cS1ZCmV1VJS5emgHznnnt+W1txV5cE9eEAq0AeoZnYA0wVKgndOXiweNu206ZMsZuaSk
    # 466cT16/sWLRq56qrynh4zEhG0HMZM8YmwXAHdK1ZwqCHGgmnRL1ByJ5GAxx+Gp/Z6cW
    # hEVaFaUbhlTYNfnZrLvTRnTsntt8+fOzeXTPa3teV0PVBcfPzChVFyfdBXuKUEPKrjVC
    # P2IG6clqSBP/95yl13AQ6wA4DXLxXF+s//bAL+4zM6au/Z47S1OXv22IcPA3Vs6NSUKf
    # CFRizm3H9/CE5+bMy4+Wb700/lfHwvYlIgvKZh8MyTT1YuW4Zv4ps3h3/xC/gXh3bRIa
    # fNYY/GvEximgZF55AILKKkZI9tf3reeTXFxWnLKp01y6coR/r6TJ8vqCjGc8/Vrl9/yo
    # knkgsqm11f/3eKB0Us0vWiAh+ig8FcbjpEwz4fik2gWlJaKr7r7tavvdbp7hbGhqs0Db
    # AiDKqtTbir9vbm115bev319q5d9ocfKgjgYIkADswWjJAwP5ROd73wQvGyZdCm8Nq19q
    # OPqkSNhEoXcEtVNTfC4gQFc24iW/bkZO+JJ37/rruC/wixUul0xR/+YM2eLYOEDA7CPc
    # K8nYkJzFvoDyKqRCIxNPT+CSfMOvvs2J//XOH3gzDZgO7OTqAXB2SQtxkIKKSr1q5dAH
    # mFeL+gmeSQOX52gNi5nNrdLXbi7bflQrSYT2IwHYYmal1dExMTFdGot7TUCIfloSGHWQ
    # bUlkHbNDUHrBi35/iOgzhavK1pq+Nxz5EjDm5z8KBwITU1NuQNJSkr8731ltPVZd98M+
    # gHpGuRDssUQioUmgCuPqyoqNi4sXHu3PHPPpMfekjhoBobywCJe+n6aElJXVGRMAF4Lw
    # 65OZwklyEIAuIKREuyXLJ3764bb1z5+ecKEJgNGD4mT+yYFIb6+8e6uipgIIDeykp1cF
    # BYK+ZPkKGAdUEowAA3pcJMIK/h0JmqlhbpW9+CmO3x8aQqUjIBgC3moetqURF2JqeqLT
    # BFWa60LOi5qQOI/TrOMc2saaanTVu3YAHQKLhoUQu0VJZLdb0sFLI40gIEYjH19cVMd0
    # dGWMMFQ6CghzM4bqrEsj6urKy/5prJeLzkwAFBVGC37Ns4dHPJjZUYG3OzYlOnSvv2sZ
    # 9nhiMUB/vorjOfJXSTJqaJZezz+fZNm1ai6+Pz52NmAXCSwUGs3O/1nnjoUNH4+IuzZ1
    # d8+9vFweDhw4eT7e0mNrakBDupYjaBQN1xxzH2qqtW9T7yiAhlBwcb//SnmSCnnF5T1Z
    # pk0kSAoaq56mpEBWYhCwn7hBqTumE/DcsqmT9/1aJFyQ0bnH37lEgE5ByqhzuKHaJUFD
    # QrRUrhgggznJISERdxSpDMOJ8WoPDNNQmPBxcnbHvvOeece8cdcKEgycWUB00SGuEn9+
    # KLh371qyX/9m/L2V2ffbZBx9V/ZPBBv//0s87i34ePP9669lqAjUBO3KunZzQeD1VUpD
    # dsSLz5ZvXkpMQGrOs5+Aioqq6XOM5exzFmzRJmu3RpHBoxMTGsaQHbrkZEAXzGymFZ4+
    # O7Z806M0+WACLMqzm0FgSb8Fhjgi5TgtNhBktmCVxZXVdXxQhBQb8ciRT19Qnxl5WBzT
    # dqmgfEA66CoksP+8lEQsgVR8bH5TlzJLJP8aFw3+npKXvxRZNTP8T7g5OTOqhLRUXZok
    # X777577xNPZCAIjwdcORmLeY87LhSJmD09ucrKiyjMDk6ffvCnP21ubq6YPx+M8OBXX0
    # 12dOhVVaGiolQ2O2/DhtqyMveOmDNkxxlyTsJxJifX1MSIJ3PymakfzAYENRxWsR5gL6
    # yfw06E/sBbICfYiM8nyGF5uQKggto4DhQVTJvxQx0fH1u40PP008VglJ9/bv7kJyI0ZT
    # yHEDEJSvebyeTgbbc1bNrkTnJiwoYcECHJMsKPoPT/+WAZKccJyvLf07HOTuPCC7EcOx
    # xWKMHs8hbE7ZwowO0ByzAGBUoF+4a/cpzheHxnJlPp9cK6gDSYHPSncmysFlSxpMSmkA
    # XeImGacRJQSNfLPR6LoTUYNL76avjAgeLVq+19++BInfJyptwS5dwcgi6vpkWef37ilF
    # OiiEAkqRYeS/CGOJslollBXcE9/pcPjDKcz93kKX4Szty6/36O/sFeJIqohYjJE1ECgF
    # MEFHw7lL+FdU0mk1uamlbfdVcsFOru6PAFAl7gh2kebm9v27WraffuCKEdrPqVlSsrTj
    # kFCmanUnXbty8EtgOKVbU0lRr+7DNn9WoTZyKCpYSDm6ZHlELhG1h+5OhR/YYbzMsugx
    # N29u+3cQnoOi6Bvxwbwx2lxkb59ts9jY3urn7yifn444KBlZbifBiasmIFOKZz4AACNb
    # u5WSgzbIrs9FgVie1IZBdOOMH1e9BY3mqv12uaB2U59dRTyxcv/r/lOuk4I7/4Rd2WLd
    # jVRCbTf++98y65hL/qGRoaBt/88kvYoZ1IvH/OOWf++79nP/tMuvZaQLdEiV64Ys68yJ
    # RSFd6IQn8Old2MfyEBBG3KZodmzvQ9/3wZItbWVuOKK4AUCrErcW0eDmRKFUqUSHCzGl
    # xgoDQzB4IineBSFo7+OcMCNTCMkKYVU/bQaW42vvMd/VvfMs87L3PTTdnJyYgsT7nkEi
    # MUghUUBQIznnwy9+677AqnVlTUP/TQeH29kkpZsAXskiR5Z8zADkssZiwMi+TYm1KzNr
    # loYdjQAk6AcrTAjgRWVlSU7uvrRUxGAZaA93AY/gaeT8RAsZigorAFXI5dZQrJiVcSAa
    # evZfbDEB/vtUtuOWgEj4Vnsu0kVAuY3dpqf/651NZm9/RYf/xjy+9/L3A+FlNIZwBgCK
    # qkW2/Vb7vN/uQTmFBZNBqZO9cCGzdNdXISJEwFf8zDNQSKgFGQJNgnthDRMkCFyijMw9
    # wEPWUmxL8IhnV9EhtISqFStUBsCYUEEhUxZfa0nF0gSuNwNh8qQF6Dq0i8QAqOyUdzOa
    # +QlFZxJ9Ir7IAPQ+N+ppkKhztHRo6n0pfMaYpsVsNuYBKvvWZu22ZMmwbuocEUsUjK3Q
    # MeMJQMLOScA1dYqPjqOkLeSSqUCv4A1OFAlRGOYg+9uDgGzMtXT8RSsU8Yjes+zMnyjo
    # crrG5QBIlAFpwJpmys5u5qnsRyhh07HMCNiabZ06Z9HA7rhmEZxoEZM05kCjE6KjE1VZ
    # RWy3p/8WKA7KpDh6IdHUZHh0jxOU42nR4MBlXKIkh0V4fqYO4iOf/GWXgchEC5hkxhEN
    # efXeaIP4NBT77IaAOloB1YJ3QYCsJlDXalXL6lfLObtMqvnxNggnhw2CBuwCIh08JAHl
    # VNjIwI7Z0xw/u73/FufLuurhrWArb8H//BqUJcdWDRorOfew5xf+dvflP1zDOCq6gqaM
    # DWaHT2RRdhgxxELfDVVEPmormb4uEMZj4NLnOVjFRA5iIwxI0jmcyY1zubUtZusoaTcP
    # lcMrNjLvS6dUnO+/K3hXNIrTQuz8L9OsxLqNwKidqQIn0Fs1k8b94xX79nj7V1q7Vzp0
    # zfArcWKUqFz+eXpMCNN4Lif/7WW4GOjq/mzVt4ww0rCeTt554T1l5U5JZUITuGEC585/
    # OPvL0y7xXmQFYHu8hms8bs2cWkgyIa5awN+1UWIimOW5SlcTgbyRkrsZHsDjFhkeLhJg
    # LWMciPS6SKglChGDtD8zOfesppbZVBuQA5CFayWYUywOJPx6nft0+/4w7rttuCkcipl1
    # 02dvHF7W1tG2tryyl9aW/bZr3/voAArqRzYZmXyrUCTqBCV0VKMScVnA1H6Y6jg3XV1j
    # KXElIG/gEyKDx0CK5YNVwTABJh/9i8TZE+c4N8qkXLvGC3/wHaz2UXKtIinp62fbve2K
    # h9+aW1ZYtLG3AmdAmRLVclScfg+jxvvKE3N6v/9E+eNWtKYrGmuXPF7NJpe/t28+GHJc
    # TiHPGza4XOM3Un8HTrspg0a2NRkc37TIYnLN2ywqwCJCaBf4yXnIvmFgyOscgKXDQtZD
    # U49Y1vISCBYUuWHGsWwd9UnhZngCHiCJMVcpXcViCzBnIhCmpJhSIxOY6ra2rkVauU0l
    # IJDgm60NEhc0GETQgLwDZy1ZsU262SE8Zw94lbNyzUk+H2stmB+fNjzz7rR1j/wgvWAw
    # 84kYjQBWIybL2FLLcb+gLtqSrKGQXhHbAE5jkieKA5udUAyqE6XBkulAKIeIrcNWdeuH
    # JDkbrLZnA+x9m4DZX8hRuA0RJndiN19hlYMDmzYwVrBhUemf/lrxhyGXUsy25sVKqrRT
    # afIz4GV272ALCBn1DngRAWnwBBUIcNC4V7FACBGjtesdp8Rccme+CCrTgCeMQacAHrTN
    # 7MZG5/4FpOvtjPGyjT1slcx4DLYZ+XL9ZxZdQdX3HbiDj5xBlGt9pC0rTZu0D1Wludlh
    # aZoE5iG+TMDrWUuDyEO1LYvTOSse4w6yL37na7CDfIlXEuZ0FAWAYLEpeRknDmhTsoRJ
    # 2S7800gCkrlefc6fK8WcysXVTFc4WIO2IlRJjcdDFmxj6TTFpLpYCLOiu85hbAuP2DK7
    # 2cpkIYipjF5tAqrxSCZlEOx3XR+Xoi02fFtexvJPFEeZZVNJ/owso9qZRX132plMqoxq
    # XzAlfhlRPpd3t/uN7LPWgse2a5+ayowq0j3H0EzMd68t1gqmke9Xq/xDncyEBe1+1ZY5
    # SiCr4my722PYH94JmzLTBHpsqjW+7G/nM/BfXukB+nsqhbrWYZc48QMXVRcVOUfkl6LR
    # J5OxaLY1ZseHmJSoUuAyrYs1IoVAd1G3BgJsGg8O34l4GaUhCuVpNCis3HnpOkMN2d8+
    # YN/epXI2VlWt5rFHilRIVOKNVANvv6eef1XXopN1OohoGDGncAshkzx8aFVC5nRBRZL7
    # e14xvdVEKlUylWMDWdTqbTfzj99BU33lhaXDzw2mvRJ59UuFqVTmvgzLpupdPQLom0Dr
    # LD1osSZiLhKTiYTAbOxmJVJPt0KLIRfQ2YPUJp7Jht+0jRhnK50PLlZ5x66tDgYOLWW/
    # 2RiM/rtRXFJA7vYRhLp3dVVW245ZY6TRt5993Q2FhKlicwH0mqDIV8imJREI5gxl0/Y5
    # toamFl4JwLFdq4R8LhRAwk5zhHA4ElV1yxhEJw+/LLs1u3ygik8JXP15dM7mho8Mdi5Q
    # MDGN1AjFVWli0rQ3gERfCPjoaGh+1czvR6546PT3Mck2kQkIY3wetNZ7NvVFbmFi8uNg
    # xfe7uezfZXVp528smi8nP22Tt6e3O9vYGBgfldXQ0IARznnVAoUVqa9PkqL7xwGlUkO2
    # +5peWDD6RYLFJfDz1vPnhw+fbtJbBteErYAgImbqYAmopGJAJPh9K8Tj695lo1oY6laZ
    # W6rlKoyNlAlQMuny9jmn9ateqUn/8cYfBIPD4xNqZ5PEVR8fGRNWYMY3R0NJvJePz+iY
    # MHh++6K5bNWpQAY7P0ZDLvVlVNfeSRE+fNg17Ek8mcaa4rLuZgEkNd+OMfI2RDEDO6bR
    # uC0AFI/L77Tj3zzLAkhfNZnuXnn4+fAvmFIiSgxlu2CE5GYMQNkQ55R60QRjn5Crrb8E
    # QQLQwvkykyTf13vzOWLBHs+fHHsXgRqchyIpM5/qKL5lRW4nAYgTh+vgljkuT3eEroW/
    # Gpqhpoa7MefdRB+MECxewdpyEWmz5vnkop3mo4f2wIlKWqyh0JBO7jjysCgYp9+wyPp1
    # qWa955x9/d7SxYIK1Y4Y4cj4taNCa0YAHCZq27u+jTTy0MRXrkdvcyvxAx/KJFMsVfBe
    # /HqRYPba9BjXm6omTS6Wx1tWWaSjwehGGbZiAcVi0rs3hx8OKLlSlTHMxyaEgwhJ4e+9
    # Ah4agbG+Vo1F682HPqqe7swUDvvFOmBrECbgvZL13qWbLEicdFum9gAORx5Pvfr/jRj+
    # AR9Isuco4cEedR76hM+Aoyb2ra8BNP1J92mrN/v3nddfbYmNjGykqR8Qb35Ow8JysLvW
    # nkqylrSTGXQ105TB6wno9M81B9va+42FZVMxTyVldrqqpFIqqmGfF4Lp0uHhlZ9be/FX
    # /yiQH2A/FhhYh7uYOYegodqnQYAKGHH55y5pkiSQq6mu+LPqYL2If//m9p5064VDUfMP
    # hefjm3fn0QLhZyhGZy9MM2STkZr2X5/+u/nKYm+fnntc5Os7RUXDs0BOAwoJUcPAKlKG
    # Bwb0fLFIkVmWpTrh9WFETCO/3+7muuOfPcc0so4vG6FYr/WUCUpOS998pbtvh4lvBDHM
    # RzBYPQWA8E/NlsfOvW2Lp1PiDk1KkWtpdidO6jZb4Bt9fn9/+tutobDlcPDlaMjPgHB4
    # euvDLr85nAfE2L+3wqgFrXU8GgAWsKBv3pdOXhw0Pnn99jGIPLl2NjVECjJNUNDZ2QTH
    # rZ6XBXMhw++B9TMVF5yDeqiX3mIBEb1dS0ceNGX77iLo2MSORXBaqNjsrl5VCeUDIZGh
    # 8fkOU9mmZHo9ifDMQJbVfVMLWkVqjqcbatwEkcOTI8OFhbVaUMDQnkZErDvXPw8YaRzO
    # XePP30k269tSoWGxkc7D58OIG9UtVASYkXhFyWcTwYDALtgqFQOBzWvF5A/HBvb39zc7
    # SycvmCBUHqgMGwI2Nj8bvvrn3/fYvdLTfQcEc8tXPnVbzQsW/bps+3rLVV2rwZblP+4g
    # vRjzMyolJ7s00eFWuwqquBdkNdXVtOP33ZD35QU1WF2fj8ACkPdiwxOZnOZDKjo32PPj
    # odNqaqKUBRVZW9e7fDSMFPFpDK4QeuaM26dQumivaQ8oYGbrr7f30wme7uymBw/rp1bo
    # MTfBgx3Gg4bIGS8wMLhYwH54AozNbYJDh16Pawwn+Cdfzyl5ACHE8SpquqI4D7bDZKA2
    # XT6ZqWlqDPNxAMnn7bbfNrav5uPlVhchkzZmTXrbM/+cSvaRblAx1ACxf1/H4GDpEGDw
    # SiPl/42Wetr7+GmgyEwwlFmd7fL8diImiDuvX3Cw/ywx96jjtOmP+OHdavf409ELAUCi
    # lAGY+nq6iooaFB4PCnnzpffy2VlbmRFi2KA08R8EUiGqe8Bd/iBwxI0UX/VzA4nkq9sn
    # JleVOTMT7unzYtUlraMTSUhIWUl0/s2rVo587GcNh+910Ebg5C3+ZmofYAFYizslKZPx
    # /eQt28GfQL3CgxMSHuMjAg3B53k3MVmut4wAgAz29/K01M/HXNmrm33TZx3XWlHR0Gxi
    # eYBWHsPXAg8OqrFaWl1tatTnu7VFIiUa+lNjDwvs/X+cMfxkABOztFKzHWwlEthRAiDU
    # o1BhE5gClwFlcgGAyP66aUf4CiHC4tXXnPPU1U9fl7nVq+3NizB+TQ8/DDomPZstRCao
    # 7gEUegyQiqATbYKOCv6HdqbeUuAbe+g/vlch5FyUHZ4LRVdQJotGTJggUL+q64ovf++6
    # FEIUXxEQTmRkfTQ0NYsCjuwWtQZdhQlMF0+utTTvn+1VeD/0488khWUfy6HvX7Teo7dC
    # gUc7sPqRCrcSO9AC0uDkBslNYyvN7ZmYxoJYWc2tqcvj65oUFs0eio0tio7tqFKULVD3
    # s8H9TXT0Fg3dtraBqYUy4cjhpGdTo9FaNjbUAax0FMI+rxY2PwMQ63fZPDgH/cqWmHV6
    # 0qCwa9HR0DuVzTmjWYXuTyy/8WDCZ6epS+vsojR5YfPRpQVWicwNexMUDd24oyPG8eBJ
    # orLz9x0yaMkz733B2joxr8Uy435ZNPlnR2yoUUD5wu17REVnj5cs4bHHvGgqAcugHuob
    # C7yoiP5fEEdB1DY+tUSqb16PofN2y44MYbAZK9vb3BaFTPZHyBQDaRGGptVd56a+mOHc
    # GiIqCINH26Z2ICDpz7pdwEoq4POM6OG264+Oqr4fnGaXKx/1kNBBofTadDV17p2bfv6G
    # OPHQfHdtllQ4bx8T33nHTxxUFg1T8CteFEwv/d7/r7+jjL7QaCFLpqLpRBjQs5awISLA
    # oM9q2ysiKvN2Pb2WnT/EVFvqGhbCplRKOg8k3t7QOx2NnXXtsAc5KkCiAKP+GFT3W1NG
    # vW5Nlnj91xR/CNNzzh8JednWWmWYOAibMwlE6Cgw1ns2doGteBY4OD0vAwLpQoteDs3A
    # lo8FRU1Pf3m0NDIDMDL76IvUAEA5Jx1vbt8PBOWZkze7bMfa0gmAcPSjNn4szyDz80AH
    # WU+udeFrG3lIoSjWlu4opCCplSJLZPtHL+Phar+c1vZlRXIwaKYcOpsyxHQp3o7i695J
    # J2zPXVV+tqaoBY5n33OfBYMK1Ewli/3vMv/wIal92/X73ssmHTfONHPzrPcaqeflpUjw
    # tkG+jFrnLaNAGWnZ0AlZ5zzql8+OFAV5e+YYOoD5O7hiNMZbN/uuqqExcvrvzJT1Qx76
    # ydzaqy3FdTo7z8cm1NjXHDDfb27SKLKBoyJ9zkFMfSnC2kjAUlNIiICGVjHCcGYqVSM0
    # OhpoaGcp+vRtdB8WAJoXi8tK0tkExWDQyINuV0OkVFI7u9He7H6e+3Ozqk3t7UM88c/v
    # BDQdFiMU8w2FFcfOrFF9dccEHW41EKCSAmt7gWU2luhshEo0QkEtq9O9PWJh05Iko5sZ
    # gSiXgRD1jWAUVpWLq0fu3aRHk55GLRozFqIBDu69OhGgjI9u7VwFJGR4Un42ZxzmPmiQ
    # YroMaNUBLXOOhhC0HBUin4g+NaWrA/UDALy4DzKC3FCm2gPEGlBoDVNJNoqgVKRM95cC
    # vZ19ksiMc8SiMjLC2NRIogzfp6u6lJ+vhjbmAudH4KPgC27PF4s9nJyckQFOPqqxEk+o
    # AxhpGy7f2O015UlFy/fiNllEf+9V/f/e1vrWhUAyimUqHu7vArrySKigActZpWDeLElI
    # Nbkzh5yFQcaxTEg5+N4JwWVbfcDDgIuuN0ffHFUVWtxz5kMs7gIHQhijAV4iBKHLCsMS
    # 64TZ++o7FxQtex7Qm/P7Ny5aXUlShaCTOZdCDgjI/XlJf76+qc3bvl/HNbDvUCup0Htv
    # 16JDJyxhnlmpbq64MOVx89OqOz880TTph66aVLFi2aCd9Opj5n7dqGtWuZXuWE8k7E29
    # sRcpvr13/V1ja8efP83l5+cOBYYanwkKfo8cg3UotYh5vqqSnMa5p7ZPmjjRuPP+20vS
    # 0tMCGV2pjN3t7wwYNLmptjgDXD4IKbv7r6uBdekCndB/OvpMIXGLj10EOwfDD+qooKzo
    # 1y6wxnPwVeUDZT3Au3vuOOa844AxaYoQdERgxj5LrrztywYRb4Y6HjjnonA52dUnExNt
    # AbjRZFo7XUxCA+S5cOrVmTvfxy38SEzFnXfGAoeDG0XOwwVWtlLrhwWyKhmW5ZbWvXXn
    # vnnQIxC6E2fYay2e4XXww/+aQYgWEZYQr3iLqRVMp+7TXrnXfA8gCViJ99pF0KMUq3Sk
    # AQYlMHDNQ+WlIybdkyJd+DKg0MVH/4YQUY1S9/aeBGljXZ1OT/2c9ARazbb7cATmVlQG
    # PQT6m8XJ47V7ngAplyBhW9vToljN0HR7hXlos7FEJpblcjd4fn2/AgeDOXq6ut9XPQum
    # OHDRACZ8ASN22qKCuLXX116r33Ih9/HOrvl+hpF+vBB+3OTgCGCMQw9IEDwruQ9wun0x
    # nQLEBjS4voLaDOMFf2lPREWDcd0f/115vz5gGrna4uZ2JCGRzUqG9AHR3FrAaBTJs2zZ
    # k1K9vT4we3Q+AFjevuFuj39tvOSy/Zc+aIW+/d6+bMIDV60EDsH2bFHSCii4dvzPUefo
    # iNDNiDaUEnKfNiPPssXKJMyc3W0dHG++4TzyTNm6ft3Vv3+us6YsN9+6xXXhGFFcTP3L
    # kJhANPzmSgojlsOKKl6mozmVQoe+g+zEkuUDy0geAOtoBY6oMPxPMIEI3Xm/T7WxBLhE
    # JZbJ3fPxoOn0PBee9VV+15/nkRNmD2huGbnIwMDFQODcW6uqCoqt9fgpBNUUyuobmPo2
    # kuAxEqzSm1QsKFq2eUeTa5tMU5Z2pn8gClDh1K6Hqp1wuXYHu9QfD1n/5UdAHDqDBpUl
    # 2RpqXkqENo2VFVtYwyW3ZDg/L551L+EXJREKL+qLdAfZcuLR4bA1IgzprX359W1b+sWT
    # N93bqGuXNLy8o8Xm9AUaI0OEy6Zt06jTodTWpkHo3HRzo6jhw8CJeApWqtrYs++miqYV
    # jcoMNPhHKFSeSuAVG8VG4WomhJsFxcnMvxDsM9eqnzaSyVOlRZeQIX0CYmHH7QEfpDGQ
    # wI7iPTnAyFjh8bq4QQYZ8ez2gikV64sIY6zrT6eveZcS47pdOaLG+bPn36gw82zZqVhA
    # +jJ7nGdu+OP/XU9x54oJx1gSuVhc5iuInubs4i+ELiUxEMSoilTzqJT8hKUtc77+g//r
    # EGyODOTW4FF2nHhOaWiLiNmZyVUACs2ecLjI3lLMurql1r1+7p7YXixSsrT7r++gCxFg
    # f0gBqHRCwNuQSDnbre8s//vOSMMw7v3v3pq682trerk5N/WrDg9I0b3Q7XRMLi56dJg7
    # DDRi5Xv2DBKmoc9fHy4vHK/fsbMfiVVxogrZOTzuSkmkgMf/e7ZddcA1Oy33zTvOceUX
    # OGBpWWKgjmYjG5pEQ+9VSF4BrrmT1/fo7L5Vy+445hGEskkg8eCi3H/AQXSIXjfFBXN2
    # fz5pjfn4V3NQzQxoiiMChbP/+5uXWrzGUkcqqabXdZlrF58yyaPaK2zn372pubV553Xk
    # M+52pceqlz6BBXlR3KocLsTTCNSy9VSkpEUA1UHx5GQCbTA3nu42SapmYybzc1nfrCCy
    # EY5hNPyMBtfj4ZKknVDBH0QolWrlThUDIZ+y9/EfuRfzzcbbuj/gOB0txQe+wxU24iNk
    # 0/jJ+0F3GvHwfhcrEte/daW7bYBw+K7jB+4pFcPEIohITx7dudWbOgdZXBYOXq1ctXrz
    # 72ZNof/mC3tMj5J0GZDAG0ATz2U0/ZHEVxJx6VbETmmDuXgCa27W1oCHLDc1WVxadxIY
    # rqQW6b9EcfWTt3ii2NRMTMuVILJserJbyk/i9+NJPJVr5UD0CqGRrKDQ1JU6ZYjz1mvf
    # aaG1FR7sJ9vQBX9KglCd+qoVDs2WczgYD/8suVwtPP+IyPiz6Yp59mL+BQXwdXA/hpMY
    # WSW25xnPWQatyiSkZVAVwYA5ciQiIj0M0/S89P6bLExQ87QoxAFV9RkecywzfeB5DvAO
    # CEC9dy+clTXJRMmscf762osN97jxNAMmWtuaGOHxg59gwfh9rgEPhz9my1rg58QDhkRG
    # 0I9Pr6uNPDLbtTUdt9tIY4j0yVUYcYKxMBt0uOpivaAiMRzwMPYB/N228XqXaySbfdjB
    # P02IxCJxqxGiGyfPufTKUWCg+hddz8xM/wcLcKV0y51YkKsFxfFVMsvDGBi0/8PDA/Ts
    # 6QiK+Af9xHwu0FhcesOJnIlxRaSQsNEUzx+Som9tz1wQ8CYT0ENFyXLTy64VJjtix6St
    # 19IQM/jFt4eQRXV0QHAL2vg9kmjyKTSNzOGq5T518acSw/BOullHXh7RFcHHOr5Nz8y+
    # 2D1MjCDY+FV2i47wMBMwUhYc3Kl/LcJ9ipE5UVSuwYp4RozTIXrrmJlkO0QuE+FCok94
    # +9xIM7ABmqvF6NOx9l6i4v9Mm7/LPwYCQ1P4mpUDrbfV0Iv0Cm0OrI9+BIKN+Gw+9AEf
    # eDqnOPGHdZ8vsq+EUEvG/s/1lkhVIGV/Z427EeFl/hBN4q1kTuNuFVsQKS0gk/lH/HCI
    # 5AvgqHxa5caU+4V921TJ4W3UCUyAvNcsyiaK84mX7s7SmYN+0JFxYKFbBj76UpvJSAux
    # LyD0WIjn2WciF7zmUh1nZq9nBZA8ZnRpiPhFz/wsE86RFPr9DI6lDnFWaruH1HuD3GpW
    # fg+H0CrvYWGrXzXYPCVrlNstCwQFjFzS7ce+42b3AHOrdFFHqTOK3D5phvk/xm+xM35r
    # lPYHF8zi18kAhDKaNjoWWBxUp/2twfBDlywyoDGNf36E0DtGBqBHD4LTH5J+Tcahj2il
    # 4OweIoPHMv5V/tw76EH993Ci25NILMas9NhPmUKOuCm/HHMihn6L4MgIsD4AwsbtwCk8
    # m/u4UVjV9KxJ0eNsdbDBOEl06+yZ+vsmHPsERaKquYRE/EuVAsF/o8C8+A8PtaMJXCe1
    # kKL77R8un7wmMM3JhFyOzQGtz+Ku7k5do6M9t8R4uL21Rt4WbJgmVKBUsu9M4zwufTyY
    # WHzdhT8FuuZH5nEDec8ZYUmjgga36RRDb7fwQYAOkxP+Fzk1pGAAAAAElFTkSuQmCC''')))
    # print(r)
    # test remind:
    #     r = c.remind.unread_count.get()
    #     print r
