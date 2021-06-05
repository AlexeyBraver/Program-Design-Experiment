# -*- coding: utf-8 -*-

"""
requests.adapters
~~~~~~~~~~~~~~~~~

This module contains the transport adapters that Requests uses to define
and maintain connections.
"""

import os.path
import socket

from urllib3.exceptions import ClosedPoolError
from urllib3.exceptions import ConnectTimeoutError
from urllib3.exceptions import HTTPError as _HTTPError
from urllib3.exceptions import LocationValueError
from urllib3.exceptions import MaxRetryError
from urllib3.exceptions import NewConnectionError
from urllib3.exceptions import ProtocolError
from urllib3.exceptions import ProxyError as _ProxyError
from urllib3.exceptions import ReadTimeoutError
from urllib3.exceptions import ResponseError
from urllib3.exceptions import SSLError as _SSLError
from urllib3.poolmanager import proxy_from_url
from urllib3.response import HTTPResponse
from urllib3.util import Timeout as TimeoutSauce
from urllib3.util import parse_url

from .auth import _basic_auth_str
from .compat import urlparse, basestring
from .cookies import extract_cookies_to_jar
from .exceptions import (ConnectionError, ConnectTimeout, ReadTimeout, SSLError, ProxyError, RetryError, InvalidSchema, InvalidProxyURL, InvalidURL)
from .models import Response
from .structures import CaseInsensitiveDict
from .utils import (DEFAULT_CA_BUNDLE_PATH, extract_zipped_paths, get_encoding_from_headers, prepend_scheme_if_needed, get_auth_from_url, urldefragauth, select_proxy)

try:
    from urllib3.contrib.socks import SOCKSProxyManager
except ImportError:
    def SOCKSProxyManager(*args, **kwargs):
        raise InvalidSchema("Missing dependencies for SOCKS support.")

DEFAULT_POOL_TIMEOUT = None


def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
    """Sends PreparedRequest object. Returns Response object.

    :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
    :param stream: (optional) Whether to stream the request content.
    :param timeout: (optional) How long to wait for the server to send
        data before giving up, as a float, or a :ref:`(connect timeout,
        read timeout) <timeouts>` tuple.
    :type timeout: float or tuple or urllib3 Timeout object
    :param verify: (optional) Either a boolean, in which case it controls whether
        we verify the server's TLS certificate, or a string, in which case it
        must be a path to a CA bundle to use
    :param cert: (optional) Any user-provided SSL certificate to be trusted.
    :param proxies: (optional) The proxies dictionary to apply to the request.
    :rtype: requests.Response
    """

    try:
        proxy = select_proxy(request.url, proxies)
        if proxy:
            proxy = prepend_scheme_if_needed(proxy, 'http')
            proxy_url = parse_url(proxy)
            if not proxy_url.host:
                raise InvalidProxyURL("Please check proxy URL. It is malformed"
                                      " and could be missing the host.")

            if proxy in self.proxy_manager:
                proxy_manager = self.proxy_manager[proxy]
            elif proxy.lower().startswith('socks'):
                username, password = get_auth_from_url(proxy)
                proxy_manager = self.proxy_manager[proxy] = SOCKSProxyManager(
                    proxy,
                    username=username,
                    password=password,
                    num_pools=self._pool_connections,
                    maxsize=self._pool_maxsize,
                    block=self._pool_block
                )
            else:
                proxy_headers = {}
                username, password = get_auth_from_url(proxy)
                if username:
                    proxy_headers['Proxy-Authorization'] = _basic_auth_str(username, password)
                proxy_manager = self.proxy_manager[proxy] = proxy_from_url(
                    proxy,
                    proxy_headers=proxy_headers,
                    num_pools=self._pool_connections,
                    maxsize=self._pool_maxsize,
                    block=self._pool_block)

            conn = proxy_manager.connection_from_url(request.url)
        else:
            # Only scheme should be lower case
            parsed = urlparse(request.url)
            url = parsed.geturl()
            conn = self.poolmanager.connection_from_url(url)
    except LocationValueError as e:
        raise InvalidURL(e, request=request)

    if request.url.lower().startswith('https') and verify:

        cert_loc = None

        # Allow self-specified cert location.
        if verify is not True:
            cert_loc = verify

        if not cert_loc:
            cert_loc = extract_zipped_paths(DEFAULT_CA_BUNDLE_PATH)

        if not cert_loc or not os.path.exists(cert_loc):
            raise IOError("Could not find a suitable TLS CA certificate bundle, "
                          "invalid path: {}".format(cert_loc))

        conn.cert_reqs = 'CERT_REQUIRED'

        if not os.path.isdir(cert_loc):
            conn.ca_certs = cert_loc
        else:
            conn.ca_cert_dir = cert_loc
    else:
        conn.cert_reqs = 'CERT_NONE'
        conn.ca_certs = None
        conn.ca_cert_dir = None

    if cert:
        if not isinstance(cert, basestring):
            conn.cert_file = cert[0]
            conn.key_file = cert[1]
        else:
            conn.cert_file = cert
            conn.key_file = None
        if conn.cert_file and not os.path.exists(conn.cert_file):
            raise IOError("Could not find the TLS certificate file, "
                          "invalid path: {}".format(conn.cert_file))
        if conn.key_file and not os.path.exists(conn.key_file):
            raise IOError("Could not find the TLS key file, "
                          "invalid path: {}".format(conn.key_file))

    proxy = select_proxy(request.url, proxies)
    scheme = urlparse(request.url).scheme

    is_proxied_http_request = (proxy and scheme != 'https')
    using_socks_proxy = False
    if proxy:
        proxy_scheme = urlparse(proxy).scheme.lower()
        using_socks_proxy = proxy_scheme.startswith('socks')

    url = request.path_url
    if is_proxied_http_request and not using_socks_proxy:
        url = urldefragauth(request.url)

    self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)

    chunked = not (request.body is None or 'Content-Length' in request.headers)

    if isinstance(timeout, tuple):
        try:
            connect, read = timeout
            timeout = TimeoutSauce(connect=connect, read=read)
        except ValueError as e:
            # this may raise a string formatting error.
            err = ("Invalid timeout {}. Pass a (connect, read) "
                   "timeout tuple, or a single float to set "
                   "both timeouts to the same value".format(timeout))
            raise ValueError(err)
    elif isinstance(timeout, TimeoutSauce):
        pass
    else:
        timeout = TimeoutSauce(connect=timeout, read=timeout)

    try:
        if not chunked:
            resp = conn.urlopen(
                method=request.method,
                url=url,
                body=request.body,
                headers=request.headers,
                redirect=False,
                assert_same_host=False,
                preload_content=False,
                decode_content=False,
                retries=self.max_retries,
                timeout=timeout
            )

        # Send the request.
        else:
            if hasattr(conn, 'proxy_pool'):
                conn = conn.proxy_pool

            low_conn = conn._get_conn(timeout=DEFAULT_POOL_TIMEOUT)

            try:
                low_conn.putrequest(request.method,
                                    url,
                                    skip_accept_encoding=True)

                for header, value in request.headers.items():
                    low_conn.putheader(header, value)

                low_conn.endheaders()

                for i in request.body:
                    low_conn.send(hex(len(i))[2:].encode('utf-8'))
                    low_conn.send(b'\r\n')
                    low_conn.send(i)
                    low_conn.send(b'\r\n')
                low_conn.send(b'0\r\n\r\n')

                # Receive the response from the server
                try:
                    # For Python 2.7, use buffering of HTTP responses
                    r = low_conn.getresponse(buffering=True)
                except TypeError:
                    # For compatibility with Python 3.3+
                    r = low_conn.getresponse()

                resp = HTTPResponse.from_httplib(
                    r,
                    pool=conn,
                    connection=low_conn,
                    preload_content=False,
                    decode_content=False
                )
            except:
                # If we hit any problems here, clean up the connection.
                # Then, reraise so that we can handle the actual exception.
                low_conn.close()
                raise

    except (ProtocolError, socket.error) as err:
        raise ConnectionError(err, request=request)

    except MaxRetryError as e:
        if isinstance(e.reason, ConnectTimeoutError):
            # TODO: Remove this in 3.0.0: see #2811
            if not isinstance(e.reason, NewConnectionError):
                raise ConnectTimeout(e, request=request)

        if isinstance(e.reason, ResponseError):
            raise RetryError(e, request=request)

        if isinstance(e.reason, _ProxyError):
            raise ProxyError(e, request=request)

        if isinstance(e.reason, _SSLError):
            # This branch is for urllib3 v1.22 and later.
            raise SSLError(e, request=request)

        raise ConnectionError(e, request=request)

    except ClosedPoolError as e:
        raise ConnectionError(e, request=request)

    except _ProxyError as e:
        raise ProxyError(e)

    except (_SSLError, _HTTPError) as e:
        if isinstance(e, _SSLError):
            # This branch is for urllib3 versions earlier than v1.22
            raise SSLError(e, request=request)
        elif isinstance(e, ReadTimeoutError):
            raise ReadTimeout(e, request=request)
        else:
            raise

    response = Response()

    # Fallback to None if there's no status_code, for whatever reason.
    response.status_code = getattr(resp, 'status', None)

    # Make headers case-insensitive.
    response.headers = CaseInsensitiveDict(getattr(resp, 'headers', {}))

    # Set encoding.
    response.encoding = get_encoding_from_headers(response.headers)
    response.raw = resp
    response.reason = response.raw.reason

    if isinstance(request.url, bytes):
        response.url = request.url.decode('utf-8')
    else:
        response.url = request.url

    # Add new cookies from the server.
    extract_cookies_to_jar(response.cookies, request, resp)

    # Give the Response some context.
    response.request = request
    response.connection = self
    return response
