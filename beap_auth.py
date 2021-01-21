"""
User credential and auth token module
See [README](../README.html) for more details.

Copyright 2020. Bloomberg Finance L.P.Permission is hereby granted, free of
charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to
the following conditions: The above copyright notice and this permission
notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import uuid
import time
import json
import jwt
import binascii
import io
import datetime
import sys
import pkg_resources

# Cope with python2/3 differences
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

import logging

import requests
import requests.adapters

log = logging.getLogger(__name__)


DAYS_IN_MONTH = 30
EXPIRE_WARNING_THRESHOLD = datetime.timedelta(days=DAYS_IN_MONTH)
REGION = 'default'
FILES_ENCODING = "utf-8"
JWT_LIFETIME = 25
JWT_MAX_CLOCK_SKEW = 180

python = sys.version_info

MIN_V3 = (3, 5)
MIN_V2 = (2, 7)

version_warning = """Only the following Python versions are supported:
Python2: >= {},
Python3: >= {}
""".format(MIN_V2, MIN_V3)

assert MIN_V2 <= python < (3, 0) or MIN_V3 <= python, version_warning

try:
    with io.open('requirements.txt', encoding=FILES_ENCODING) as requirements:
        pkg_resources.require(requirements.read())
except (pkg_resources.VersionConflict,
        pkg_resources.DistributionNotFound) as requirement_error:
    sys.stderr.write(
        "Samples require certain set of packages to be installed.\n"
        "The following requirement is not satisfied: {}.\n"
        "Please install all needed requirements using 'pip install -r "
        "requirements.txt' command first.\n".format(requirement_error.req))
    sys.exit(-1)
except (IOError, ValueError, UnicodeDecodeError):
    sys.stderr.write(
        "Requirements file cannot be verified. Please ensure that required "
        "versions of packages listed 'requirements.txt' file (from the "
        "original samples archive) are installed.\n"
    )


class BEAPAuthError(Exception):
    """
    Base exception class for connectivity errors.
    """


class BEAPValidationError(BEAPAuthError):
    """
    Indicates that one or more of the user provided parameters were incorrect.
    """


class Credentials(object):
    """
    Class to encapsulate the client ID and secret, and methods to generate the
    JWT.
    """

    def __init__(self, client_id, client_secret):
        """
        Initialise the object directly with the client's credentials.

        :param client_id: client id created at console.bloomberg.com for
        your BEAP account
        :type client_id: str
        :param client_secret: client secret created at console.bloomberg.com
        for your BEAP account
        :type client_secret: str
        """
        self.client_id = client_id
        self.client_secret = client_secret

    @classmethod
    def from_dict(cls, credentials_data):
        """
        Create an object from a dict that has 'client_id' and 'client_secret'
        keys.

        :param credentials_data: credentials data
        :type credentials_data: collections.Mapping
        :return: created Credentials instance
        :rtype: Credentials
        """
        try:
            client_id = credentials_data['client_id']
            client_secret = credentials_data['client_secret']
            expire_time = credentials_data['expiration_date']
        except KeyError as key:
            message = "Credentials missing key: '{}'".format(key)
            log.error(message)
            raise BEAPValidationError(message)

        cls._check_expiration(expire_time)
        client_secret = binascii.unhexlify(client_secret)
        return cls(client_id=client_id, client_secret=client_secret)

    @classmethod
    def from_file(cls, file_path):
        """
        Create an object from file.

        The file is assumed to contain a JSON dict with 'client_id' and
        'client_secret' keys.

        :param file_path: The path of the file to load the client credentials
        from
        :type file_path: str
        """
        try:
            with io.open(file_path, encoding=FILES_ENCODING) as credential_file:
                decoded_credential = json.load(credential_file)
        except IOError:
            log.error("Could not find or open %r", file_path)
            raise
        except ValueError:
            log.error("Cannot deserialize contents of the %r file", file_path)
            raise
        else:
            log.info("Credential file %r loaded", file_path)
            return cls.from_dict(decoded_credential)

    @classmethod
    def _check_expiration(cls, expires_at):
        """
        Check expiration time to notify users that their credentials have
        expired or are about to expire.

        :param expires_at: non-parsed expiration time value
        :type expires_at: str
        """
        try:
            expires_at = int(expires_at)
        except ValueError:
            message = "Bad credentials expiration date format: '{}'".format(
                expires_at
            )
            log.error(message)
            raise BEAPValidationError(message)

        expires_at = datetime.datetime.fromtimestamp(expires_at / 1000)
        now = datetime.datetime.utcnow()
        expires_in = expires_at - now
        if expires_at < now:
            log.warning("Credentials expired %s ago", abs(expires_in))
        elif expires_in < EXPIRE_WARNING_THRESHOLD:
            log.warning("Credentials expiring in %s", expires_in)

    def generate_token(self, path, method, host, region=REGION):
        """
        Generates a single-use BEAP compliant JWT access token that is valid for
        25 seconds.

        :param path: Path of the endpoint that the JWT will be used to access
        :type path: str
        :param method: The HTTPMethod that the token will be used with. For a
                       list of available methods see `HTTPMethods` above
        :type method: str
        :param host: The BEAP host being accessed
        :type host: str
        :param region: The account region
        :type region: str
        :returns: The generated access token
        :rtype: str
        :raises BEAPValidationError: If any of the parameters are invalid
        """
        now = time.time()
        payload = {
            'iss': self.client_id,
            'iat': int(now - JWT_MAX_CLOCK_SKEW),
            'nbf': int(now - JWT_MAX_CLOCK_SKEW),
            'exp': int(now + JWT_MAX_CLOCK_SKEW + JWT_LIFETIME),
            'region': region,
            'path': path,
            'method': method,
            'host': host,
            'jti': str(uuid.uuid4()),
        }
        key = self.client_secret
        return jwt.encode(payload, key)


class BEAPAdapter(requests.adapters.HTTPAdapter):
    """
    Requests adapter for connectivity group token signing.

    Note: this class automatically signs JWT tokens on HTTP redirects either.
    """

    def __init__(self, credentials, api_version='2', *args, **kwargs):
        """
        Initialize the connectivity adapter directly with a ``Credentials``
        tuple.

        :param credentials: A (client_id, client_secret) pair
        :type credentials: ``Credentials``
        """
        super(BEAPAdapter, self).__init__(*args, **kwargs)
        self.credentials = credentials
        self.api_version = api_version

    def send(self, request, **kwargs):
        """
        Inject JWT tokens in every outgoing HTTP request.

        :param request: HTTP request about to be send to BEAP
        :type request: requests.Request
        :param kwargs: 'requests' library parameters, such as method and url.
        :type kwargs: dict
        :return: HTTP response for provided request
        :type: requests.Response
        """
        url = urlparse(request.url)
        token = self.credentials.generate_token(url.path,
                                                request.method,
                                                url.hostname)
        request.headers['JWT'] = token
        request.headers['api-version'] = self.api_version
        response = super(BEAPAdapter, self).send(request, **kwargs)

        latest_api_version = response.headers.get('latest-api-version')
        if latest_api_version and self.api_version != latest_api_version:
            log.info(
                'You are using HAPI version %s; '
                'however, version %s is available',
                self.api_version,
                latest_api_version
            )

        if response.status_code in (requests.codes.forbidden,
                                    requests.codes.unauthorized):
            log.error(
                'Either supplied credentials are invalid or expired, '
                'or the requesting IP address is not on the allowlist.'
            )

        if log.isEnabledFor(logging.INFO) and not response.is_redirect:
            log.info("Request: %s, %s ", request.method, request.url)
            log.info("Response status code: %s", response.status_code)
            log.info("Response x-request-id: %s",
                     response.headers.get("x-request-id"))

            stream = kwargs.get("stream")

            if not stream and log.isEnabledFor(logging.INFO):
                log.info("Response JSON: %s", response.text)

        return response
