# Copyright 2011 Arunjit Singh. All Rights Reserved.
"""Bot detection for webapps.

@author: Arunjit Singh <arunjit@me.com>
@license: MIT license. This notice must be included in all distributions.
    @see: //LICENSE for details.
    @see: http://www.opensource.org/licenses/mit-license.php for details.
"""


from datetime import datetime as dt
import hashlib
import re


def _create_now_timestamp():
    """Creates a timestamp (in seconds)."""
    delta = dt.now() - dt.fromtimestamp(0)
    return delta.days * 86400 + delta.seconds


# pylint: disable-msg=R0903
class TimeCheck(object):
    """Decorator class to check the delay between requests.

    A request must take at least or at most a specified amount of time.

    Attributes:
        strategy: The comparison strategy to use. One of TimeCheck.AT_LEAST,
                TimeCheck.AT_MOST.
        delay: The time delay to expect.
        secret: The secret key to use.
    """
    # At least strategy.
    AT_LEAST = min

    # At most strategy.
    AT_MOST = max

    # The hash function to use.
    _HASH_TYPE = hashlib.sha512  # pylint: disable-msg=E1101

    # The name of the cookie to set
    _COOKIE_NAME = 'TCHK'

    # The cookie string.
    _COOKIE = '%s=%s|%s;'

    # RegEx to search for the cookie values. 128 is 2x the digestsize of sha512.
    _COOKIE_SEARCH_RE = '([0-9a-f]{128})\|(\d+)'

    # The secret to use
    _secret = None

    @staticmethod
    def set_secret(secret):
        """Sets the secret key for hashing the times.

        Args:
            secret: The secret to set. Will be converted to str before being
                    used.
        """
        TimeCheck._secret = secret
    
    def __init__(self, strategy, delay, secret=None):
        """Initializes the decorator.

        Args:
            strategy: The comparison strategy to use.
                    @see: TimeCheck.AT_LEAST, TimeCheck.AT_MOST
            delay: The time delay to expect.
            secret: The secret key to use. Defaults to TimeCheck._secret.
        
        Raises:
            TypeError: secret and TimeCheck._secret are both None.
            ValueError: strategy is not one of (TimeCheck.AT_LEAST, 
                    TimeCheck.AT_MOST)
        """
        if not secret and not TimeCheck._secret:
            raise TypeError('Need a secret to verify against')
        
        if strategy not in (TimeCheck.AT_LEAST, TimeCheck.AT_MOST):
            raise ValueError('Unknown strategy')
        
        self.strategy = strategy
        self.delay = int(delay)
        self.secret = str(secret or TimeCheck._secret)

    def _create_hash_timestamp(self):
        """Creates a timestamp and a hash using the timestamp and secret.

        Returns:
            A two item tuple of the hash and timestamp.
        """
        sha = TimeCheck._HASH_TYPE()
        timestamp = _create_now_timestamp()
        sha.update(str(timestamp))
        sha.update(self.secret)
        timestamp_hash = sha.hexdigest()
        return (timestamp_hash, timestamp)


    def _verify_hash_timestamp(self, timestamp_hash, timestamp):
        """Verifies if the hashes for the timestamp match.

        Returns:
            True, if the hashes match, False otherwise.
        """
        sha = TimeCheck._HASH_TYPE()
        sha.update(str(timestamp))
        sha.update(self.secret)
        gen_timestamp_hash = sha.hexdigest()
        return gen_timestamp_hash == timestamp_hash

    def _create_cookie(self):
        """Creates the cookie string.

        Returns:
            The cookie string.
        """
        timestamp_hash, timestamp = self._create_hash_timestamp()
        return TimeCheck._COOKIE % (TimeCheck._COOKIE_NAME,
                                    timestamp_hash,
                                    str(timestamp))

    def _verify_cookie(self, cookie_str):
        """Verifies a cookie.

        Args:
            cookie_str: The content of a cookie.

        Returns:
            0, if the cookie was invalid, otherwise the timestamp as an int.
        """
        found = re.search(TimeCheck._COOKIE_SEARCH_RE, cookie_str)
        if found:
            timestamp_hash, timestamp = found.groups()
            if self._verify_hash_timestamp(timestamp_hash, timestamp):
                return int(timestamp)
        return 0

    def __call__(self, method):
        """The decorator call.

        Verfies and sets a new cookie.
        Args:
            method: The method to decorate.

        Returns:
            A wrapper method for the call.
        """
        def wrapper(handler, *args, **kwargs):
            """The wrapper for a RequestHandler.
            
            Args:
                handler: An instance of RequestHandler.
            """
            handler.response.headers['Set-Cookie'] = self._create_cookie()
            cookie = handler.request.cookies.get(TimeCheck._COOKIE_NAME)
            if not cookie:
                handler.error(400)
                return
            if isinstance(cookie, list):
                cookie = cookie[0]
            cookie_str = str(cookie)
            if cookie_str:
                timestamp = self._verify_cookie(cookie_str)
                if not timestamp:
                    handler.error(403)
                    return
                now_timestamp = _create_now_timestamp()
                delta_seconds = now_timestamp - timestamp
                if self.strategy(delta_seconds, self.delay) != self.delay:
                    handler.error(403)
                    return
            method(handler, *args, **kwargs)
        return wrapper
