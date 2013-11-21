#!/usr/bin/env python
# htail - tail over HTTP
# Copyright (C) 2013  Vincent Pelletier <plr.vincent@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import base64
import httplib
import netrc
import time
import urllib

scheme_dict = {
    'http': httplib.HTTPConnection,
    'https': httplib.HTTPSConnection,
}

decode_dict = {
}

GOOD_STATUS_SET = (
    httplib.REQUESTED_RANGE_NOT_SATISFIABLE,
    httplib.OK,
    httplib.PARTIAL_CONTENT,
)
TEMPFAIL_STATUS_SET = (
    httplib.NOT_FOUND,
    httplib.LOCKED,
)

class HTTPFileError(Exception):
    pass

class HTTPFileTempFail(HTTPFileError):
    pass

class HTTPFile(object):
    def __init__(self, selector, connection, auth=None):
        self._selector = selector
        self._connection = connection
        self._auth = auth
        self._offset = 0

    def len(self):
        response = self._request('HEAD')
        response.close()
        assert response.status == 200, repr(response.status)
        result = response.getheader('content-length')
        if result is None:
            raise ValueError('server does not report content-length')
        return int(result)

    def read(self, length=None):
        offset = self._offset
        byte_range = 'bytes=%d-' % offset
        if length is not None:
            byte_range += '%d' % (offset + length)
        response = self._request('GET', {
            'Range': byte_range,
            'Accept-Encoding': ', '.join(decode_dict),
        })
        status = response.status
        if status in GOOD_STATUS_SET:
            length = response.getheader('content-length')
            if length is None:
                response.close()
                return ''
            encoding = response.getheader('content-encoding', 'identity').lower()
            body = response.read(int(length))
            response.close()
            if encoding != 'identity':
                body = decode_dict[encoding](body)
            self._offset += len(body)
            return body
        if status in TEMPFAIL_STATUS_SET:
            raise HTTPFileTempFail(status)
        raise HTTPFileError(status)

    def seek(self, offset, whence=0):
        if whence == 0:
            self._offset = offset
        elif whence == 1:
            self._offset += offset
        elif whence == 2:
            self._offset = self.len() + offset
        else:
            raise ValueError(repr(whence))
        if self._offset < 0:
            self._offset = 0

    def _request(self, method, header_dict={}):
        self._connection.putrequest(method, self._selector, skip_accept_encoding=True)
        if self._auth:
            self._connection.putheader('Authorization', 'Basic ' + self._auth)
        for k, v in header_dict.iteritems():
            self._connection.putheader(k, v)
        self._connection.endheaders()
        return self._connection.getresponse()

DEFAULT_OFFSET = 1024

SLEEP_MIN = 1
SLEEP_MAX = 16

WHENCE_BEGIN = 0
WHENCE_END = 2

JEDEC_UNIT = 1024
IEC_UNIT = 1000

def basicAuth(login, password):
    return base64.b64encode(login + ':' + password).strip()

def tail(stream,
        url_list, offset=-DEFAULT_OFFSET, whence=WHENCE_END, follow=False,
        retry=False, sleep_min=SLEEP_MIN, sleep_max=SLEEP_MAX, quiet=False,
        verbose=False, netrc_path=None):
    httpfile_list = []
    append = httpfile_list.append
    getNetRCAuth = lambda _: None
    if netrc_path is not False:
        try:
            getNetRCAuth = netrc.netrc(netrc_path).authenticators
        except IOError:
            if netrc_path is not None:
                raise
    for url in url_list:
        urltype, rest = urllib.splittype(url)
        host, rest = urllib.splithost(rest)
        user_passwd, host = urllib.splituser(host)
        if user_passwd:
            selector = urltype + '://' + host + rest
            auth = basicAuth(*urllib.splitpasswd(user_passwd))
        else:
            selector = url
            netrc_auth = getNetRCAuth(host)
            if netrc_auth:
                auth = basicAuth(netrc_auth[0], netrc_auth[2])
            else:
                auth = None
        http_file = HTTPFile(
            selector,
            scheme_dict[urltype.lower()](host),
            auth,
        )
        http_file.seek(offset, whence)
        append([0, sleep_min, http_file, url])
    if verbose or len(httpfile_list) > 1:
        last_activity = None
    elif len(httpfile_list) == 1:
        last_activity = httpfile_list[0][2]
    need_newline = False
    while httpfile_list:
        next_httpfile_list = []
        append = next_httpfile_list.append
        next_timeout = httpfile_list[0][0]
        for entry in httpfile_list:
            timeout, sleep, http_file, url = entry
            now = time.time()
            if timeout <= now:
                try:
                    data = http_file.read()
                except httplib.BadStatusLine, exc:
                    if exc.line:
                        continue
                    data = ''
                except HTTPFileTempFail:
                    if retry:
                        data = ''
                    else:
                        continue
                except HTTPFileError:
                    continue
                if data:
                    if not quiet and last_activity is not http_file:
                        if need_newline:
                            need_newline = False
                            stream.write('\n')
                        stream.write('==> ' + url + ' <==\n')
                        last_activity = http_file
                    need_newline |= data[-1] != '\n'
                    stream.write(data)
                    if follow:
                        sleep = sleep_min
                    else:
                        continue
                else:
                    sleep = min(sleep * 2, sleep_max)
                entry[0] = timeout = now + sleep
                entry[1] = sleep
            append(entry)
            if timeout < next_timeout:
                next_timeout = timeout
        httpfile_list = next_httpfile_list
        if httpfile_list:
            to_sleep = next_timeout - time.time()
            if to_sleep > 0:
                stream.flush()
                time.sleep(to_sleep)

def main():
    import argparse
    import re
    import sys
    parser = argparse.ArgumentParser(
        description='Print the last BYTES bytes of each URL to standard '
            'output. With more than one URL, precede each with a header '
            'giving the file name.',
        epilog="If the first character of K (the number of bytes or lines) is "
            "a '+', print beginning with the Kth item from the start of each "
            "file, otherwise, print the last K items in the file.  K may have "
            "a multiplier suffix: b 512, kB 1000, K 1024, MB 1000*1000, "
            "M 1024*1024, GB 1000*1000*1000, G 1024*1024*1024, and so on for "
            "T, P, E, Z, Y.",
    )
    parser.add_argument('URL', nargs='+',
        help='user information (<scheme>://<user info>@<host>) is converted '
            'into basic HTTP authentication; if not provided netrc is looked '
            'up; supported schemes (case-insensitive): %(schemes)s' % {
                'schemes': ', '.join(scheme_dict),
            },
    )
    parser.add_argument('-c', '--bytes',
        help='output the last BYTES bytes; alternatively, use -c +BYTES to '
            'output bytes starting with the Kth of each file',
    )
    parser.add_argument('-f', '--follow', action='store_true',
        help='output appended data as the file grows',
    )
    parser.add_argument('-F', dest='follow_retry', action='store_true',
        help='same as --follow --retry',
    )
    parser.add_argument('-n', '--netrc', nargs='?',
        help='enable netrc usage; optionally specifying a non-standard path',
    )
    parser.add_argument('-q', '--quiet', '--silent', action='store_true',
        help='never output headers giving file names',
    )
    parser.add_argument('--retry', action='store_true',
        help='keep trying to open a file even when it is or becomes '
            'inaccessible',
    )
    parser.add_argument('-s', '--sleep-interval', type=float,
        default=SLEEP_MIN,
        help='with -f, sleep for approximately SLEEP_INTERVAL seconds '
            '(default %(default).1f) between iterations',
    )
    parser.add_argument('-S', '--sleep-max-interval', type=float, default=0,
        help='increase sleep duration quadratically with consecutive '
            'empty/failed reads up to this value (default %(default).2f); '
            'sleep duration is set to --sleep-interval on next '
            'non-empty/successful read; values lower than --sleep-interval '
            'are set to --sleep-interval',
    )
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
        help='always output headers giving file names',
    )
    options = parser.parse_args()
    si_multiplicator_list = 'bkMGTPEZY'
    whence, offset, multiplicator, unit = re.match(
        r'(\+?)(\d+)([' + si_multiplicator_list + 'K]?)(B?)',
        options.bytes or str(DEFAULT_OFFSET),
    ).groups()
    if multiplicator == 'K':
        multiplicator = 'k'
    options.sleep_max_interval = max(
        options.sleep_interval,
        options.sleep_max_interval,
    )
    try:
        tail(
            stream=sys.stdout,
            url_list=options.URL,
            offset=int(float(offset) * (
                {'': JEDEC_UNIT, 'B': IEC_UNIT}[unit] ** (
                    si_multiplicator_list.index(multiplicator or 'b')
                )
            )) * {'': -1, '+': 1}[whence],
            whence={'': WHENCE_END, '+': WHENCE_BEGIN}[whence],
            quiet=options.quiet,
            follow=options.follow | options.follow_retry,
            netrc_path=options.netrc,
            retry=options.retry | options.follow_retry,
            sleep_min=options.sleep_interval,
            sleep_max=options.sleep_max_interval,
            verbose=options.verbose,
        )
    except (KeyboardInterrupt, SystemExit):
        pass

if __name__ == '__main__':
    main()
