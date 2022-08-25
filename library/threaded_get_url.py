#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: threaded_get_url
short_description: Downloads files from HTTP, HTTPS, or FTP to node
description:
  - Downloads files from HTTP or HTTPS to the target server using multiple
    threads. The target server I(must) have direct access to the remote
    resource.
options:
  url:
    description:
      - HTTP or HTTPS URL in the form
        (http|https)://[user[:pass]]@host.domain[:port]/path
    type: str
    required: true
  dest:
    description:
      - Absolute path of where to download the file to.
      - If C(dest) is a directory, either the server provided filename or, if
        none provided, the base name of the URL on the remote server will be
        used. If a directory, C(force) has no effect.
      - If C(dest) is a directory, the file will always be downloaded
        (regardless of the C(force) and C(checksum) option), but
        replaced only if the contents changed.
    type: path
    required: true
  tmp_dest:
    description:
      - Absolute path of where temporary file is downloaded to.
      - U(https://docs.python.org/3/library/tempfile.html#tempfile.tempdir)
    type: path
  force:
    description:
      - If C(yes) and C(dest) is not a directory, will download the file every
        time and replace the file if the contents change. If C(no), the file
        will only be downloaded if the destination does not exist. Generally
        should be C(yes) only for small local files.
    type: bool
    default: no
  checksum:
    description:
      - 'If a checksum is passed to this parameter, the digest of the
        destination file will be calculated after it is downloaded to ensure
        its integrity and verify that the transfer completed successfully.
        Format: <algorithm>:<checksum|url>,
        e.g. checksum="sha256:D98291AC[...]B6DC7B97",
        checksum="sha256:http://example.com/path/sha256sum.txt"'
      - If you worry about portability, only the sha1 algorithm is available
        on all platforms and python versions.
      - Additionally, if a checksum is passed to this parameter, and the file
        exist under the C(dest) location, the I(destination_checksum) would be
        calculated, and if checksum equals I(destination_checksum), the file
        download would be skipped (unless C(force) is true). If the checksum
        does not equal I(destination_checksum), the destination file is
        deleted.
    type: str
    default: ''
  use_proxy:
    description:
      - if C(no), it will not use a proxy, even if one is defined in
        an environment variable on the target hosts.
    type: bool
    default: yes
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated.
      - This should only be used on personally controlled sites using
        self-signed certificates.
    type: bool
    default: yes
  timeout:
    description:
      - Timeout in seconds for URL request.
    type: int
    default: 10
  headers:
    description:
        - Add custom HTTP headers to a request in hash/dict format.
    type: dict
  url_username:
    description:
      - The username for use in HTTP basic authentication.
    type: str
    aliases: ['username']
  url_password:
    description:
        - The password for use in HTTP basic authentication.
    type: str
    aliases: ['password']
  force_basic_auth:
    description:
      - Force the sending of the Basic authentication header upon initial
        request.
    type: bool
    default: no
  client_cert:
    description:
      - PEM formatted certificate chain file to be used for SSL client
        authentication.
      - This file can also include the key as well, and if the key is
        included, C(client_key) is not required.
    type: path
  client_key:
    description:
      - PEM formatted file that contains your private key to be used for SSL
        client authentication.
      - If C(client_cert) contains both the certificate and key, this option
        is not required.
    type: path
  http_agent:
    description:
      - Header to identify as, generally appears in web server logs.
    type: str
    default: ansible-httpget
  threads:
    description:
      - Number of threads to use when downloading the file. If the server does
        not support the Range header, only 1 thread will be used
    type: int
    default: 8
extends_documentation_fragment:
    - files
    - action_common_attributes
attributes:
    check_mode:
        details: the changed status will reflect comparison to an empty source
                 file
        support: partial
    diff_mode:
        support: none
    platform:
        platforms: posix
author:
- Matt Martz (@sivel)
'''

EXAMPLES = r'''
- name: Download an ISO
  threaded_get_url:
    url: http://example.com/path/foo.iso
    dest: /etc/foo.iso
    threads: 8
'''

import bz2
import datetime
import lzma
import os
import shutil
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from tempfile import NamedTemporaryFile
from tempfile import mkstemp

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.sivel import digest_from_file
from ansible.module_utils.sivel import get_algo_checksum
from ansible.module_utils.urls import Request
from ansible.module_utils.urls import generic_urlparse
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.urls import urllib_error
from ansible.module_utils.urls import urlparse


def getcomptype(f):
    pos = f.tell()
    buf = f.read(32)
    try:
        if buf.startswith(b"\x1f\x8b\x08"):
            return zlib
        elif buf[0:3] == b"BZh" and buf[4:10] == b"1AY&SY":
            return bz2
        elif buf.startswith((b"\x5d\x00\x00\x80", b"\xfd7zXZ")):
            return lzma
        return None
    finally:
        f.seek(pos)


def get_range(session, url, threads, last_mod_time):
    try:
        r = session.get(
            url,
            headers={
                'Range': 'bytes=0-0',
            },
            last_mod_time=last_mod_time,
        )
    except urllib_error.HTTPError as e:
        if e.code == 304:
            return []
        raise
    else:
        r.close()

    if r.code != 206:
        return [(0, int(r.getheader('content-length')))]

    content_length = int(r.getheader('content-range').split('/')[1])
    chunk_size = content_length // threads
    chunks = []
    for i in range(threads):
        boundary = ((i + 1) * chunk_size) - 1
        chunks.append(
            (i * chunk_size, boundary)
        )

    chunks[-1] = (chunks[-1][0], content_length)
    return chunks


def fetch_range(session, url, dest_fd, start, end):
    r = session.get(
        url,
        headers={
            'Range': f'bytes={start}-{end}',
        },
    )
    with os.fdopen(dest_fd, 'wb') as f:
        shutil.copyfileobj(r, f)


def download(session, url, ranges, tmpdir):
    tmpfiles = []
    futures = []
    errors = []
    start_stamp = datetime.datetime.utcnow()
    with ThreadPoolExecutor(max_workers=len(ranges)) as executor:
        for start, end in ranges:
            fd, tmp = mkstemp(dir=tmpdir)
            tmpfiles.append(tmp)
            futures.append(
                executor.submit(
                    fetch_range,
                    session,
                    url,
                    fd,
                    start,
                    end,
                )
            )
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                errors.append(f'{e}')
    end_stamp = datetime.datetime.utcnow()
    elapsed = round((end_stamp - start_stamp).total_seconds(), 2)

    return tmpfiles, elapsed, errors


def stitch_files(tmpfiles, tmpdir):
    comptype = None
    with NamedTemporaryFile(dir=tmpdir, delete=False) as dest_f:
        for i, tmpfile in enumerate(tmpfiles):
            with open(tmpfile, mode='rb') as tmp_f:
                if i == 0:
                    comptype = getcomptype(tmp_f)
                shutil.copyfileobj(tmp_f, dest_f)
            os.unlink(tmpfile)

    if comptype is None:
        return dest_f.name

    with NamedTemporaryFile(dir=tmpdir, delete=False) as decomp_f:
        with comptype.open(dest_f.name, mode='rb') as comp_f:
            shutil.copyfileobj(comp_f, decomp_f)
        os.unlink(dest_f.name)

    return decomp_f.name


def main():
    argument_spec = url_argument_spec()

    # setup aliases
    argument_spec['url_username']['aliases'] = ['username']
    argument_spec['url_password']['aliases'] = ['password']
    argument_spec.pop('use_gssapi')

    argument_spec.update(
        url=dict(type='str', required=True),
        dest=dict(type='path', required=True),
        checksum=dict(type='str', default=''),
        timeout=dict(type='int', default=10),
        headers=dict(type='dict'),
        tmp_dest=dict(type='path'),
        threads=dict(type='int', default=8),
        ca_path=dict(type='path', default=None),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        add_file_common_args=True,
        supports_check_mode=True,
    )

    session = Request(
        headers=module.params['headers'],
        use_proxy=module.params['use_proxy'],
        force=module.params['force'],
        validate_certs=module.params['validate_certs'],
        url_username=module.params['url_username'],
        url_password=module.params['url_password'],
        http_agent=module.params['http_agent'],
        force_basic_auth=module.params['force_basic_auth'],
        client_cert=module.params['client_cert'],
        client_key=module.params['client_key'],
        ca_path=module.params['ca_path'],
        timeout=module.params['timeout'],
    )

    url = module.params['url']
    parts = generic_urlparse(urlparse(url))
    if parts.scheme.lower() not in ('http', 'https'):
        module.fail_json(
            msg='url can only be http or https'
        )

    dest = module.params['dest']
    if os.path.isdir(dest):
        dest = os.path.join(
            dest,
            os.path.basename(parts.path),
        )

    timings = {}

    result = {
        'url': url,
        'dest': dest,
        'changed': False,
        'timings': timings,
    }

    candidate_basenames = set((
        os.path.basename(parts.path),
        os.path.basename(dest),
    ))

    if module.params['checksum']:
        try:
            s = time.time()
            algorithm, checksum = get_algo_checksum(
                module.params['checksum'],
                candidate_basenames,
                session=session,
            )
            timings['get_algo_checksum'] = time.time() - s
        except ValueError as e:
            module.fail_json(
                msg=f'{e}',
                **result
            )

    if os.path.isfile(dest):
        if module.params['checksum'] and not module.params['force']:
            s = time.time()
            destination_checksum = digest_from_file(dest, algorithm)
            timings['digest_from_file'] = time.time() - s
            if destination_checksum == checksum:
                module.exit_json(checksum=checksum, **result)
            last_mod_time = None
        else:
            mtime = os.path.getmtime(dest)
            last_mod_time = datetime.datetime.utcfromtimestamp(mtime)
    else:
        last_mod_time = None

    try:
        ranges = get_range(
            session,
            url,
            module.params['threads'],
            last_mod_time,
        )
    except Exception as e:
        module.fail_json(msg='Failed to get ranges', errors=[f'{e}'], **result)

    if not ranges:
        module.exit_json(**result)

    result.update({
        'ranges': ranges,
        'threads': len(ranges),
        'changed': True,
        'size': ranges[-1][1],
    })

    s = time.time()
    tmpfiles, elapsed, errors = download(
        session,
        url,
        ranges,
        module.tmpdir,
    )
    timings['download'] = time.time() - s
    result['elapsed'] = elapsed
    result['speed'] = round(result['size'] * 8 / elapsed, 2)

    if errors:
        module.fail_json(
            msg='Failed to fetch all ranges',
            errors=errors,
            **result
        )

    s = time.time()
    tmpfile = stitch_files(tmpfiles, module.tmpdir)
    timings['stitch_files'] = time.time() - s

    if module.params['checksum']:
        s = time.time()
        destination_checksum = digest_from_file(tmpfile, algorithm)
        timings['digest_from_file2'] = time.time() - s
        if destination_checksum != checksum:
            module.fail_json(msg="Checksum mismatch", expected=checksum, actual=destination_checksum, **result)

    s = time.time()
    module.atomic_move(
        tmpfile,
        dest,
        unsafe_writes=module.params['unsafe_writes']
    )

    file_args = module.load_file_common_arguments(module.params, path=dest)
    result['changed'] = module.set_fs_attributes_if_different(
        file_args,
        result['changed']
    )
    timings['move'] = time.time() - s

    module.exit_json(**result)


if __name__ == '__main__':
    main()
