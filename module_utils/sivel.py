#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import hashlib
import os
import re
import secrets
from functools import partial

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.urls import Request


OPENSSL_FILE_CKSUM_RE = re.compile(
    r'^(\S+) ?\(([^\)]+)\) ?= ?(\S+)$',
    flags=re.M
)


def digest_from_file(filename, algorithm):
    digest = hashlib.new(algorithm)
    # Localize variable access to minimize overhead.
    digest_update = digest.update
    BUFFER_SIZE = (64 * 1024) // digest.block_size * digest.block_size
    with open(filename, 'rb') as f:
        for b_block in iter(partial(f.read, BUFFER_SIZE), b''):
            digest_update(b_block)
    return digest.hexdigest()


def get_algo_checksum(data, candidates, session=None):
    if not session:
        session = Request()

    algorithm, checksum = data.split(':', 1)

    if not checksum.isalnum():
        try:
            cksum_r = session.get(checksum)
        except Exception as e:
            raise ValueError(
                f'Failed to fetch checksum file: {e}'
            )

        file_map, token_candidate = parse_checksum_file(to_native(cksum_r.read()))
        if token_candidate:
            candidates.append(token_candidate)

        for candidate in candidates:
            if (checksum := file_map.get(candidate)):
                break
        else:
            raise ValueError(
                'Could not find checksum in checksum file for: {}'.format(
                    ', '.join(candidates)
                )
            )

    return algorithm, checksum


def parse_checksum_file(contents):
    file_map = {}
    token = None

    # Strip signature
    if contents.startswith('-----BEGIN PGP SIGNED MESSAGE-----'):
        idx = contents.index('-----BEGIN PGP SIGNATURE-----')
        contents = contents[34:idx]

    count = 0
    for line in contents.splitlines():
        # Ignore:
        #  1. empty lines
        #  2. comments
        #  3. openssl ``Hash:`` lines
        if not line.strip() or line[0] == '#' or line.startswith('Hash:'):
            continue
        count += 1
        if (match := OPENSSL_FILE_CKSUM_RE.match(line)):
            # openssl format
            file_map[match.group(2)] = match.group(3)
            continue
        elif len(line.split()) == 1:
            # non-standard checksum file with only a checksum and no filenames
            if count > 1:
                raise ValueError('too many single checksums')
            token = secrets.token_urlsafe(12)
            file_map[token] = line
            continue
        elif len(line.split()) == 2:
            # BSD checksum format
            checksum, filename = line.split()
            if filename[0] == '*':
                filename = os.path.basename(filename[1:])
            else:
                filename = os.path.basename(filename)
            file_map[filename] = checksum
    return file_map, token
