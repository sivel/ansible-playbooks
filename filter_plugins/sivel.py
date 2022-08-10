#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os
import re
from pathlib import Path
from urllib.parse import urlparse

QCOW2_RE = re.compile(
    r'[\w\.-]+(?:genericcloud|cloudimg|cloud-base|kvm-legacy|kvm|nocloud)[\w\.-]*(?:\.qcow2|(?<!disk-kvm)\.img)',
    flags=re.I
)
SIXFOUR = re.compile('(amd64|x86_64)', flags=re.I)
STRIP_EXTENSIONS = frozenset(('.bz', '.gz', '.xz', '.qcow2', '.img'))


def weight_sort(v, weights, reverse=False):
    weight_len = len(weights)

    def _key(vv):
        for i, w in list(enumerate(weights))[::-1]:
            if w.lower() in vv.lower():
                return (i, vv)
        return (weight_len, vv)

    return sorted(v, key=_key, reverse=reverse)


def _normalize_dest(name):
    while (suffix := Path(name).suffix) and suffix in STRIP_EXTENSIONS:
        name = Path(name).stem
    return f'{name}.qcow2'


def newest_image(text, sixfour=True, pattern=None):
    o = urlparse(text)
    if o.hostname:
        name = Path(o.path).name
        return {
            'src': name,
            'dest': _normalize_dest(name),
        }

    matches = set()  # QCOW2_RE.findall(text)

    if pattern:
        pat_re = re.compile(pattern)
    else:
        pat_re = QCOW2_RE

    for m in pat_re.findall(text):
        m_lower = m.lower()
        if 'uefi' in m_lower or 'latest' in m_lower:
            continue
        if sixfour and not SIXFOUR.search(m):
            continue
        matches.add(m)

    weighted = weight_sort(
        matches,
        ['nocloud', 'kvm', 'kvm-legacy', 'cloud-base', 'cloudimg', 'genericcloud'],
    )

    name = weighted[-1]
    return {
        'src': name,
        'dest': _normalize_dest(name)
    }


def _stem(v):
    return os.path.splitext(v)[0]


def select_updated_images(hostvars, find_result):
    b = os.path.basename
    existing = set(b(f['path']) for f in find_result['files'])

    downloaded = set()
    changed = set()
    changed = []
    for host, data in hostvars.items():
        if not (download := data.get('downloads')):
            continue
        if not (dest := download.get('dest')):
            continue
        filename = os.path.basename(dest)
        downloaded.add(filename)
        if download.get('changed', False):
            changed.append(filename)

    remove = [r for r in existing - downloaded if 'rhel' not in r]
    remove_names = [_stem(r.replace('_', '-')) for r in remove + changed]
    return {
        'remove_files': remove,
        'remove_names': remove_names,
    }


class FilterModule:
    def filters(self):
        return {
            'newest_image': newest_image,
            'weight_sort': weight_sort,
            'select_updated_images': select_updated_images,
        }
