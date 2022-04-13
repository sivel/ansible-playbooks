#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


def weight_sort(v, weights, reverse=False):
    weight_len = len(weights)

    def _key(vv):
        for i, w in enumerate(weights):
            if w.lower() in vv.lower():
                return (i, vv)
        return (weight_len, vv)

    return sorted(v, key=_key, reverse=reverse)


class FilterModule:
    def filters(self):
        return {
            'weight_sort': weight_sort,
        }
