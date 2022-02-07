#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2021, Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+
#     (see https://www.gnu.org/licenses/gpl-3.0.txt)

import os

from ansible import config

import yaml

base = os.path.join(
    os.path.dirname(config.__file__),
    'base.yml'
)

with open(base) as f:
    data = yaml.safe_load(f)

vars_data = {
    '_d_distro_map': data['INTERPRETER_PYTHON_DISTRO_MAP']['default'],
    '_d_py_fallback': data['INTERPRETER_PYTHON_FALLBACK']['default'],
    '_d_alias_map': {
        'rhel': 'redhat',
    }
}

with open('vars/main.yml', 'w+') as f:
    yaml.dump(vars_data, f, indent=2, default_flow_style=False)
