# ansible-openssh

This ansible role installs and configures openssh

# Caveats

1. Currently this is limited to configuring `sshd_config`, but will eventually be extended to `ssh_config` as well.
1. Not all possible configuration values are provided in `defaults/main.yml` as there are so many differences between operating systems and openssh versions
1. `sshd_config` options are prefixed with `opensshd_`, `ssh_config` options will be prefixed with `openssh_`

## Requirements

This role requires Ansible 1.4 higher and platforms listed in the metadata file.

## Examples

### Paramaterized Role

    ---
    - hosts: all
      roles:
        - role: openssh
          opensshd_PermitRootLogin: "no"

### Vars

    ---
    - hosts: all
      vars:
        opensshd_PermitRootLogin: "no"
      roles:
        - openssh

### Group vars

#### group_vars/production

    ---
    opensshd_PermitRootLogin: "no"

#### site.yml

    ---
    - hosts: all
      roles:
        - openssh
