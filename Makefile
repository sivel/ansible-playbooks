.PHONY: qcow2
qcow2:
	time ANSIBLE_FORCE_COLOR=1 ANSIBLE_BECOME_ASK_PASS=0 ansible-playbook -e rh_username='' -e rh_password='' fetch_$(@).yml | cat

# Playbooks that do not require a become password
.PHONY: proxmox_clone proxmox_destroy proxmox_templates src
proxmox_destroy proxmox_clone proxmox_templates src:
	ANSIBLE_BECOME_ASK_PASS=0 ansible-playbook $@.yml

.PHONY: clone destroy templates
destroy clone templates:
	ANSIBLE_BECOME_ASK_PASS=0 ansible-playbook proxmox_$@.yml

.DEFAULT:
	ansible-playbook -v $@.yml
