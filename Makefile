.PHONY: qcow2
qcow2:
	time ANSIBLE_FORCE_COLOR=1 ANSIBLE_BECOME_ASK_PASS=0 ansible-playbook -e rh_username='' -e rh_password='' fetch_$(@).yml | cat

# Playbooks that do not require a become password
NOBECOME = src proxmox_clone proxmox_destroy proxmox_templates fetch_qcow2
.PHONY: $(NOBECOME)
$(NOBECOME):
	ANSIBLE_BECOME_ASK_PASS=0 ansible-playbook $(@).yml

# Shortcuts so I can type less
PROXMOX = clone destroy templates
.PHONY: $(PROXMOX)
$(PROXMOX):
	ANSIBLE_BECOME_ASK_PASS=0 ansible-playbook proxmox_$(@).yml

# Everything other than those defined above
DEFAULT = $(filter-out qcow2 $(NOBECOME) $(PROXMOX), $(basename $(wildcard *.yml)))
.PHONY: $(DEFAULT)
$(DEFAULT):
	ansible-playbook -v $(@).yml
