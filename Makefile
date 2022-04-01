.PHONY: qcow2
qcow2:
	ANSIBLE_FORCE_COLOR=1 ANSIBLE_BECOME_ASK_PASS=0 ansible-playbook -e rh_username='' -e rh_password='' fetch_qcow2.yml | cat
