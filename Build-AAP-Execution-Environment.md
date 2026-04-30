# Building an Ansible Automation Platform (*AAP*) Execution Environment (*EE*) (AAP 2.5)

This document describes how to build a custom execution environment (*EE*) for Ansible Automation Platform that includes:

* Azure SDK support
* WinRM / Windows automation
* Kerberos authentication
* LDAP / Active Directory integration
* VMware, AWS, Cisco, and general automation collections

---

# 1. Directory Layout

```bash
# Create the user to manage AAP containers
sudo useradd -m -s /bin/bash -c "AAP Execution Environment User" -U poduser
sudo passwd poduser --stdin
sudo usermod -aG wheel poduser # Needs sudo permissions at least temprorarily for builds and installations

# Ensure home directory has correct permissions
sudo chown -R poduser:poduser /home/poduser
sudo chmod 700 /home/poduser

# Verify you receive 2 results from the below command
grep poduser /etc/sub?id

# Ensure Linger is set to yes for poduser
loginctl enable-linger poduser
loginctl show-user poduser | grep Linger
sudo -u poduser podman info | grep rootless
# EXPECTED OUTPUT BELOW:
  rootlessNetworkCmd: pasta
    rootless: true

# Create a dedicated execution environment directory
sudo -i -u poduser
podman info
ansible-builder --version
mkdir -p /home/poduser/aap_ee_envs
cd /home/poduser/aap_ee_envs
```

Expected files:

```text
.
├── execution-environment.yml
├── requirements.txt
├── bindep.txt
├── requirements.yml
├── context/
   └──krb5.conf
└── update_ee_environment.sh
```

---

# 2. execution-environment.yml

```yaml
version: 3

images:
  base_image:
    name: registry.redhat.io/ansible-automation-platform-25/ee-minimal-rhel9:latest

dependencies:
  ansible_core:
    package_pip: ansible-core
  ansible_runner:
    package_pip: ansible-runner
  galaxy: requirements.yml
  python: requirements.txt
  system: bindep.txt

additional_build_steps:
  prepend_base:
    - RUN microdnf install -y krb5-workstation krb5-libs && microdnf clean all
    - COPY krb5.conf /etc/krb5.conf
    - RUN microdnf install -y dnf && microdnf clean all
    - RUN pip3 install --upgrade pip setuptools wheel
    - RUN dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
    - RUN dnf install -y python3-kerberos

  append_final:
    - RUN microdnf clean all && rm -rf /var/cache/dnf/*
```

---

# 3. requirements.txt

```text
azure-identity>=1.6.0,<2.0.0
pywinrm[credssp]>=0.4.2,<0.5.0
ldap3>=2.9
pyasn1>=0.4.8
certifi>=2020.12.5,<2025.0.0
```

---

# 4. bindep.txt

```text
gcc                [platform:rpm]
python3-devel      [platform:rpm]
krb5-devel         [platform:rpm]
krb5-libs          [platform:rpm]
krb5-workstation   [platform:rpm]
openssl-devel      [platform:rpm]
libffi-devel       [platform:rpm]
dnf                [platform:rpm]
jq                 [platform:rpm]
zip                [platform:rpm]
unzip              [platform:rpm]
```

---

# 5. requirements.yml

```yaml
---
collections:
  - name: ansible.posix
  - name: cisco.ios
  - name: ansible.netcommon
  - name: ansible.windows
  - name: ansible.utils
  - name: vmware.vmware_rest
  - name: amazon.aws
  - name: azure.azcollection
  - name: community.vmware
  - name: microsoft.ad
```

---

# 6. Kerberos Config (krb5.conf)

Example:

```ini
# To opt out of the system crypto-policies configuration of krb5, remove the
# symlink at /etc/krb5.conf.d/crypto-policies which will not be recreated.
includedir /etc/krb5.conf.d/

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt
    spake_preauth_groups = edwards25519
    dns_canonicalize_hostname = fallback
    qualify_shortname = ""
    default_ccache_name = KEYRING:persistent:%{uid}
    udp_preference_limit = 0
    default_realm = SUBDOMAIN.DOMAIN.COM

[realms]
SUBDOMAIN.DOMAIN.COM = {
    kdc = dc-001.subdomain.domain.com
    admin_server = dc-001.subdomain.domain.com
}

[domain_realm]
.subdomain.domain.com = SUBDOMAIN.DOMAIN.COM
subdomain.domain.com = SUBDOMAIN.DOMAIN.COM
```

---

# 7. Manual Build Commands

```bash
cd /home/poduser/aap_ee_envs
```

Login:

```bash
# For this command enter your Red Hat credentials
podman login registry.redhat.io

# For this command enter the AAP web UI login credentials for the admin user
podman login --tls-verify=true ansible.domain.com
```

Pull base image:

```bash
podman pull registry.redhat.io/ansible-automation-platform-25/ee-minimal-rhel9:latest
```

Build:

```bash
ansible-builder build -vvv -t aap_ee_env:test -f execution-environment.yml
```

Verify:

```bash
podman images | grep aap_ee_env
```

Tag + push:

```bash
podman tag aap_ee_env:test ansible.domain.com/aap_ee:test
podman push --tls-verify=true ansible.domain.com/aap_ee:test
```

---

# 8. Automated Build Script Usage

Make executable:

```bash
chmod +x update_ee_environment.sh
```

Run:

```bash
./update_ee_environment.sh
```

---

# 9. Versioning

Auto-generated format:

```text
YYYYMMDD-HHMMSS-g<gitsha>
```

Override manually:

```bash
EE_VERSION=1.0.0 ./update_ee_environment.sh
```

---

# 10. Validate the EE

Run container:

```bash
podman run --rm -it ansible.domain.com/aap_ee:<tag> /bin/bash
```

Check Ansible:

```bash
ansible --version
ansible-galaxy collection list
```

Check Python deps:

```bash
python3 -m pip list
```

Quick import test:

```bash
python3 - <<'PY'
import winrm, ldap3, pyasn1, certifi
from azure.identity import DefaultAzureCredential
print("OK")
PY
```

Check Kerberos:

```bash
kinit --version || true
klist || true
```

---

# 11. Add EE to AAP

In AAP UI:

* Go to **Administration → Execution Environments**
* Add new EE
* Image:

```text
ansible.domain.com/aap_ee:<tag>
```

* Add registry credential
* Save and assign to job templates

---

# 12. Troubleshooting

### Build fails (storage)

```bash
podman system prune -a -f
```

---

### Registry login issues

```bash
podman login ansible.domain.com
```

---

### Base image pull fails

```bash
podman login registry.redhat.io
```

---

### Kerberos issues

Inside container:

```bash
cat /etc/krb5.conf
kinit user@REALM
klist
```

---

### Missing Python deps

```bash
podman run -it <image> pip list
```

---

# 13. Recommended Workflow

```bash
cd /home/poduser/aap_ee_envs

# Edit configs
vim execution-environment.yml
vim requirements.txt
vim bindep.txt
vim requirements.yml

# Build + push
./update_ee_environment.sh
```

---

# 14. What This EE Supports

* Azure automation
* Windows / WinRM (CredSSP + Kerberos)
* Active Directory / LDAP
* VMware (REST + community)
* AWS
* Cisco IOS
* General Linux automation
* Kerberos auth workflows
* JSON / zip utilities

---

# 15. Version Control

Track:

```text
execution-environment.yml
requirements.txt
bindep.txt
requirements.yml
update_ee_environment.sh
```

Avoid committing:

* credentials
* keytabs
* secrets

---
