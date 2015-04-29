#!/bin/bash

# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# A library of helper functions for deploying on Rackspace

# Use the config file specified in $KUBE_CONFIG_FILE, or default to
# config-default.sh.
KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../..
source $(dirname ${BASH_SOURCE})/${KUBE_CONFIG_FILE-"config-default.sh"}

verify-prereqs() {
  # Make sure that prerequisites are installed.
  for x in nova swiftly; do
    if [ "$(which $x)" == "" ]; then
      echo "cluster/rackspace/util.sh:  Can't find $x in PATH, please fix and retry."
      exit 1
    fi
  done

  if [[ -z "${OS_AUTH_URL-}" ]]; then
    echo "cluster/rackspace/util.sh: OS_AUTH_URL not set."
    echo -e "\texport OS_AUTH_URL=https://identity.api.rackspacecloud.com/v2.0/"
    return 1
  fi

  if [[ -z "${OS_USERNAME-}" ]]; then
    echo "cluster/rackspace/util.sh: OS_USERNAME not set."
    echo -e "\texport OS_USERNAME=myusername"
    return 1
  fi

  if [[ -z "${OS_PASSWORD-}" ]]; then
    echo "cluster/rackspace/util.sh: OS_PASSWORD not set."
    echo -e "\texport OS_PASSWORD=myapikey"
    return 1
  fi
}

# Ensure that we have a password created for validating to the master.  Will
# read from $HOME/.kubernetres_auth if available.
#
# Vars set:
#   KUBE_USER
#   KUBE_PASSWORD
get-password() {
  local file="$HOME/.kubernetes_auth"
  if [[ -r "$file" ]]; then
    KUBE_USER=$(cat "$file" | python -c 'import json,sys;print json.load(sys.stdin)["User"]')
    KUBE_PASSWORD=$(cat "$file" | python -c 'import json,sys;print json.load(sys.stdin)["Password"]')
    return
  fi
  KUBE_USER=admin
  KUBE_PASSWORD=$(python -c 'import string,random; print "".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))')

  # Store password for reuse.
  cat << EOF > "$file"
{
  "User": "$KUBE_USER",
  "Password": "$KUBE_PASSWORD"
}
EOF
  chmod 0600 "$file"
}

rax-ssh-key() {
  if [ ! -f $HOME/.ssh/${SSH_KEY_NAME} ]; then
    echo "cluster/rackspace/util.sh: Generating SSH KEY ${HOME}/.ssh/${SSH_KEY_NAME}"
    ssh-keygen -f ${HOME}/.ssh/${SSH_KEY_NAME} -N '' > /dev/null 2>&1
  fi

  if ! $(nova keypair-list 2>/dev/null | grep $SSH_KEY_NAME >/dev/null 2>&1); then
    echo "cluster/rackspace/util.sh: Uploading key to Rackspace:"
    echo -e "\tnova keypair-add ${SSH_KEY_NAME} --pub-key ${HOME}/.ssh/${SSH_KEY_NAME}.pub"
    nova keypair-add ${SSH_KEY_NAME} --pub-key ${HOME}/.ssh/${SSH_KEY_NAME}.pub 2>/dev/null
  else
    echo "cluster/rackspace/util.sh: SSH key ${SSH_KEY_NAME}.pub already uploaded"
  fi
}

find-release-tars() {
  SERVER_BINARY_TAR="${KUBE_ROOT}/server/kubernetes-server-linux-amd64.tar.gz"
  RELEASE_DIR="${KUBE_ROOT}/server/"
  if [[ ! -f "$SERVER_BINARY_TAR" ]]; then
    SERVER_BINARY_TAR="${KUBE_ROOT}/_output/release-tars/kubernetes-server-linux-amd64.tar.gz"
    RELEASE_DIR="${KUBE_ROOT}/_output/release-tars/"
  fi
  if [[ ! -f "$SERVER_BINARY_TAR" ]]; then
    echo "!!! Cannot find kubernetes-server-linux-amd64.tar.gz"
    exit 1
  fi
}

rackspace-set-vars() {
  CLOUDFILES_CONTAINER="kubernetes-releases-${OS_USERNAME}"
  CONTAINER_PREFIX=${CONTAINER_PREFIX-devel/}
  find-release-tars
}

# Retrieves a tempurl from cloudfiles to make the release object publicly accessible temporarily.
find-object-url() {
  rackspace-set-vars

  KUBE_TAR=${CLOUDFILES_CONTAINER}/${CONTAINER_PREFIX}/kubernetes-server-linux-amd64.tar.gz

  RELEASE_TMP_URL=$(swiftly -A ${OS_AUTH_URL} -U ${OS_USERNAME} -K ${OS_PASSWORD} tempurl GET ${KUBE_TAR})
  echo "cluster/rackspace/util.sh: Object temp URL:"
  echo -e "\t${RELEASE_TMP_URL}"
}

ensure-dev-container() {
  SWIFTLY_CMD="swiftly -A ${OS_AUTH_URL} -U ${OS_USERNAME} -K ${OS_PASSWORD}"

  if ! ${SWIFTLY_CMD} get ${CLOUDFILES_CONTAINER} > /dev/null 2>&1 ; then
    echo "cluster/rackspace/util.sh: Container doesn't exist. Creating container ${CLOUDFILES_CONTAINER}"
    ${SWIFTLY_CMD} put ${CLOUDFILES_CONTAINER} > /dev/null 2>&1
  fi
}

# Copy kubernetes-server-linux-amd64.tar.gz to cloud files object store
copy-dev-tarballs() {
  echo "cluster/rackspace/util.sh: Uploading to Cloud Files"
  ${SWIFTLY_CMD} put -i ${RELEASE_DIR}/kubernetes-server-linux-amd64.tar.gz \
  ${CLOUDFILES_CONTAINER}/${CONTAINER_PREFIX}/kubernetes-server-linux-amd64.tar.gz > /dev/null 2>&1

  echo "cluster/rackspace/util.sh: Release pushed."
}

download-easyrsa() {
  $(cd ${KUBE_TEMP}; curl -L -O https://storage.googleapis.com/kubernetes-release/easy-rsa/easy-rsa.tar.gz > /dev/null 2>&1)
  $(cd ${KUBE_TEMP}; tar xzf easy-rsa.tar.gz > /dev/null 2>&1)

  export EASYRSA=${KUBE_TEMP}/easy-rsa-master/easyrsa3
  export EASYRSA_PKI=${KUBE_TEMP}/pki
}

make-ca-cert() {
  local cert_name=$1

  ${EASYRSA}/easyrsa init-pki > /dev/null 2>&1
  ${EASYRSA}/easyrsa --batch "--req-cn=${cert_name}@`date +%s`" build-ca nopass > /dev/null 2>&1
}

make-server-cert() {
  local cert_name=$1
  local cert_ip=$2

  ${EASYRSA}/easyrsa --subject-alt-name=IP:${cert_ip} build-server-full ${cert_name} nopass > /dev/null 2>&1
}

make-peer-cert() {
  local cert_name=$1
  local cert_ip=$2

  EASYRSA_EXTRA_EXTS="extendedKeyUsage = clientAuth,serverAuth" \
    ${EASYRSA}/easyrsa --subject-alt-name=IP:${cert_ip} build-server-full ${cert_name} nopass > /dev/null 2>&1
}

make-client-cert() {
  local cert_name=$1

  ${EASYRSA}/easyrsa build-client-full ${cert_name} nopass > /dev/null 2>&1
}

distribute-etcd-certs() {
  local public_ip=$1
  local private_ip=$2

  echo "cluster/rackspace/util.sh: Distributing ETCD Certificates to: ${public_ip}"
  echo

  local etcd_server_cert_name="${private_ip}-etcd-server"
  make-server-cert "${etcd_server_cert_name}" ${private_ip}

  local etcd_peer_cert_name="${private_ip}-etcd-peer"
  make-peer-cert "${etcd_peer_cert_name}" ${private_ip}

  ssh -i $HOME/.ssh/${SSH_KEY_NAME} root@${public_ip} > /dev/null 2>&1 <<EOF
  mkdir -p /etc/ssl/etcd/certs
  mkdir -p /etc/ssl/etcd/private
  chmod -R 600 /etc/ssl/etcd/private
EOF

  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/ca.crt" root@${public_ip}:/etc/ssl/etcd/certs/ca.crt
  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/issued/${etcd_server_cert_name}.crt" root@${public_ip}:/etc/ssl/etcd/certs/server.crt
  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/private/${etcd_server_cert_name}.key" root@${public_ip}:/etc/ssl/etcd/private/server.key
  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/issued/${etcd_peer_cert_name}.crt" root@${public_ip}:/etc/ssl/etcd/certs/peer.crt
  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/private/${etcd_peer_cert_name}.key" root@${public_ip}:/etc/ssl/etcd/private/peer.key
}

distribute-kubernetes-master-certs() {
  local public_ip=$1
  local private_ip=$2

  echo "cluster/rackspace/util.sh: Distributing Kubernetes Master Certificates to: ${public_ip}"
  echo

  local kubernetes_server_cert_name="${private_ip}-kubernetes-server"
  make-server-cert "${kubernetes_server_cert_name}" ${private_ip}

  ssh -i $HOME/.ssh/${SSH_KEY_NAME} root@${public_ip} > /dev/null 2>&1 <<EOF
  mkdir -p /etc/ssl/kubernetes/certs
  mkdir -p /etc/ssl/kubernetes/private
  chmod -R 600 /etc/ssl/kubernetes/private
EOF

  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/ca.crt" root@${public_ip}:/etc/ssl/kubernetes/certs/ca.crt
  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/issued/${kubernetes_server_cert_name}.crt" root@${public_ip}:/etc/ssl/kubernetes/certs/server.crt
  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/private/${kubernetes_server_cert_name}.key" root@${public_ip}:/etc/ssl/kubernetes/private/server.key
}

distribute-kubernetes-minion-certs() {
  local public_ip=$1
  local private_ip=$2

  echo "cluster/rackspace/util.sh: Distributing Kubernetes Minion Certificates to: ${public_ip}"
  echo

  local kubernetes_client_cert_name="${private_ip}-kubernetes-client"
  make-server-cert "${kubernetes_client_cert_name}" ${private_ip}

  ssh -i $HOME/.ssh/${SSH_KEY_NAME} root@${public_ip} > /dev/null 2>&1 <<EOF
  mkdir -p /etc/ssl/kubernetes/certs
  mkdir -p /etc/ssl/kubernetes/private
  chmod -R 600 /etc/ssl/kubernetes/private
EOF

  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/ca.crt" root@${public_ip}:/etc/ssl/kubernetes/certs/ca.crt
  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/issued/${kubernetes_client_cert_name}.crt" root@${public_ip}:/etc/ssl/kubernetes/certs/client.crt
  scp -i $HOME/.ssh/${SSH_KEY_NAME} "${EASYRSA_PKI}/private/${kubernetes_client_cert_name}.key" root@${public_ip}:/etc/ssl/kubernetes/private/client.key
}

rax-boot-master() {
  DISCOVERY_URL=$(curl https://discovery.etcd.io/new)
  DISCOVERY_ID=$(echo "${DISCOVERY_URL}" | cut -f 4 -d /)
  echo "cluster/rackspace/util.sh: etcd discovery URL: ${DISCOVERY_URL}"

  MASTER_CLOUD_CONFIG=${KUBE_TEMP}/master-cloud-config.yaml

  # Copy cloud-config to KUBE_TEMP and work some sed magic
  sed -e "s|DISCOVERY_ID|${DISCOVERY_ID}|" \
    -e "s|CLOUD_FILES_URL|${RELEASE_TMP_URL//&/\\&}|" \
    -e "s|KUBE_USER|${KUBE_USER}|" \
    -e "s|KUBE_PASSWORD|${KUBE_PASSWORD}|" \
    -e "s|PORTAL_NET|${PORTAL_NET}|" \
    -e "s|OS_AUTH_URL|${OS_AUTH_URL}|" \
    -e "s|OS_USERNAME|${OS_USERNAME}|" \
    -e "s|OS_PASSWORD|${OS_PASSWORD}|" \
    -e "s|OS_TENANT_NAME|${OS_TENANT_NAME}|" \
    -e "s|OS_REGION_NAME|${OS_REGION_NAME}|" \
    $(dirname $0)/rackspace/cloud-config/master-cloud-config.yaml > ${MASTER_CLOUD_CONFIG}

  MASTER_BOOT_CMD="nova boot \
    --key-name ${SSH_KEY_NAME} \
    --flavor ${KUBE_MASTER_FLAVOR} \
    --image ${KUBE_IMAGE} \
    --meta ${MASTER_TAG} \
    --meta ETCD=${DISCOVERY_ID} \
    --user-data ${MASTER_CLOUD_CONFIG} \
    --config-drive true \
    --nic net-id=${NETWORK_UUID} \
    ${MASTER_NAME}"

  echo "cluster/rackspace/util.sh: Booting ${MASTER_NAME} with the following command:"
  echo -e "\t${MASTER_BOOT_CMD}"
  $MASTER_BOOT_CMD 2>/dev/null
}

rax-boot-minions() {
  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    MINION_CLOUD_CONFIG=${KUBE_TEMP}/minion-cloud-config-$((${i} + 1)).yaml

    sed -e "s|DISCOVERY_ID|${DISCOVERY_ID}|" \
      -e "s|INDEX|$((i + 1))|g" \
      -e "s|CLOUD_FILES_URL|${RELEASE_TMP_URL//&/\\&}|" \
      -e "s|KUBE_USER|${KUBE_USER}|" \
      -e "s|KUBE_PASSWORD|${KUBE_PASSWORD}|" \
      -e "s|ENABLE_NODE_MONITORING|${ENABLE_NODE_MONITORING:-false}|" \
      -e "s|ENABLE_NODE_LOGGING|${ENABLE_NODE_LOGGING:-false}|" \
      -e "s|LOGGING_DESTINATION|${LOGGING_DESTINATION:-}|" \
      -e "s|ENABLE_CLUSTER_DNS|${ENABLE_CLUSTER_DNS:-false}|" \
      -e "s|DNS_SERVER_IP|${DNS_SERVER_IP:-}|" \
      -e "s|DNS_DOMAIN|${DNS_DOMAIN:-}|" \
      $(dirname $0)/rackspace/cloud-config/minion-cloud-config.yaml > ${MINION_CLOUD_CONFIG}

    MINION_BOOT_CMD="nova boot \
      --key-name ${SSH_KEY_NAME} \
      --flavor ${KUBE_MINION_FLAVOR} \
      --image ${KUBE_IMAGE} \
      --meta ${MINION_TAG} \
      --user-data ${MINION_CLOUD_CONFIG} \
      --config-drive true \
      --nic net-id=${NETWORK_UUID} \
      ${MINION_NAMES[$i]}"

    echo "cluster/rackspace/util.sh: Booting ${MINION_NAMES[$i]} with the following command:"
    echo -e "\t${MINION_BOOT_CMD}"
    $MINION_BOOT_CMD 2>/dev/null
  done
}

rax-nova-network() {
  if ! $(nova network-list 2>/dev/null | grep "${NOVA_NETWORK_LABEL}" > /dev/null 2>&1); then
    SAFE_CIDR=$(echo $NOVA_NETWORK_CIDR | tr -d '\\')
    NETWORK_CREATE_CMD="nova network-create $NOVA_NETWORK_LABEL $SAFE_CIDR"

    echo "cluster/rackspace/util.sh: Creating cloud network with following command:"
    echo -e "\t${NETWORK_CREATE_CMD}"
    $NETWORK_CREATE_CMD 2>/dev/null
  else
    echo "cluster/rackspace/util.sh: Using existing cloud network $NOVA_NETWORK_LABEL"
  fi
}

detect-minions() {
  KUBE_MINION_IPS=()
  KUBE_MINION_PRIVATE_IPS=()

  echo "cluster/rackspace/util.sh: Waiting for Minion IP Addresses."
  echo
  echo "  This will continually check to see if the node has the required IP addresses."
  echo

  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    local minion_ip=$(detect-nova-net ${MINION_NAMES[$i]} accessIPv4)
    while [ "${minion_ip-}" == "" ]; do
      minion_ip=$(detect-nova-net ${MINION_NAMES[$i]} accessIPv4)
      printf "."
      sleep 2
    done

    local minion_private_ip=$(detect-nova-net ${MINION_NAMES[$i]} $NOVA_NETWORK_LABEL)
    while [ "${minion_private_ip-}" == "" ]; do
      minion_private_ip=$(detect-nova-net ${MINION_NAMES[$i]} $NOVA_NETWORK_LABEL)
      printf "."
      sleep 2
    done

    echo "cluster/rackspace/util.sh: ${MINION_NAMES[$i]} IP Address is ${minion_ip}, Private IP Address is ${minion_private_ip}"
    KUBE_MINION_IPS+=("${minion_ip}")
    KUBE_MINION_PRIVATE_IPS+=("${minion_private_ip}")
  done
}

detect-master() {
  KUBE_MASTER=${MASTER_NAME}

  echo "cluster/rackspace/util.sh: Waiting for ${MASTER_NAME} IP Addresses."
  echo
  echo "  This will continually check to see if the master node has the required IP addresses."
  echo

  KUBE_MASTER_IP=$(detect-nova-net $KUBE_MASTER accessIPv4)
  while [ "${KUBE_MASTER_IP-}" == "" ]; do
    KUBE_MASTER_IP=$(detect-nova-net $KUBE_MASTER accessIPv4)
    printf "."
    sleep 2
  done

  KUBE_MASTER_PRIVATE_IP=$(detect-nova-net $KUBE_MASTER $NOVA_NETWORK_LABEL)
  while [ "${KUBE_MASTER_PRIVATE_IP-}" == "" ]; do
    KUBE_MASTER_PRIVATE_IP=$(detect-nova-net $KUBE_MASTER $NOVA_NETWORK_LABEL)
    printf "."
    sleep 2
  done

  echo "cluster/rackspace/util.sh: ${KUBE_MASTER} IP Address is ${KUBE_MASTER_IP}, Private IP Address is ${KUBE_MASTER_PRIVATE_IP}"
}

detect-nova-net() {
  echo $(nova show $1 --minimal 2>/dev/null | grep -i "$2" | awk -F"|" '{print $3}')
}

kube-up() {
  SCRIPT_DIR=$(CDPATH="" cd $(dirname $0); pwd)

  rackspace-set-vars
  ensure-dev-container
  ###### copy-dev-tarballs

  # Find the release to use.  Generally it will be passed when doing a 'prod'
  # install and will default to the release/config.sh version when doing a
  # developer up.
  find-object-url

  # Create a temp directory to hold scripts that will be uploaded to master/minions
  KUBE_TEMP=$(mktemp -d -t kubernetes.XXXXXX)
  trap "rm -rf ${KUBE_TEMP}" EXIT

  get-password
  python $(dirname $0)/../third_party/htpasswd/htpasswd.py -b -c ${KUBE_TEMP}/htpasswd $KUBE_USER $KUBE_PASSWORD
  HTPASSWD=$(cat ${KUBE_TEMP}/htpasswd)

  rax-nova-network
  NETWORK_UUID=$(nova network-list 2>/dev/null | grep -i ${NOVA_NETWORK_LABEL} | awk '{print $2}')

  # create and upload ssh key if necessary
  rax-ssh-key

  # echo "cluster/rackspace/util.sh: Starting Cloud Servers"
  # rax-boot-master
  #
  # rax-boot-minions

  FAIL=0
  for job in `jobs -p`
  do
      wait $job || let "FAIL+=1"
  done
  if (( $FAIL != 0 )); then
    echo "cluster/rackspace/util.sh: ${FAIL} commands failed.  Exiting."
    exit 2
  fi

  # gater public/private ip's of master
  detect-master

  # gater public/private ip's from minions
  # detect-minions

  # download easyrsa to use for application server/client certificate signing
  echo "download easyrsa"
  download-easyrsa

  make-ca-cert ${KUBE_MASTER_PRIVATE_IP}

  # create and distribute etcd certificates
  distribute-etcd-certs ${KUBE_MASTER_IP} ${KUBE_MASTER_PRIVATE_IP}
  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    distribute-etcd-certs ${KUBE_MINION_IPS[$i]} ${KUBE_MINION_PRIVATE_IPS[$i]}
  done

  # # create and distribute kubernetes master certificates
  # distribute-kubernetes-master-certs ${KUBE_MASTER_IP} ${KUBE_MASTER_PRIVATE_IP}
  #
  # # create and distribute kubernetes minion certificates
  # for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
  #   distribute-kubernetes-minion-certs ${KUBE_MINION_IPS[$i]} ${KUBE_MINION_PRIVATE_IPS[$i]}
  # done

  exit

  # echo "Waiting for cluster initialization."
  # echo
  # echo "  This will continually check to see if the API for kubernetes is reachable."
  # echo "  This might loop forever if there was some uncaught error during start"
  # echo "  up."
  # echo
  #
  # #This will fail until apiserver salt is updated
  # until $(curl --insecure --user ${KUBE_USER}:${KUBE_PASSWORD} --max-time 5 \
  #         --fail --output /dev/null --silent https://${KUBE_MASTER_IP}/api/v1beta1/pods); do
  #     printf "."
  #     sleep 2
  # done
  #
  # echo "Kubernetes cluster created."
  #
  # # Don't bail on errors, we want to be able to print some info.
  # set +e
  #
  # echo "All minions may not be online yet, this is okay."
  # echo
  # echo "Kubernetes cluster is running.  The master is running at:"
  # echo
  # echo "  https://${KUBE_MASTER_IP}"
  # echo
  # echo "The user name and password to use is located in ~/.kubernetes_auth."
  # echo
  # echo "Security note: The server above uses a self signed certificate.  This is"
  # echo "    subject to \"Man in the middle\" type attacks."
  # echo
}

# Perform preparations required to run e2e tests
function prepare-e2e() {
  echo "Rackspace doesn't need special preparations for e2e tests"

}
