#!/usr/bin/env bash
###############################################################################
# mock_data/seed_secrets_hardened.sh
#
# Seeds the HARDENED EFS filesystem with mock_customers.csv ONLY.
# In the hardened architecture, credentials are stored in AWS Secrets Manager
# (provisioned by hardened/modules/secrets/main.tf) — NOT on EFS.
# Do NOT write credentials.env to EFS in the hardened environment.
#
# Usage:
#   export EFS_DNS_NAME=$(terraform -chdir=hardened output -raw efs_dns_name)
#   sudo bash mock_data/seed_secrets_hardened.sh
#
# Prerequisites:
#   - nfs-utils / nfs-common installed
#   - Run from within the AWS VPC (EFS is private in hardened architecture)
#   - Wait ~90 seconds after terraform apply for the mount target
#   - Must be run as root (sudo)
###############################################################################
set -euo pipefail

MOUNT_POINT="/mnt/efs-hardened-temp"

if [ -z "${EFS_DNS_NAME:-}" ]; then
  echo "ERROR: EFS_DNS_NAME environment variable is not set." >&2
  echo "  export EFS_DNS_NAME=\$(terraform -chdir=hardened output -raw efs_dns_name)" >&2
  exit 1
fi

echo "INFO: EFS DNS name: ${EFS_DNS_NAME}"

cleanup() {
  if mountpoint -q "${MOUNT_POINT}" 2>/dev/null; then
    echo "INFO: Unmounting ${MOUNT_POINT} ..."
    umount "${MOUNT_POINT}" && echo "INFO: Unmounted." \
      || echo "WARNING: Unmount failed — check: umount ${MOUNT_POINT}" >&2
  fi
}
trap cleanup EXIT

mkdir -p "${MOUNT_POINT}"
echo "INFO: Mounting ${EFS_DNS_NAME}:/ at ${MOUNT_POINT} ..."
mount -t nfs4 \
  -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport \
  "${EFS_DNS_NAME}:/" \
  "${MOUNT_POINT}"

echo "INFO: Mount successful."

# NOTE: Do NOT write credentials.env in hardened mode.
# Credentials are in Secrets Manager — writing them to EFS would undermine
# the control being evaluated.

mkdir -p "${MOUNT_POINT}"
cat > "${MOUNT_POINT}/mock_customers.csv" << 'CSV'
customer_id,full_name,email,account_id,account_balance
a1b2c3d4-e5f6-7890-abcd-ef1234567801,Alice Hartley,alice.hartley@synth-example.invalid,ACC-00000001,12450.75
b2c3d4e5-f6a7-8901-bcde-f12345678902,Bob Nguyen,bob.nguyen@synth-example.invalid,ACC-00000002,3200.00
c3d4e5f6-a7b8-9012-cdef-123456789003,Carol Ferris,carol.ferris@synth-example.invalid,ACC-00000003,87632.10
d4e5f6a7-b8c9-0123-defa-234567890104,David Okafor,david.okafor@synth-example.invalid,ACC-00000004,540.25
e5f6a7b8-c9d0-1234-efab-345678901205,Eva Lindqvist,eva.lindqvist@synth-example.invalid,ACC-00000005,22100.50
f6a7b8c9-d0e1-2345-fabc-456789012306,Frank Morozov,frank.morozov@synth-example.invalid,ACC-00000006,6780.90
a7b8c9d0-e1f2-3456-abcd-567890123407,Grace Owusu,grace.owusu@synth-example.invalid,ACC-00000007,150320.00
b8c9d0e1-f2a3-4567-bcde-678901234508,Henry Salazar,henry.salazar@synth-example.invalid,ACC-00000008,980.45
c9d0e1f2-a3b4-5678-cdef-789012345609,Isla Petrov,isla.petrov@synth-example.invalid,ACC-00000009,44215.60
d0e1f2a3-b4c5-6789-defa-890123456710,James Thornton,james.thornton@synth-example.invalid,ACC-00000010,7830.00
CSV

echo "INFO: Written ${MOUNT_POINT}/mock_customers.csv (hardened — no credentials.env)"
echo "SUCCESS: Hardened EFS seeding complete."
