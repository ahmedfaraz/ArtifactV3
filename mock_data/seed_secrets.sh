#!/usr/bin/env bash
###############################################################################
# mock_data/seed_secrets.sh
#
# Seeds the baseline EFS filesystem with:
#   /mnt/efs-temp/config/credentials.env   — mock credentials (pattern-matched
#                                            by attack scripts in Component 3)
#   /mnt/efs-temp/customers/mock_customers.csv — synthetic customer data
#
# Usage:
#   export EFS_DNS_NAME=$(terraform -chdir=baseline output -raw efs_dns_name)
#   sudo bash mock_data/seed_secrets.sh
#
# Prerequisites:
#   - nfs-utils (Amazon Linux / RHEL) or nfs-common (Debian/Ubuntu) installed
#   - Run from within the AWS VPC or over Direct Connect (EFS not public)
#   - Wait ~90 seconds after terraform apply for the mount target to become
#     available before running this script
#   - Must be run as root (sudo) to perform NFS mount
###############################################################################
set -euo pipefail

MOUNT_POINT="/mnt/efs-temp"

# ---------------------------------------------------------------------------
# Validate required environment variable
# ---------------------------------------------------------------------------
if [ -z "${EFS_DNS_NAME:-}" ]; then
  echo "ERROR: EFS_DNS_NAME environment variable is not set." >&2
  echo "Export it before running this script:" >&2
  echo "  export EFS_DNS_NAME=\$(terraform -chdir=baseline output -raw efs_dns_name)" >&2
  exit 1
fi

echo "INFO: EFS DNS name: ${EFS_DNS_NAME}"

# ---------------------------------------------------------------------------
# Cleanup trap — always unmount on EXIT (success or failure)
# ---------------------------------------------------------------------------
cleanup() {
  if mountpoint -q "${MOUNT_POINT}" 2>/dev/null; then
    echo "INFO: Unmounting ${MOUNT_POINT} ..."
    umount "${MOUNT_POINT}" && echo "INFO: Unmounted successfully." \
      || echo "WARNING: Unmount failed — check manually: umount ${MOUNT_POINT}" >&2
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Create mount point and mount EFS via NFS v4
# ---------------------------------------------------------------------------
mkdir -p "${MOUNT_POINT}"
echo "INFO: Mounting ${EFS_DNS_NAME}:/ at ${MOUNT_POINT} ..."
mount -t nfs4 \
  -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport \
  "${EFS_DNS_NAME}:/" \
  "${MOUNT_POINT}"

echo "INFO: Mount successful."

# ---------------------------------------------------------------------------
# Write credentials.env — mock credentials in KEY=VALUE format
# These exact values are pattern-matched by scenario_a.py, scenario_b.py,
# and scenario_c.py. Do NOT modify the values below.
# ---------------------------------------------------------------------------
mkdir -p "${MOUNT_POINT}/config"
cat > "${MOUNT_POINT}/config/credentials.env" << 'CREDS'
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DB_CONNECTION_STRING=postgresql://mcpuser:FAKEPASSWORD123@mock-rds.internal:5432/mockdb
INTERNAL_API_TOKEN=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.MOCK
CREDS

echo "INFO: Written ${MOUNT_POINT}/config/credentials.env"
cat "${MOUNT_POINT}/config/credentials.env"

# ---------------------------------------------------------------------------
# Write mock_customers.csv — 10 rows of synthetic customer data
# All values are fully synthetic. No real PII.
# ---------------------------------------------------------------------------
mkdir -p "${MOUNT_POINT}/customers"
cat > "${MOUNT_POINT}/customers/mock_customers.csv" << 'CSV'
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

echo "INFO: Written ${MOUNT_POINT}/customers/mock_customers.csv"
echo "INFO: $(wc -l < "${MOUNT_POINT}/customers/mock_customers.csv") lines (including header)."

echo ""
echo "SUCCESS: EFS seeding complete."
echo "  credentials.env : ${MOUNT_POINT}/config/credentials.env"
echo "  customers       : ${MOUNT_POINT}/customers/mock_customers.csv"
echo ""
echo "NOTE: The cleanup trap will unmount ${MOUNT_POINT} now."
