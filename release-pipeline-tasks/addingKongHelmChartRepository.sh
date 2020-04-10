#Stop on error
set -e

echo 'Adding kong chart repository'
helm repo add kong https://charts.konghq.com

echo 'Upgrading helm index again'
helm repo update