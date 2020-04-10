#Stop on error
set -e
echo "Getting most helm updated version"
wget https://get.helm.sh/helm-v3.1.2-linux-amd64.tar.gz

echo "Unpacking helm v3.1.2"
tar -zxvf helm-v3.1.2-linux-amd64.tar.gz

echo "Checking helm version command from the source package"
./linux-amd64/helm version

echo "Looking helm directory ls command"
ls  /home/vsts/work/r1/a/linux-amd64/

cd /usr/bin
echo "Creating a symbolic link to make helm wide system scope"
sudo ln -s /home/vsts/work/r1/a/linux-amd64/helm helm
echo "Symbolic link created"

cd
echo "Now in root path directory to test the wide scope helm command"
helm version

echo 'Adding most updated helm index chart repositories'
helm repo add stable https://kubernetes-charts.storage.googleapis.com/

echo 'Upgrading helm index repositories'
helm repo update 