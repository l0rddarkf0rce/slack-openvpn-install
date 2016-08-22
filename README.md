# slack-openvpn-install

OpenVPN road warrior installer for Slackware.  It is based in Nyr's original script.

This script will let you setup your own VPN server in no more than a minute, even if you haven't used OpenVPN before.  It has been designed to be as unobtrusive and universal as possible.

There is no installation needed.  Just run the script as ROOT and follow the on-screen prompts.

wget https://git.io/v6SeG -O openvpn-install.sh

chmod +x openvpn-install.sh

sudo ./openvpn-install.sh

or clone the whole project

git clone https://github.com/l0rddarkf0rce/slack-openvpn-install.git

cd slack-openvpn-install/

chmod +x openvpn-install.sh

sudo ./openvpn-install.sh

Once it ends, you can run it again to add more users, remove some of them or even completely uninstall OpenVPN.
