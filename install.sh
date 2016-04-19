#!/usr/bin/env bash
set -e
BASE_URL="https://github.com/AgilData/gibbs-mysql-spyglass/releases/download"
VERSION="v0.6.28"

if [[ "$OSTYPE" == "linux-gnu" ]]; then
        PLATFORM="x86_64-unknown-linux-gnu"
        DISTRO=$(cat /etc/*-release | grep '^ID_LIKE=' | awk -F= '{print $2}' | sed 's/\"//g')
        if [ -z "$DISTRO" ]; then
			DISTRO=$(cat /etc/*-release | grep '^ID=' | awk -F= '{print $2}' | sed 's/\"//g')
		fi
		echo DISTRO=$DISTRO
        if [[ "$DISTRO" == "fedora" ]]; then
                yum install -y openssl-devel
                PLATFORM="fedora"
        elif [[ "$DISTRO" == "debian" ]]; then
                apt-get install -y libssl-dev
        fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
        PLATFORM="x86_64-apple-darwin"
fi

FILENAME="gibbs-mysql-spyglass-${VERSION}-${PLATFORM}.tar.gz"
curl --remote-name -fL $BASE_URL/$VERSION/$FILENAME
tar -xvf $FILENAME

echo "Spyglass is ready, type ./spyglass to run it!"
