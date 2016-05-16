#!/usr/bin/env bash
set -e
BASE_URL="https://github.com/AgilData/gibbs-mysql-spyglass/releases/download"
VERSION=$(curl -s https://api.github.com/repos/AgilData/gibbs-mysql-spyglass/releases | grep -Po -m1 'tag_name\": \"\Kv[0-9]*\.[0-9*]\.[0-9]*')

if [[ "$OSTYPE" == "linux-gnu" ]]; then
        PLATFORM="x86_64-unknown-linux-musl"
		FILENAME="gibbs-mysql-spyglass-${VERSION}-${PLATFORM}.tar.gz"
		echo "Downloading $BASE_URL/$VERSION/$FILENAME"
		curl -s --remote-name -fL $BASE_URL/$VERSION/$FILENAME
		tar -xf $FILENAME
		echo "Spyglass is ready, type ./spyglass to run it!"
elif [[ "$OSTYPE" == "darwin"* ]]; then
        PLATFORM="x86_64-apple-darwin"
        echo "Looks like you're running on a mac? Spyglass is only meant to run on linux servers. If you're a developer, please build from source: https://github.com/AgilData/gibbs-mysql-spyglass"
fi

