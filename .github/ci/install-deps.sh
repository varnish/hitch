#!/bin/sh
# Install hitch build and test dependencies inside a CI container.

set -eux

if apt-get -v >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	export DEBCONF_NONINTERACTIVE_SEEN=true
	apt-get update
	apt-get install -y --no-install-recommends \
		autoconf \
		automake \
		bison \
		ca-certificates \
		curl \
		flex \
		gcc \
		libc6-dev \
		libev-dev \
		libssl-dev \
		lsof \
		make \
		openssl \
		pkg-config \
		python3-docutils
elif pacman -V >/dev/null 2>&1; then
	pacman -Syu --noconfirm --needed \
		base-devel \
		curl \
		libev \
		lsof \
		openssl \
		python-docutils
else
	. /etc/os-release
	case "${PLATFORM_ID:-}" in
	platform:el*)
		dnf install -y epel-release 'dnf-command(config-manager)'
		dnf config-manager --set-enabled crb
		;;
	esac
	# curl itself is left out: the images ship curl-minimal, which
	# conflicts with the full curl package but provides the binary.
	dnf install -y \
		autoconf \
		automake \
		bison \
		findutils \
		flex \
		gcc \
		libev-devel \
		lsof \
		make \
		openssl \
		openssl-devel \
		pkgconf-pkg-config \
		python3-docutils
fi
