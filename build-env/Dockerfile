FROM saschpe/android-ndk:35-jdk23.0.2_7-ndk28.0.13004108-cmake3.31.5

USER root

# the first line from libtool to python3 contains packages required for building native libs
#
# the second line with pkgconf and libsodium-dev contains packages that are not strictly
# required, yet make things easier given the current state of the liboprf makefile

RUN apt-get update && apt-get -y install \
		libtool autoconf automake make python3 \
		pkgconf libsodium-dev \
		--no-install-recommends

ENV ANDROID_NDK_HOME=/opt/android-sdk-linux/ndk/28.0.13004108

USER nonroot
