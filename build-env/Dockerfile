FROM saschpe/android-ndk:35-jdk23.0.2_7-ndk28.0.13004108-cmake3.31.5

USER root

RUN apt-get update && \
	apt-get -y install libtool autoconf automake make python3 --no-install-recommends

ENV ANDROID_NDK_HOME=/opt/android-sdk-linux/ndk/28.0.13004108

USER nonroot
