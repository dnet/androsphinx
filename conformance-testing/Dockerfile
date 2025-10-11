FROM python:3.14.0-alpine3.22

RUN apk add build-base libsodium-dev git openssl-dev

WORKDIR /app

RUN git clone https://github.com/stef/liboprf && (cd liboprf/src && make -j4 && make install)
RUN git clone https://github.com/stef/equihash && (cd equihash && make -j4 && make install)
RUN pip3 install pwdsphinx

COPY oracle-config.toml /etc/sphinx/config

EXPOSE 2355

CMD ["oracle"]
