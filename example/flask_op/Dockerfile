FROM debian:stable-slim

MAINTAINER Roland Hedberg "roland@catalogix.se"

COPY . /app
ENV SRCDIR /app/src

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    libssl-dev \
    libffi-dev \
    python3-pip \
    python3-setuptools && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/rohe/oidc-op.git ${SRCDIR}/oidc-op
WORKDIR ${SRCDIR}/oidc-op
RUN python3 setup.py install

RUN pip3 install ndg-httpsclient

WORKDIR /app
RUN pip3 install -r requirements.txt
EXPOSE 5000
CMD python3 ./server.py config.yaml
