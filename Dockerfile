FROM p4lang/p4app:latest

# Install additional tools

RUN set -x; \
  apt-get update && \
  apt-get install -qy \
    tcpreplay \
    ethtool \
    libpcap-dev \
    bison \
    flex \
    snort \
    curl \
    && \
    curl -sLO http://archive.ubuntu.com/ubuntu/pool/universe/c/cpulimit/cpulimit_2.5-1_amd64.deb && sudo dpkg -i cpulimit_2.5-1_amd64.deb \
    && \
  apt-get remove -qy \
    mawk \
    && \
  apt-get clean && \
  : ;

