# Zeek with the zeek-tds package, for running the TDS notebook's analysis.
# Build once:  docker build -t zeek-tds:0.2.0 "TDS Analysis/zeek"
FROM zeek/zeek:8.2.2
ARG ZEEK_TDS_VERSION=v0.2.0
RUN apt-get update -q \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends g++ cmake make git libpcap-dev libssl-dev \
 && zkg autoconfig --force \
 && zkg install --force --skiptests --version "${ZEEK_TDS_VERSION}" https://github.com/dgunter/zeek-tds \
 && apt-get purge -y -q g++ cmake make && apt-get autoremove -y -q && rm -rf /var/lib/apt/lists/*
WORKDIR /data
ENTRYPOINT ["zeek", "-C", "packages", "LogAscii::use_json=F"]
