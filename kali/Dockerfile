FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Preinstall tools used by this lab's attack scripts so we don't reinstall each run.
# Keep it minimal and reproducible.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    nmap \
    hping3 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

CMD ["tail","-f","/dev/null"]
