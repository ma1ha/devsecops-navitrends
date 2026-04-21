FROM ubuntu:22.04
 
ARG WAZUH_VERSION=4.14.4
 
ENV DEBIAN_FRONTEND=noninteractive
 
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    apt-transport-https \
    lsb-release \
    ca-certificates \
    jq \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*
 
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
 
RUN apt-get update && \
    apt-get install -y wazuh-agent=${WAZUH_VERSION}-1 && \
    rm -rf /var/lib/apt/lists/*
 
COPY agent-config/ossec.conf /var/ossec/etc/ossec.conf
RUN chown root:wazuh /var/ossec/etc/ossec.conf && chmod 640 /var/ossec/etc/ossec.conf
 
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
 
ENTRYPOINT ["/entrypoint.sh"]
 