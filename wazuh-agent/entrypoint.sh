MANAGER="${WAZUH_MANAGER_IP:-172.27.0.3}"
AGENT_NAME="${WAZUH_AGENT_NAME:-navitrends-docker-agent}"
REG_PASS="${WAZUH_REGISTRATION_PASS:-}"
 
echo "[wazuh-agent] Manager  : ${MANAGER}"
echo "[wazuh-agent] Agent    : ${AGENT_NAME}"
 
sed -i "s|WAZUH_MANAGER_PLACEHOLDER|${MANAGER}|g" /var/ossec/etc/ossec.conf
 
echo "[wazuh-agent] Registering with manager..."
if [ -n "${REG_PASS}" ]; then
  /var/ossec/bin/agent-auth -m "${MANAGER}" -A "${AGENT_NAME}" -P "${REG_PASS}" || \
    echo "[wazuh-agent] Registration failed or agent already exists, continuing..."
else
  /var/ossec/bin/agent-auth -m "${MANAGER}" -A "${AGENT_NAME}" || \
    echo "[wazuh-agent] Registration failed or agent already exists, continuing..."
fi
 
echo "[wazuh-agent] Starting wazuh-agentd..."
/var/ossec/bin/wazuh-control start
 
echo "[wazuh-agent] Agent running. Tailing logs..."
tail -f /var/ossec/logs/ossec.log
 