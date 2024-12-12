#!/bin/bash

# Log file setup
COMP_NAME=$(hostname)
CURRENT_USER=$(whoami)
LOG_PATH="$HOME/update-log-$COMP_NAME-$(date +%Y-%m-%d).log"

# Function to disable weak services
disable_weak_services() {
    echo "Disabling weak services..." | tee -a "$LOG_PATH"
    systemctl disable --now telnet.service
    systemctl disable --now ftp.service
    echo "Weak services disabled." | tee -a "$LOG_PATH"
}

# Function to disable remote desktop (if applicable)
disable_remote_desktop() {
    echo "Disabling remote desktop..." | tee -a "$LOG_PATH"
    systemctl disable --now xrdp.service
    echo "Remote desktop disabled." | tee -a "$LOG_PATH"
}

# Malware scan (requires ClamAV or a similar tool)
malware_scan() {
    echo "Performing malware scan..." | tee -a "$LOG_PATH"
    clamscan -r / --log="$LOG_PATH"
    echo "Malware scan completed." | tee -a "$LOG_PATH"
}

# System integrity check
system_integrity_scan() {
    echo "Checking system integrity..." | tee -a "$LOG_PATH"
    debsums -s > "$LOG_PATH" 2>&1 || echo "Install 'debsums' to perform integrity checks." | tee -a "$LOG_PATH"
    echo "System integrity check completed." | tee -a "$LOG_PATH"
}

# Check file and folder permissions
check_permissions() {
    echo "Checking file and folder permissions..." | tee -a "$LOG_PATH"
    find / -xdev \(
        -perm -002 -o -perm -004 \) -type f -exec ls -l {} \; >> "$LOG_PATH"
    echo "Permissions check completed." | tee -a "$LOG_PATH"
}

# Apply security settings
apply_security_settings() {
    echo "Applying security settings..." | tee -a "$LOG_PATH"

    # Password policies
    echo "Setting password policies..." | tee -a "$LOG_PATH"
    echo "PASS_MAX_DAYS   90" >> /etc/login.defs
    echo "PASS_MIN_DAYS   5" >> /etc/login.defs
    echo "PASS_MIN_LEN    8" >> /etc/login.defs
    echo "PASS_WARN_AGE   7" >> /etc/login.defs

    # Lockout policy (requires PAM modifications)
    echo "Editing PAM configurations for lockout policies..." | tee -a "$LOG_PATH"
    echo "auth required pam_tally2.so onerr=fail deny=5 unlock_time=900" >> /etc/pam.d/common-auth

    # Auditing policies
    echo "Setting auditing policies..." | tee -a "$LOG_PATH"
    apt-get install -y auditd
    systemctl enable --now auditd.service
    auditctl -e 1

    echo "Security settings applied." | tee -a "$LOG_PATH"
}

# Execute functions
disable_weak_services
disable_remote_desktop
malware_scan
system_integrity_scan
check_permissions
apply_security_settings

# Final log message
echo "System security configuration completed." | tee -a "$LOG_PATH"





# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! PART 2 REWRITTEN: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!/bin/bash

# Log file setup
COMP_NAME=$(hostname)
CURRENT_USER=$(whoami)
LOG_PATH="$HOME/update-log-$COMP_NAME-$(date +%Y-%m-%d).log"

# Function to disable weak services
disable_weak_services() {
    echo "Disabling weak services..." | tee -a "$LOG_PATH"
    systemctl disable --now telnet.service
    systemctl disable --now ftp.service
    echo "Weak services disabled." | tee -a "$LOG_PATH"
}

# Function to disable remote desktop (if applicable)
disable_remote_desktop() {
    echo "Disabling remote desktop..." | tee -a "$LOG_PATH"
    systemctl disable --now xrdp.service
    echo "Remote desktop disabled." | tee -a "$LOG_PATH"
}

# Configure security policies
configure_security_policies() {
    echo "Configuring security policies..." | tee -a "$LOG_PATH"

    # Password policies
    echo "Setting password policies..." | tee -a "$LOG_PATH"
    echo "PASS_MAX_DAYS   90" >> /etc/login.defs
    echo "PASS_MIN_DAYS   5" >> /etc/login.defs
    echo "PASS_MIN_LEN    8" >> /etc/login.defs
    echo "PASS_WARN_AGE   7" >> /etc/login.defs

    # PAM lockout policy
    echo "Editing PAM configurations for lockout policies..." | tee -a "$LOG_PATH"
    echo "auth required pam_tally2.so onerr=fail deny=5 unlock_time=900" >> /etc/pam.d/common-auth

    # Disable root login over SSH
    echo "Disabling root login over SSH..." | tee -a "$LOG_PATH"
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd

    echo "Security policies configured." | tee -a "$LOG_PATH"
}

# Enable and configure the firewall
enable_firewall() {
    echo "Enabling firewall..." | tee -a "$LOG_PATH"
    ufw enable
    ufw default deny incoming
    ufw default allow outgoing
    echo "Firewall enabled and configured." | tee -a "$LOG_PATH"
}

# Perform updates and install security patches
update_system() {
    echo "Updating system and installing security patches..." | tee -a "$LOG_PATH"
    apt-get update && apt-get upgrade -y
    echo "System updated." | tee -a "$LOG_PATH"
}

# Disable unused features and services
disable_unused_features() {
    echo "Disabling unused features and services..." | tee -a "$LOG_PATH"

    # Disable Telnet client
    echo "Disabling Telnet client..." | tee -a "$LOG_PATH"
    apt-get remove --purge -y telnet

    # Disable Remote Assistance features
    echo "Disabling Remote Assistance..." | tee -a "$LOG_PATH"
    systemctl disable --now remote-fs.target

    echo "Unused features and services disabled." | tee -a "$LOG_PATH"
}

# Execute functions
disable_weak_services
disable_remote_desktop
configure_security_policies
enable_firewall
update_system
disable_unused_features

# Final log message
echo "System security configuration completed." | tee -a "$LOG_PATH"

