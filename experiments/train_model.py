import json
import os
from features.feature_engineering import extract_features
from anomaly.anomaly_score import train

raw_folder = "/home/eyerin/projects/ai-nids/data/raw"
features_list = []

#loads fake jsons, extracts features
for file_name in os.listdir(raw_folder):
    if file_name.endswith(".json"):
        file_path = os.path.join(raw_folder, file_name)
        with open(file_path) as f:
            raw = json.load(f)
        features = extract_features(raw)
        features_list.append(features)

#trains isolationforest
train(features_list)
print(f"Isolation Forest trained on {len(features_list)} samples and model saved.")

eyerin@eyerin-vb:~$ which auditd

/usr/sbin/auditd

eyerin@eyerin-vb:~$ systemctl status auditd

● auditd.service - Security Auditing Service

     Loaded: loaded (/usr/lib/systemd/system/auditd.service; enabled; preset: e>

     Active: active (running) since Fri 2026-02-06 17:36:22 IST; 7min ago

       Docs: man:auditd(8)

             https://github.com/linux-audit/audit-documentation

    Process: 15493 ExecStart=/sbin/auditd (code=exited, status=0/SUCCESS)

    Process: 15497 ExecStartPost=/sbin/augenrules --load (code=exited, status=0>

   Main PID: 15494 (auditd)

      Tasks: 2 (limit: 9432)

     Memory: 480.0K (peak: 2.6M)

        CPU: 33ms

     CGroup: /system.slice/auditd.service

             └─15494 /sbin/auditd

Feb 06 17:36:22 eyerin-vb augenrules[15508]: enabled 1

Feb 06 17:36:22 eyerin-vb augenrules[15508]: failure 1

Feb 06 17:36:22 eyerin-vb augenrules[15508]: pid 15494

Feb 06 17:36:22 eyerin-vb augenrules[15508]: rate_limit 0

Feb 06 17:36:22 eyerin-vb augenrules[15508]: backlog_limit 8192

Feb 06 17:36:22 eyerin-vb augenrules[15508]: lost 0

Feb 06 17:36:22 eyerin-vb augenrules[15508]: backlog 8

Feb 06 17:36:22 eyerin-vb augenrules[15508]: backlog_wait_time 60000

Feb 06 17:36:22 eyerin-vb augenrules[15508]: backlog_wait_time_actual 0

eyerin@eyerin-vb:~$ sudo systemctl start auditd

[sudo] password for eyerin: 

eyerin@eyerin-vb:~$ sudo systemctl enable auditd

Synchronizing state of auditd.service with SysV service script with /usr/lib/systemd/systemd-sysv-install.

Executing: /usr/lib/systemd/systemd-sysv-install enable auditd

eyerin@eyerin-vb:~$ systemctl status auditd

● auditd.service - Security Auditing Service

     Loaded: loaded (/usr/lib/systemd/system/auditd.service; enabled; preset: e>

     Active: active (running) since Fri 2026-02-06 17:36:22 IST; 9min ago

       Docs: man:auditd(8)

             https://github.com/linux-audit/audit-documentation

   Main PID: 15494 (auditd)

      Tasks: 2 (limit: 9432)

     Memory: 496.0K (peak: 2.6M)

        CPU: 36ms

     CGroup: /system.slice/auditd.service

             └─15494 /sbin/auditd

Feb 06 17:36:22 eyerin-vb augenrules[15508]: enabled 1

Feb 06 17:36:22 eyerin-vb augenrules[15508]: failure 1

Feb 06 17:36:22 eyerin-vb augenrules[15508]: pid 15494

Feb 06 17:36:22 eyerin-vb augenrules[15508]: rate_limit 0

Feb 06 17:36:22 eyerin-vb augenrules[15508]: backlog_limit 8192

Feb 06 17:36:22 eyerin-vb augenrules[15508]: lost 0

Feb 06 17:36:22 eyerin-vb augenrules[15508]: backlog 8

Feb 06 17:36:22 eyerin-vb augenrules[15508]: backlog_wait_time 60000

Feb 06 17:36:22 eyerin-vb augenrules[15508]: backlog_wait_time_actual 0

Feb 06 17:36:22 eyerin-vb systemd[1]: Started auditd.service - Security Auditin>

lines 1-22/22 (END) 
