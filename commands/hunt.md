---
description: "Quick IOC hunt — search for an indicator across all Wazuh data and report findings"
argument-hint: "[IOC value to hunt for]"
---

Search for the provided IOC across all Wazuh SIEM data using the wazuh-ioc-hunter MCP tools. Auto-detect the IOC type and search with both the default 2h attack window and expanded 48h window for delayed syscheck detections. Report what you find with affected hosts, timestamps, hashes, and MITRE ATT&CK context. If found, automatically pivot to related indicators.
