## User-Executed Files

**Summary:**

User-Executed Files refers to the execution of attacker-controlled content initiated directly by a user action within a target environment. This includes opening attachments, launching downloaded files, running shared utilities, or executing documents containing embedded code. Within MalChain, this capability begins once delivered content is intentionally or unintentionally executed by a user. Attackers exploit implicit trust in familiar file formats and routine operational workflows. Curiosity, urgency, and perceived legitimacy often override security warnings or established procedures. Trust abuse may involve renamed executables, document icons, or files presented as required tools or updates. Common execution methods include:

* Opening email attachments
* Launching downloaded files
* Running shared utilities or installers
* Executing files from network locations
* Double-clicking disguised executable files

Real world usage includes:

* Phishing and spear-phishing campaigns
* Initial malware deployment in enterprise environments
* Business email compromise operations
* Commodity malware infections through user interaction

**Detection:**

Detection relies on monitoring process creation events, user interaction telemetry, and execution patterns associated with newly introduced files. Contextual correlation between file origin and execution behavior is essential to reduce false positives.

* Monitor process launches initiated by user sessions
* Detect execution of files from temporary or download locations
* Correlate email attachment access with process execution
* Alert on execution of files with uncommon extensions
* Identify rare or newly introduced applications executed by users

**KQL Detection Concepts:**

* Process execution events initiated by user context
* Executable launches from Downloads or Temp directories
* File execution immediately following email attachment access

**YARA Detection Concepts:**

* Suspicious executable headers or embedded payload indicators
* Document files containing macro or script logic
* Files with mismatched file extension and content type

**Mitigation:**

* Implement application control and execution policies
* Restrict execution from user-writable directories
* Enforce attachment and download scanning controls
* Educate users on recognizing suspicious files

**Incident response:**

* Identify the executed file and associated processes
* Isolate affected systems from the network
* Collect and analyze execution artifacts
* Review user activity and execution timeline

**Linking:**

* Script-Based Activation
* DLL Side-Loading
* Startup & Logon Execution
