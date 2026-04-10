## Removable Media Data Extraction

**Summary:**

Removable Media Data Extraction refers to the transfer of sensitive information from a target environment to external storage devices such as USB drives, external hard disks, or portable media. This includes copying files, exporting databases, or synchronizing data to removable storage that can be physically removed from the environment. Within MalChain, this capability begins once data is successfully written to removable media with the intent of removal from the controlled environment. Attackers exploit implicit trust in physical storage devices and routine data transfer workflows to extract information without relying on network connectivity. Routine reliance on removable media for backup, maintenance, or operational tasks often allows unauthorized data transfer to occur without immediate detection. Trust abuse may involve connecting unauthorized storage devices, copying sensitive files to portable media, or disguising data transfers as legitimate operational activity. Common extraction methods include:

* Copying files to USB or external storage devices  
* Exporting sensitive data to portable media  
* Synchronizing directories to removable drives  
* Transferring database backups to external storage  
* Using removable devices to bypass network restrictions  

Real world usage includes:

* Data theft operations in restricted or air-gapped environments  
* Insider threat scenarios involving unauthorized file copying  
* Espionage campaigns extracting sensitive information physically  
* Persistent threats bypassing network monitoring controls  

**Detection:**

Detection relies on monitoring device connection events, file transfer activity, and system behavior associated with removable storage usage. Contextual correlation between data access and device activity is essential to reduce false positives.

* Monitor connection of removable storage devices  
* Detect large or unusual file copying to external media  
* Correlate file access with device insertion events  
* Alert on data transfer to unauthorized storage devices  
* Identify rare or unauthorized removable media usage  

**KQL Detection Concepts:**

* Device connection events indicating removable media insertion  
* File copy activity associated with external storage paths  
* Data transfer patterns involving removable devices  

**YARA Detection Concepts:**

* Scripts or binaries interacting with removable storage interfaces  
* Code patterns associated with automated file copying routines  
* Executable components writing data to external media  

**Mitigation:**

* Enforce removable media usage policies and device controls  
* Monitor file transfer activity to external storage  
* Restrict use of unauthorized portable devices  
* Implement data loss prevention controls for removable media  

**Incident response:**

* Identify systems where removable media was connected  
* Secure and analyze the external storage device  
* Review file transfer logs and access history  
* Assess scope of data exposure  

**Linking:**

* Stenographic Data Transfer  
* Multi-Channel Redundant Exfiltration  
* Anti-Forensics & Cleanup
