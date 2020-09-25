### getTenantExportToOCI.py

Script to connect to an Cisco ACI APIC, download a Tenant and export information
to OCI and Terraform data structures.

Cleaning rules, adaptations, warning and error messages.

Check the video at https://youtu.be/aHDO0EOuCHs


### getTenantExportEpgSecurity.py
Script to connect to an Cisco ACI APIC, download a Tenant and export information:

1.- to screen AEPg, EPG, provider/consumer, contract

2.- to screen Contract, Subject, Filter, Filter Name, ports, etc

3.- export to excel format the full combination of: AEPg, EPG, provider/consumer, contract, subject, filter and filter name, ports, etc
 

### aci_to_chat.py
Script to send ACI faults and events to Slack or WebEx Teams.


### duplicateTenant.py
Connect to APIC and duplicate a tenant.


### Directories
Modules: contains reusable modules for OCI and ACI

Data: contains the data to be uses with the scripts

Check custom variables at the beginning of the scripts
