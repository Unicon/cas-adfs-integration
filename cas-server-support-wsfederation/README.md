#Overview
This project is a super project documenting multiple ways to integrate Apereo/Jasig CAS Server and Microsoft's ADFS.## cas-server-support-wsfederationThis method of integrating CAS Server and ADFS delegates user authentication from CAS Server to ADFS. This is accomplished by making CAS Server a WS-Federation client. Claims released from ADFS are made available as attributes to CAS Server, and by extension CAS Clients.## ADFS CASificationThis method of integrating CAS Server and ADFS delegates user authentication from ADFS to CAS server by CASifying ADFS. This method requires that the CAS Server supports the ClearPass protocol.
The cas-server-support-wsfederation module provides integration support for Microsoft's Active Directory Federation
Services v2.0 (and potentially other WS-Federation based IdPs) with CAS Server.

## Documentation
See the documentation at: https://github.com/Unicon/cas-adfs-integration/wiki


## Versioning
Version 1.0.0 works with CAS Server versions 3.5.1 through current (3.5.2.1).

