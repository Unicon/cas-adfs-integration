cas-adfs-integration [![Build Status](https://travis-ci.org/Unicon/cas-adfs-integration.svg?branch=master)](https://travis-ci.org/Unicon/cas-adfs-integration) [ ![Codeship Status for jtgasper3/cas-adfs-integration](https://www.codeship.io/projects/78679d20-ee7e-0131-30df-429ee894f4d5/status)](https://www.codeship.io/projects/26865)
====================

> This project was developed as part of Unicon's [Open Source Support program](https://unicon.net/support). Professional support/integration assistance for this module is available. For more information, visit <https://unicon.net/opensource/cas>. 

#Overview
This project is a super project documenting multiple ways to integrate Apereo/Jasig CAS Server and Microsoft's ADFS.

## cas-server-support-wsfederation
This method of integrating CAS Server and ADFS delegates user authentication from CAS Server to ADFS. This is accomplished by making CAS Server a WS-Federation client. Claims released from ADFS are made available as attributes to CAS Server, and by extension CAS Clients.

## ADFS CASification
This method of integrating CAS Server and ADFS delegates user authentication from ADFS to CAS server by CASifying ADFS. This method requires that the CAS Server supports the ClearPass protocol.
The cas-server-support-wsfederation module provides integration support for Microsoft's Active Directory Federation
Services v2.0 - v3.0 (and potentially other WS-Federation based IdPs) with CAS Server.

## Documentation
See the documentation at: https://github.com/Unicon/cas-adfs-integration/wiki


## Versioning
Version 1.0.0 has been verified that it works with CAS Server versions 3.5.1 through 3.5.2.1.

Version 1.0.1 has been verified that it works with CAS Server versions 4.0.x.
