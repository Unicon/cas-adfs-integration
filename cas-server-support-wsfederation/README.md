#Overview
The cas-server-support-wsfederation module provides integration support for Microsoft's Active Directory Federation
Services v2.0 (and potentially other WS-Federation based IdPs) with CAS Server.

See documentation at : https://github.com/Unicon/cas-adfs-integration/wiki

#Versioning
Version 1.0.0 works with CAS Server versions 3.5.1 through current (3.5.2).

# Configurable Relying Party ID

In previous versions, you would set a global relying party identifier for the system, such as in your properties file.
This ID would be used for all services. Later versions, though, allow configuration of this ID per CAS service. If you
use a service registry that supports `RegisteredServiceWithAttributes`, such as the JSON service registry from Unicon,
you can add an extra attribute called `wsfed.relyingPartyId` to be used for that service

For Example:

```
{
    "services":[
         {
             "id": 2,
             "serviceId": "https://**",
             "name": "EVERY HTTPS",
             "description": "allow all https",
             "extraAttributes": {
                "wsfed.relyingPartyId": "urn:federation:cas-mfa"
             }
         }
    ]
}
```
