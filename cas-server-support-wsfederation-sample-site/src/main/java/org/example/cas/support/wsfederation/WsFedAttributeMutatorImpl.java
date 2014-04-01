package org.example.cas.support.wsfederation;

import java.util.Map;
import net.unicon.cas.support.wsfederation.WsFederationAttributeMutator;
import net.unicon.cas.support.wsfederation.WsFederationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * This will remove the @example.org from the upn local accounts. Other IdP should
 * have the upn un-altered to prevent users collusions in CAS-based applications.
 * 
 * @author jgasper
 * @since 3.5.1
 */
public class WsFedAttributeMutatorImpl implements WsFederationAttributeMutator {
    private static final Logger logger = LoggerFactory.getLogger(WsFedAttributeMutatorImpl.class);

    @Override
    public void modifyAttributes(Map<String, Object> attributes) {
        if ( attributes.containsKey("upn") ) {
            attributes.put("upn", attributes.get("upn").toString().replace("@example.org", ""));
            logger.debug(String.format("modifyAttributes: upn modified (%s)", attributes.get("upn").toString()));
        }
        else {
            logger.warn("modifyAttributes: upn attribute not found");
        }
        
        attributeMapping(attributes, "surname", "LastName");
        attributeMapping(attributes, "givenname", "FirstName");
        attributeMapping(attributes, "Group", "Groups");
        attributeMapping(attributes, "employeeNumber", "UDC_IDENTIFIER");
    }

    private void attributeMapping(Map<String, Object> attributes, String oldName, String newName) {
        if ( attributes.containsKey(oldName) ) {
            logger.debug(String.format("attributeRemapping: %s -> %s (%s)", oldName, newName, attributes.get(oldName)));
            attributes.put(newName, attributes.get(oldName));
            attributes.remove(oldName);
        }
        else { 
            logger.debug(String.format("attributeRemapping: attribute not found (%s)", oldName));
        }
    }
    
}
