package net.unicon.cas.addons.serviceregistry;

import org.jasig.cas.services.RegisteredService;

import java.util.Map;

/**
 * An extention to <code>RegisteredService</code> with extra arbitrary attributes.
 *
 * @author CAS Addons
 * @since 1.0.2
 */
public interface RegisteredServiceWithAttributes extends RegisteredService {
    /**
     * Extra attributes on the service.
     *
     * @return extraAttributes
     */
    Map<String, Object> getExtraAttributes();
}
