/*
 * Copyright 2014 Unicon, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.unicon.cas.support.wsfederation.web.flow;

import net.unicon.cas.addons.serviceregistry.RegisteredServiceWithAttributes;
import net.unicon.cas.support.wsfederation.WsFederationConfiguration;
import net.unicon.cas.support.wsfederation.WsFederationUtils;
import net.unicon.cas.support.wsfederation.authentication.principal.WsFederationCredential;
import net.unicon.cas.support.wsfederation.authentication.principal.WsFederationCredentials;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.web.support.WebUtils;
import org.opensaml.saml1.core.impl.AssertionImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotNull;

/**
 * This class represents an action in the webflow to retrieve WsFederation information on the callback url which is
 * the webflow url (/login).
 *
 * @author John Gasper
 * @since 3.5.2
 */
public final class WsFederationAction extends AbstractAction {

    private static final String LOCALE = "locale";
    private static final String METHOD = "method";
    private static final String PROVIDERURL = "WsFederationIdentityProviderUrl";
    private static final String QUERYSTRING = "?wa=wsignin1.0&wtrealm=";
    private static final String SERVICE = "service";
    private static final String THEME = "theme";
    private static final String WA = "wa";
    private static final String WCTX = "wctx";
    private static final String WRESULT = "wresult";
    private static final String WSIGNIN = "wsignin1.0";
    private final Logger logger = LoggerFactory.getLogger(WsFederationAction.class);
    @NotNull
    private WsFederationConfiguration configuration;

    @NotNull
    private CentralAuthenticationService centralAuthenticationService;

    private ServicesManager servicesManager;

    /**
     * Executes the webflow action.
     *
     * @param context the context
     * @return the event
     * @throws Exception all unhandled exceptions
     */
    @Override
    protected Event doExecute(final RequestContext context) throws Exception {

        try {
            final HttpServletRequest request = WebUtils.getHttpServletRequest(context);
            final HttpSession session = request.getSession();

            final String wa = request.getParameter(WA);

            // it's an authentication
            if (StringUtils.isNotBlank(wa) && wa.equalsIgnoreCase(WSIGNIN)) {
                final String wresult = request.getParameter(WRESULT);
                logger.debug("wresult : {}", wresult);

                final String wctx = request.getParameter(WCTX);
                logger.debug("wctx : {}", wctx);

                // create credentials
                final AssertionImpl assertion = WsFederationUtils.parseTokenFromString(wresult);

                //Validate the signature
                if (assertion != null && WsFederationUtils.validateSignature(assertion, configuration.getSigningCertificates())) {
                    final WsFederationCredential credential = WsFederationUtils.createCredentialFromToken(assertion);

                    final Credentials credentials;
                    final Service service = (Service) session.getAttribute(SERVICE);
                    if (credential != null && credential.isValid(getRelyingPartyIdentifier(service),
                            configuration.getIdentityProviderIdentifier(),
                            configuration.getTolerance())) {

                        //Give the library user a chance to change the attributes as necessary
                        if (configuration.getAttributeMutator() != null) {
                            configuration.getAttributeMutator().modifyAttributes(credential.getAttributes());
                        }

                        credentials = new WsFederationCredentials(credential);

                    } else {
                        logger.warn("SAML assertions are blank or no longer valid.");
                        return error();
                    }

                    // retrieve parameters from web session
                    try {
                        context.getFlowScope().put(SERVICE, service);
                        restoreRequestAttribute(request, session, THEME);
                        restoreRequestAttribute(request, session, LOCALE);
                        restoreRequestAttribute(request, session, METHOD);

                    } catch (final Exception ex) {
                        logger.warn("Session is most-likely empty: {}", ex.getMessage());
                    }


                    try {
                        WebUtils.putTicketGrantingTicketInRequestScope(context, this.centralAuthenticationService
                                .createTicketGrantingTicket(credentials));

                        logger.info("Token validated and new WsFederationCredcredentials created: {}", credentials.toString());
                        return success();

                    } catch (final TicketException e) {
                        logger.error(e.getMessage());
                        return error();
                    }

                } else {
                    logger.error("WS Requested Security Token is blank or the signature is not valid.");
                    return error();
                }

            } else { // no authentication : go to login page
                logger.debug("Preparing to redirect to the IdP");

                // save parameters in web session
                final Service service = (Service) context.getFlowScope().get(SERVICE);
                if (service != null) {
                    session.setAttribute(SERVICE, service);
                }
                saveRequestParameter(request, session, THEME);
                saveRequestParameter(request, session, LOCALE);
                saveRequestParameter(request, session, METHOD);

                final String relyingPartyIdentifier = this.getRelyingPartyIdentifier(service);

                final String key = PROVIDERURL;
                final String authorizationUrl = this.configuration.getIdentityProviderUrl()
                        + QUERYSTRING
                        + relyingPartyIdentifier;

                logger.debug("{} -> {}", key, authorizationUrl);
                context.getFlowScope().put(key, authorizationUrl);
            }

            logger.debug("Redirecting to the IdP");
            return error();

        } catch (final Exception ex) {
            logger.error(ex.getMessage());
            return error();
        }

    }

    /**
     * Get the relying party id for a service.
     *
     * @param service the service to get an id for
     * @return relying party id
     */
    private String getRelyingPartyIdentifier(final Service service) {
        String relyingPartyIdentifier = this.configuration.getRelyingPartyIdentifier();
        if (service != null) {
            final RegisteredService registeredService = this.servicesManager.findServiceBy(service);
            if (registeredService instanceof RegisteredServiceWithAttributes
                    && ((RegisteredServiceWithAttributes) registeredService).
                    getExtraAttributes().containsKey("wsfed.relyingPartyId")) {
                relyingPartyIdentifier = ((RegisteredServiceWithAttributes) registeredService).
                        getExtraAttributes().get("wsfed.relyingPartyId").toString();
            }
        }
        return relyingPartyIdentifier;
    }

    /**
     * Restore an attribute in web session as an attribute in request.
     *
     * @param request the request
     * @param session the session
     * @param name    the attribute name
     */
    private void restoreRequestAttribute(final HttpServletRequest request, final HttpSession session, final String name) {
        final String value = (String) session.getAttribute(name);
        request.setAttribute(name, value);
    }

    /**
     * Save a request parameter in the web session.
     *
     * @param request the request
     * @param session the session
     * @param name    the attribute name
     */
    private void saveRequestParameter(final HttpServletRequest request, final HttpSession session, final String name) {
        final String value = request.getParameter(name);
        if (value != null) {
            session.setAttribute(name, value);
        }
    }

    /**
     * set the CAS config.
     *
     * @param centralAuthenticationService the cas config
     */
    public void setCentralAuthenticationService(final CentralAuthenticationService centralAuthenticationService) {
        this.centralAuthenticationService = centralAuthenticationService;
    }

    /**
     * sets the WsFederation configuration.
     *
     * @param configuration the configuration
     */
    public void setConfiguration(final WsFederationConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * set the services Manager.
     *
     * @param servicesManager the services manager
     */
    public void setServicesManager(final ServicesManager servicesManager) {
        this.servicesManager = servicesManager;
    }
}
