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

package net.unicon.cas.support.wsfederation;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.unicon.cas.support.wsfederation.authentication.principal.WsFederationCredential;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.saml1.core.Assertion;
import org.opensaml.saml.saml1.core.Attribute;
import org.opensaml.saml.saml1.core.Conditions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.soap.wsfed.RequestSecurityTokenResponse;
import org.opensaml.soap.wsfed.RequestedSecurityToken;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Helper class that does the heavy lifting with the openSaml library.
 *
 * @author John Gasper
 * @since 3.5.2
 */
public final class WsFederationUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(WsFederationUtils.class);

    static {
        Configuration.bootstrap();
        Assert.notNull(Configuration.getParserPool(), "parserPool cannot be null");
        Assert.notNull(Configuration.getMarshallerFactory(), "marshallerFactory cannot be null");
        Assert.notNull(Configuration.getUnmarshallerFactory(), "unmarshallerFactory cannot be null");
        Assert.notNull(Configuration.getBuilderFactory(), "builderFactory cannot be null");
    }

    /**
     * private constructor.
     */
    private WsFederationUtils() {
    }

    /**
     * createCredentialFromToken converts a SAML 1.1 assertion to a WSFederationCredential.
     *
     * @param assertion the provided assertion
     * @return an equivalent credential.
     */
    public static WsFederationCredential createCredentialFromToken(final Assertion assertion) {
        final DateTime retrievedOn = new DateTime().withZone(DateTimeZone.UTC);
        LOGGER.debug("createCredentialFromToken: retrieved on {}", retrievedOn);

        final WsFederationCredential credential = new WsFederationCredential();
        credential.setRetrievedOn(retrievedOn);
        credential.setId(assertion.getID());
        credential.setIssuer(assertion.getIssuer());
        credential.setIssuedOn(assertion.getIssueInstant());

        final Conditions conditions = assertion.getConditions();
        if (conditions != null) {
            credential.setNotBefore(conditions.getNotBefore());
            credential.setNotOnOrAfter(conditions.getNotOnOrAfter());
            credential.setAudience(conditions.getAudienceRestrictionConditions().get(0).getAudiences().get(0).getUri());
        }

        if (!assertion.getAuthenticationStatements().isEmpty()) {
            credential.setAuthenticationMethod(assertion.getAuthenticationStatements().get(0).getAuthenticationMethod());
        }

        //retrieve an attributes from the assertion
        final HashMap<String, Object> attributes = new HashMap<String, Object>();
        for (final Attribute item : assertion.getAttributeStatements().get(0).getAttributes()) {
            LOGGER.debug("createCredentialFromToken: processed attribute: {}", item.getAttributeName());

            if (item.getAttributeValues().size() == 1) {
                attributes.put(item.getAttributeName(), ((XSAny) item.getAttributeValues().get(0)).getTextContent());
            } else {
                final List<String> itemList = new ArrayList<String>();
                for (int i = 0; i < item.getAttributeValues().size(); i++) {
                    itemList.add(((XSAny) item.getAttributeValues().get(i)).getTextContent());
                }

                if (!itemList.isEmpty()) {
                    attributes.put(item.getAttributeName(), itemList);
                }
            }
        }
        credential.setAttributes(attributes);
        LOGGER.debug("createCredentialFromToken: {}", credential);
        return credential;
    }

    /**
     * getSigningCredential loads up an X509Credential from a file.
     *
     * @param resource the signing certificate file
     * @return an X509 credential
     */
    public static Credential getSigningCredential(final Resource resource) {
        try (final InputStream inputStream = resource.getInputStream()) {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            final Credential publicCredential = new BasicX509Credential(certificate);
            LOGGER.debug("getSigningCredential: key retrieved.");
            return publicCredential;
        } catch (final Exception ex) {
            LOGGER.error("I/O error retrieving the signing cert: {}", ex);
            return null;
        }
    }

    /**
     * parseTokenFromString converts a raw wresult and extracts it into an assertion.
     *
     * @param wresult the raw token returned by the IdP
     * @return an assertion
     */
    public static Assertion parseTokenFromString(final String wresult) {
        try (final InputStream in = new ByteArrayInputStream(wresult.getBytes("UTF-8"))) {

            final Document document = Configuration.getParserPool().parse(in);
            final Element metadataRoot = document.getDocumentElement();
            final UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            final Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
            if (unmarshaller == null) {
                throw new IllegalArgumentException("Unmarshaller for the metadata root element cannot be determined");
            }

            final RequestSecurityTokenResponse rsToken = (RequestSecurityTokenResponse) unmarshaller.unmarshall(metadataRoot);

            //Get our SAML token
            final List<RequestedSecurityToken> rst = rsToken.getRequestedSecurityToken();
            final Assertion assertion = (Assertion) rst.get(0).getSecurityTokens().get(0);

            if (assertion == null) {
                LOGGER.debug("parseTokenFromString: assertion null");
            } else {
                LOGGER.debug("parseTokenFromString: {}", assertion);
            }
            return assertion;
        } catch (final Exception ex) {
            LOGGER.warn(ex.getMessage());
            return null;
        }
    }

    /**
     * validateSignature checks to see if the signature on an assertion is valid.
     *
     * @param assertion a provided assertion
     * @param wsFederationConfiguration WS-Fed configuration provided.
     * @return true if the assertion's signature is valid, otherwise false
     */
    public static boolean validateSignature(final Assertion assertion,
                                            final WsFederationConfiguration wsFederationConfiguration) {

        if (assertion == null) {
            LOGGER.warn("No assertion was provided to validate signatures");
            return false;
        }

        boolean valid = false;
        if (assertion.getSignature() != null) {
            final SignaturePrevalidator validator = new SAMLSignatureProfileValidator();
            try {
                validator.validate(assertion.getSignature());

                final CriteriaSet criteriaSet = new CriteriaSet();
                criteriaSet.add(new UsageCriterion(UsageType.SIGNING));
                criteriaSet.add(new EntityRoleCriterion(IDPSSODescriptor.DEFAULT_ELEMENT_NAME));
                criteriaSet.add(new ProtocolCriterion(SAMLConstants.SAML20P_NS));
                criteriaSet.add(new EntityIdCriterion(wsFederationConfiguration.getIdentityProviderIdentifier()));

                try {
                    final SignatureTrustEngine engine = buildSignatureTrustEngine(wsFederationConfiguration);
                    valid = engine.validate(assertion.getSignature(), criteriaSet);
                } catch (final SecurityException e) {
                    LOGGER.warn(e.getMessage(), e);
                } finally {
                    if (!valid) {
                        LOGGER.warn("validateSignature: Signature doesn't match any signing credential.");
                    }
                }

            } catch (final SignatureException e) {
                LOGGER.warn("Failed to validate assertion signature", e);
            }
        }
        return valid;
    }

    /**
     * Build signature trust engine.
     *
     * @param wsFederationConfiguration the ws federation configuration
     * @return the signature trust engine
     */
    private static SignatureTrustEngine buildSignatureTrustEngine(final WsFederationConfiguration wsFederationConfiguration) {
        try {
            final CredentialResolver resolver = new StaticCredentialResolver(wsFederationConfiguration.getSigningCertificates());
            final KeyInfoCredentialResolver keyResolver =
                    new StaticKeyInfoCredentialResolver(wsFederationConfiguration.getSigningCertificates());

            return new ExplicitKeySignatureTrustEngine(resolver, keyResolver);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Loads opensaml configuration and initializes
     * marshallers and parser pools.
     */
    private static final class Configuration {
        private static BasicParserPool PARSER_POOL;
        private static final int POOL_SIZE = 100;

        /**
         * Instantiates a new Configuration.
         */
        private Configuration() {}

        /**
         * Bootstrap config.
         */
        public static void bootstrap() {
            PARSER_POOL = new BasicParserPool();
            PARSER_POOL.setMaxPoolSize(POOL_SIZE);
            PARSER_POOL.setCoalescing(true);
            PARSER_POOL.setIgnoreComments(true);
            PARSER_POOL.setNamespaceAware(true);

            final Map<String, Object> builderAttributes = new HashMap<String, Object>();
            PARSER_POOL.setBuilderAttributes(builderAttributes);

            final Map<String, Boolean> features = new HashMap<String, Boolean>();
            features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
            features.put("http://apache.org/xml/features/validation/schema/normalized-value", Boolean.FALSE);
            features.put("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);
            PARSER_POOL.setBuilderFeatures(features);

            try {
                PARSER_POOL.initialize();
            } catch (final ComponentInitializationException e) {
                throw new RuntimeException("Exception initializing PARSER_POOL", e);
            }

            try {
                InitializationService.initialize();
            } catch (final InitializationException e) {
                throw new RuntimeException("Exception initializing OpenSAML", e);
            }

            XMLObjectProviderRegistry registry;
            synchronized(ConfigurationService.class) {
                registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
                if (registry == null) {
                    registry = new XMLObjectProviderRegistry();
                    ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
                }
            }

            registry.setParserPool(PARSER_POOL);
        }

        public static ParserPool getParserPool() {
            return PARSER_POOL;
        }

        public static XMLObjectBuilderFactory getBuilderFactory() {
            return XMLObjectProviderRegistrySupport.getBuilderFactory();
        }

        public static MarshallerFactory getMarshallerFactory() {
            return XMLObjectProviderRegistrySupport.getMarshallerFactory();
        }

        public static UnmarshallerFactory getUnmarshallerFactory() {
            return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
        }
    }
}
