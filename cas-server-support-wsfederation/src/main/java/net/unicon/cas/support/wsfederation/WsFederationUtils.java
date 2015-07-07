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

import net.unicon.cas.support.wsfederation.authentication.principal.WsFederationCredential;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.impl.AssertionImpl;
import org.opensaml.ws.wsfed.RequestedSecurityToken;
import org.opensaml.ws.wsfed.impl.RequestSecurityTokenResponseImpl;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Helper class that does the heavy lifting with the openSaml library.
 *
 * @author John Gasper
 * @since 3.5.2
 */
public final class WsFederationUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(WsFederationUtils.class);
    /**
     * Initialized the openSaml library.
     */
    static {
        try {
            // Initialize the library
            DefaultBootstrap.bootstrap();
        } catch (final ConfigurationException ex) {
            LOGGER.error(ex.getMessage());
        }
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

        if (assertion.getAuthenticationStatements() != null && assertion.getAuthenticationStatements().size() > 0) {
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
    public static X509Credential getSigningCredential(final Resource resource) {
        try (final InputStream inputStream = resource.getInputStream()) {
            //grab the certificate file
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);

            //get the public key from the certificate
            final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificate.getPublicKey().getEncoded());

            //generate public key to validate signatures
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            //add the public key
            final BasicX509Credential publicCredential = new BasicX509Credential();
            publicCredential.setPublicKey(publicKey);
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
            final BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);

            final Document document = parserPool.parse(in);
            final Element metadataRoot = document.getDocumentElement();
            final UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            final Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
            final RequestSecurityTokenResponseImpl rsToken = (RequestSecurityTokenResponseImpl) unmarshaller.unmarshall(metadataRoot);

            //Get our SAML token
            final List<RequestedSecurityToken> rst = rsToken.getRequestedSecurityToken();
            final AssertionImpl assertion = (AssertionImpl) rst.get(0).getSecurityTokens().get(0);

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
     * @param x509Creds list of x509certs to check.
     * @return true if the assertion's signature is valid, otherwise false
     */
    public static boolean validateSignature(final Assertion assertion, final List<X509Credential> x509Creds) {
        SignatureValidator signatureValidator;
        for (final X509Credential cred : x509Creds) {
            try {
                signatureValidator = new SignatureValidator(cred);
            } catch (final Exception ex) {
                LOGGER.warn(ex.getMessage());
                break;
            }

            //get the signature to validate from the response object
            final Signature signature = assertion.getSignature();

            //try to validate
            try {
                signatureValidator.validate(signature);
                LOGGER.debug("validateSignature: Signature is valid.");
                return true;

            } catch (final ValidationException ex) {
                LOGGER.warn("validateSignature: Signature is NOT valid.");
                LOGGER.warn(ex.getMessage());
            }
        }
        LOGGER.warn("validateSignature: Signature doesn't match any signing credential.");
        return false;
    }

}
