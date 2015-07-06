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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.xml.security.x509.X509Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.*;

/**
 * @author John Gasper
 * @since 3.5.1
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:/applicationContext.xml")
public class WsFederationUtilsTests {
    
    @Autowired
    WsFederationConfiguration wsFedConfig;
    
    @Autowired
    HashMap<String,String> testTokens;

    @Autowired
    ApplicationContext ctx;

    /**
     *
     * @throws Exception
     */
    @Test
    public void testParseTokenString() throws Exception {
        String wresult = testTokens.get("goodToken");
        final Assertion result = WsFederationUtils.parseTokenFromString(wresult);
        assertNotNull("testParseTokenString() - Not null", result);
    }

    /**
     *
     * @throws Exception
     */
    @Test
    public void testCreateCredentialFromToken() throws Exception {
        String wresult = testTokens.get("goodToken");
        final Assertion assertion = WsFederationUtils.parseTokenFromString(wresult);
        
        WsFederationCredential expResult = new WsFederationCredential();
        expResult.setIssuedOn(new DateTime("2014-02-26T22:51:16.504Z").withZone(DateTimeZone.UTC));
        expResult.setNotBefore(new DateTime("2014-02-26T22:51:16.474Z").withZone(DateTimeZone.UTC));
        expResult.setNotOnOrAfter(new DateTime("2014-02-26T23:51:16.474Z").withZone(DateTimeZone.UTC));
        expResult.setIssuer("http://adfs.example.com/adfs/services/trust");
        expResult.setAudience("urn:federation:cas");
        expResult.setId("_6257b2bf-7361-4081-ae1f-ec58d4310f61");
        
        WsFederationCredential result = WsFederationUtils.createCredentialFromToken(assertion);
        
        assertNotNull("testCreateCredentialFromToken() - Not Null", result);
        assertEquals("testCreateCredentialFromToken() - IssuedOn", expResult.getIssuedOn(), result.getIssuedOn());
        assertEquals("testCreateCredentialFromToken() - NotBefore", expResult.getNotBefore(), result.getNotBefore());
        assertEquals("testCreateCredentialFromToken() - NotOnOrAfter", expResult.getNotOnOrAfter(), result.getNotOnOrAfter());
        assertEquals("testCreateCredentialFromToken() - Issuer", expResult.getIssuer(), result.getIssuer());
        assertEquals("testCreateCredentialFromToken() - Audience", expResult.getAudience(), result.getAudience());
        assertEquals("testCreateCredentialFromToken() - Id", expResult.getId(), result.getId());
    }

    /**
     *
     * @throws Exception
     */
    @Test
    public void testGetSigningCredential() throws Exception {
        X509Credential result = WsFederationUtils.getSigningCredential(wsFedConfig.getSigningCertificateFiles().iterator().next());
        assertNotNull("testGetSigningCredential() - Not Null", result);        
    }

    /**
     *
     * @throws Exception
     */
    @Test
    public void testValidateSignatureGoodToken() throws Exception {
        String wresult = testTokens.get("goodToken");
        Assertion assertion = WsFederationUtils.parseTokenFromString(wresult);
        boolean result = WsFederationUtils.validateSignature(assertion, wsFedConfig.getSigningCertificates());
        assertTrue("testValidateSignatureGoodToken() - True", result);
    }

    /**
     *
     * @throws Exception
     */
    @Test
    public void testValidateSignatureModifiedAttribute() throws Exception {
        String wresult = testTokens.get("badTokenModifiedAttribute");
        Assertion assertion = WsFederationUtils.parseTokenFromString(wresult);
        boolean result = WsFederationUtils.validateSignature(assertion, wsFedConfig.getSigningCertificates());
        assertFalse("testValidateSignatureModifiedAttribute() - False", result);
    }

    /**
     *
     * @throws Exception
     */
    @Test
    public void testValidateSignatureBadKey() throws Exception {
        List<X509Credential> signingWallet = new ArrayList<X509Credential>();
        signingWallet.add(WsFederationUtils.getSigningCredential(ctx.getResource("classpath:bad-signing.crt")));
        String wresult = testTokens.get("goodToken");
        Assertion assertion = WsFederationUtils.parseTokenFromString(wresult);
        boolean result = WsFederationUtils.validateSignature(assertion, signingWallet);
        assertFalse("testValidateSignatureModifiedKey() - False", result);
    }

    /**
     *
     * @throws Exception
     */
    @Test
    public void testValidateSignatureModifiedSignature() throws Exception {
        String wresult = testTokens.get("badTokenModifiedSignature");
        Assertion assertion = WsFederationUtils.parseTokenFromString(wresult);
        boolean result = WsFederationUtils.validateSignature(assertion, wsFedConfig.getSigningCertificates());
        assertFalse("testValidateSignatureModifiedSignature() - False", result);
    }

    /**
     *
     * @param config a configuration object
     */
    public void setWsFedConfig(WsFederationConfiguration config) {
        this.wsFedConfig = config;
    }

    /**
     *
     * @param testTokens a configuration object
     */
    public void setTestTokens(HashMap<String, String> testTokens) {
        this.testTokens = testTokens;
    }

}
