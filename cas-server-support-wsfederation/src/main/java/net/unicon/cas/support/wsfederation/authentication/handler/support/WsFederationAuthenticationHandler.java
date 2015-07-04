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

package net.unicon.cas.support.wsfederation.authentication.handler.support;

import net.unicon.cas.support.wsfederation.authentication.principal.WsFederationCredential;
import org.jasig.cas.authentication.BasicCredentialMetaData;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.jasig.cas.authentication.principal.SimplePrincipal;

import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;

/**
 * This handler authenticates Security token/credentials.
 *
 * @author John Gasper
 * @since 3.5.2
 */
public final class WsFederationAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {

    /**
     * Determines if this handler can support the credentials provided.
     *
     * @param credentials the credentials to test
     * @return true if supported, otherwise false
     */
    @Override
    public boolean supports(final Credential credentials) {
        return credentials != null && (WsFederationCredential.class.isAssignableFrom(credentials.getClass()));
    }

    @Override
    protected HandlerResult doAuthentication(final Credential credential) throws GeneralSecurityException, PreventedException {
        final WsFederationCredential wsFederationCredentials = (WsFederationCredential) credential;
        if (wsFederationCredentials != null) {
            return new HandlerResult(this, new BasicCredentialMetaData(wsFederationCredentials),
                    new SimplePrincipal(wsFederationCredentials.getId()));
        }
        throw new FailedLoginException();
    }

}
