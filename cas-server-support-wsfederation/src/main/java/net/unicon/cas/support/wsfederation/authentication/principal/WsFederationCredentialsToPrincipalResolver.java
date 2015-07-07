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

package net.unicon.cas.support.wsfederation.authentication.principal;

import net.unicon.cas.support.wsfederation.WsFederationConfiguration;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.principal.PersonDirectoryPrincipalResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class resolves the principal id regarding the WsFederation credentials.
 *
 * @author John Gasper
 * @since 3.5.1
 */
public final class WsFederationCredentialsToPrincipalResolver extends PersonDirectoryPrincipalResolver {

    private final Logger logger = LoggerFactory.getLogger(WsFederationCredentialsToPrincipalResolver.class);

    private WsFederationConfiguration configuration;

    /**
     * Extracts the principalId.
     *
     * @param credentials the credentials
     * @return the principal id
     */
    @Override
    protected String extractPrincipalId(final Credential credentials) {

        final WsFederationCredential wsFedCredentials = (WsFederationCredential) credentials;
        final String principalId = wsFedCredentials.getAttributes().get(
                this.configuration.getIdentityAttribute()
        ).toString();
        logger.debug("principalId : {}", principalId);
        return principalId;
    }



    /**
     * Sets the configuration.
     *
     * @param configuration a configuration
     */
    public void setConfiguration(final WsFederationConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public boolean supports(final Credential credential) {
        return credential != null && (WsFederationCredential.class.isAssignableFrom(credential.getClass()));
    }

}
