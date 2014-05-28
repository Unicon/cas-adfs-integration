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

package net.unicon.cas.support.wsfederation.authentication;

import net.unicon.cas.support.wsfederation.authentication.principal.WsFederationCredentials;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.MutableAuthentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;

/**
 * This class is a metadata populator for WsFederation authentication. The attributes returned
 * in the Security Token are added to returned principal.
 *
 * @author John Gasper
 * @since 3.5.2
 */
public final class WsFederationAuthenticationMetaDataPopulator implements AuthenticationMetaDataPopulator {

    /**
     * populateAttributes adds attributes from the Security Token to the principal.
     *
     * @param authentication the authentication object to add attributes and data to
     * @param credentials    the generated WsFederationCredentials
     * @return the authentication object
     */
    @Override
    public Authentication populateAttributes(final Authentication authentication, final Credentials credentials) {
        if (credentials instanceof WsFederationCredentials) {
            final WsFederationCredentials wsFedCredentials = (WsFederationCredentials) credentials;

            final Principal simplePrincipal = new SimplePrincipal(authentication.getPrincipal().getId(),
                    wsFedCredentials.getCredential().getAttributes());

            final MutableAuthentication mutableAuthentication = new MutableAuthentication(simplePrincipal,
                    authentication.getAuthenticatedDate());

            mutableAuthentication.getAttributes().putAll(authentication.getAttributes());

            return mutableAuthentication;
        }

        return authentication;
    }
}
