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

import org.jasig.cas.authentication.principal.Credentials;

/**
 * This class represents an WsFederation credential.
 *
 * @author John Gasper
 * @since 3.5.2
 */
public final class WsFederationCredentials implements Credentials {

    private static final long serialVersionUID = -4278253713673609027L;

    private final WsFederationCredential credential;

    /**
     * Constructor.
     *
     * @param credential the credential
     */
    public WsFederationCredentials(final WsFederationCredential credential) {
        this.credential = credential;
    }

    /**
     * getCredential returns the stored credential.
     *
     * @return the credential
     */
    public WsFederationCredential getCredential() {
        return this.credential;
    }

}
