/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.ddf.security.oidc.client;

import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.utils.OAuthEncoder;
import org.pac4j.core.client.IndirectClient;
import org.pac4j.core.context.WebContext;
import org.pac4j.oauth.config.OAuth20Configuration;
import org.pac4j.oauth.credentials.OAuth20Credentials;
import org.pac4j.oauth.credentials.extractor.OAuth20CredentialsExtractor;

public class CustomOAuthCredentialsExtractor extends OAuth20CredentialsExtractor {

  public CustomOAuthCredentialsExtractor(
      final OAuth20Configuration configuration, final IndirectClient client) {
    super(configuration, client);
  }

  @Override
  protected OAuth20Credentials getOAuthCredentials(final WebContext context) {
    OAuth20Credentials credentials;

    final String codeParam = context.getRequestParameter(OAuth20Configuration.OAUTH_CODE);
    if (codeParam != null) {
      credentials = new OAuth20Credentials(OAuthEncoder.decode(codeParam));
    } else {
      logger.debug("No OAuth2 code found on request.");
      credentials = new OAuth20Credentials(null);
    }

    final String accessTokenParam = context.getRequestParameter("access_token");
    final String accessTokenHeader = getAccessTokenFromHeader(context);
    final String accessToken = accessTokenParam != null ? accessTokenParam : accessTokenHeader;
    if (accessToken != null) {
      credentials.setAccessToken(new OAuth2AccessToken(OAuthEncoder.decode(accessToken)));
    } else {
      logger.debug("No OAuth2 access token found on request.");
    }

    return credentials;
  }

  private String getAccessTokenFromHeader(WebContext context) {
    String authorizationHeader = context.getRequestHeader("Authorization");
    String[] authorizationArray = null;
    if (authorizationHeader != null) {
      authorizationArray = authorizationHeader.split(" ");
    }

    if (authorizationArray != null
        && "bearer".equals(authorizationArray[0].toLowerCase())
        && authorizationArray.length == 2) {
      return authorizationArray[1];
    }
    return null;
  }
}
