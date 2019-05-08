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

import java.util.Map;
import java.util.Map.Entry;
import org.pac4j.oauth.client.OAuth20Client;
import org.pac4j.oauth.config.OAuth20Configuration;
import org.pac4j.oauth.profile.generic.GenericOAuth20ProfileDefinition;
import org.pac4j.oidc.client.AzureAdClient;
import org.pac4j.oidc.client.GoogleOidcClient;
import org.pac4j.oidc.client.KeycloakOidcClient;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.AzureAdOidcConfiguration;
import org.pac4j.oidc.config.KeycloakOidcConfiguration;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.logout.OidcLogoutActionBuilder;
import org.pac4j.oidc.profile.azuread.AzureAdProfile;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;
import org.pac4j.oidc.profile.google.GoogleOidcProfile;
import org.pac4j.oidc.profile.keycloak.KeycloakOidcProfile;
import org.pac4j.scribe.builder.api.GenericApi20;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HandlerConfiguration {
  private static final Logger LOGGER = LoggerFactory.getLogger(HandlerConfiguration.class);

  private static final String IDP_TYPE = "idpType";
  private static final String CLIENT_ID = "clientId";
  private static final String REALM = "realm";
  private static final String SECRET = "secret";
  private static final String DISCOVERY_URI = "discoveryUri";
  private static final String BASE_URI = "baseUri";
  private static final String SCOPE = "scope";
  private static final String USE_NONCE = "useNonce";
  private static final String DEFAULT_RESPONSE_TYPE = "defaultResponseType";
  private static final String RESPONSE_MODE = "responseMode";
  private static final String LOGOUT_URI = "logoutUri";

  private OidcConfiguration oidcConfiguration;
  private OidcClient oidcClient;
  private OidcProfileCreator oidcProfileCreator;
  private OidcLogoutActionBuilder logoutActionBuilder;

  private OAuth20Configuration oAuthConfiguration;
  private OAuth20Client oAuthClient;

  private String responseType;
  private String callbackUrl;

  private boolean initialized = false;

  // metatype variables
  private String idpType;
  private String clientId;
  private String realm;
  private String secret;
  private String discoveryUri;
  private String baseUri;
  private String scope;
  private boolean useNonce;
  private String defaultResponseType;
  private String responseMode;
  private String logoutUri;

  public HandlerConfiguration(Map<String, Object> properties) {
    if (!properties.isEmpty()) {
      update(properties);
    }
  }

  public OidcClient getOidcClient() {
    return oidcClient;
  }

  public OidcConfiguration getOidcConfiguration() {
    return oidcConfiguration;
  }

  public OidcLogoutActionBuilder getLogoutActionBuilder() {
    return logoutActionBuilder;
  }

  public OidcProfileCreator getOidcProfileCreator() {
    return oidcProfileCreator;
  }

  public OAuth20Client getOAuthClient() {
    return oAuthClient;
  }

  public OAuth20Configuration getOAuthConfiguration() {
    return oAuthConfiguration;
  }

  public boolean isInitialized() {
    return initialized;
  }

  public void setCallbackUrl(String callbackUrl) {
    this.callbackUrl = callbackUrl;
  }

  public void update(Map<String, Object> properties) {
    initialized = true;

    for (Entry entry : properties.entrySet()) {
      String key = (String) entry.getKey();
      Object value = entry.getValue();

      switch (key) {
        case IDP_TYPE:
          idpType = (String) value;
          break;
        case REALM:
          realm = (String) value;
          break;
        case CLIENT_ID:
          clientId = (String) value;
          break;
        case SECRET:
          secret = (String) value;
          break;
        case DISCOVERY_URI:
          discoveryUri = (String) value;
          break;
        case BASE_URI:
          baseUri = (String) value;
          break;
        case SCOPE:
          scope = (String) value;
          break;
        case USE_NONCE:
          useNonce = (boolean) value;
          break;
        case DEFAULT_RESPONSE_TYPE:
          defaultResponseType = (String) value;
          break;
        case RESPONSE_MODE:
          responseMode = (String) value;
          break;
        case LOGOUT_URI:
          logoutUri = (String) value;
          break;
      }
    }
  }

  public void configureFlow(Flow flow) {
    if (flow == null) {
      flow = Flow.DEFAULT;
    }
    configureResponseType(flow);
  }

  public void configureResponseType(Flow flow) {
    switch (flow) {
      case AUTHORIZATION_CODE:
        responseType = "code";
        break;
      case IMPLICIT:
        responseType = "id_token token";
        break;
      case CREDENTIAL:
        responseType = "id_token token";
        break;
      case DEFAULT:
        responseType = defaultResponseType;
    }
  }

  public void generate() {
    generateOidcConfiguration();
    generateOidcClient();
    generateOidcLogoutAction();

    generateOAuthConfiguration();
    generateOAuthClient();
  }

  private void generateOidcConfiguration() {
    if ("Keycloak".equals(idpType)) {
      oidcConfiguration = new KeycloakOidcConfiguration();
      ((KeycloakOidcConfiguration) oidcConfiguration).setRealm(realm);
      ((KeycloakOidcConfiguration) oidcConfiguration).setBaseUri(baseUri);
    } else if ("Azure".equals(idpType)) {
      oidcConfiguration = new AzureAdOidcConfiguration();
      ((AzureAdOidcConfiguration) oidcConfiguration).setTenant(realm);
    } else {
      oidcConfiguration = new OidcConfiguration();
    }

    oidcConfiguration.setClientId(clientId);
    oidcConfiguration.setDiscoveryURI(discoveryUri);
    oidcConfiguration.setSecret(secret);
    oidcConfiguration.setScope(scope);
    oidcConfiguration.setResponseType(responseType);
    oidcConfiguration.setResponseMode(responseMode);
    oidcConfiguration.setUseNonce(useNonce);
    oidcConfiguration.setLogoutUrl(logoutUri);

    oidcConfiguration.init();
  }

  private void generateOidcLogoutAction() {
    logoutActionBuilder = new OidcLogoutActionBuilder(oidcConfiguration);
  }

  private void generateOidcClient() {
    if ("Keycloak".equals(idpType)) {
      oidcClient = new KeycloakOidcClient((KeycloakOidcConfiguration) oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<KeycloakOidcProfile>(oidcConfiguration);
    } else if ("Azure".equals(idpType)) {
      oidcClient = new AzureAdClient((AzureAdOidcConfiguration) oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<AzureAdProfile>(oidcConfiguration);
    } else if ("Google".equals(idpType)) {
      oidcClient = new GoogleOidcClient(oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<GoogleOidcProfile>(oidcConfiguration);
    } else {
      oidcClient = new OidcClient(oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<>(oidcConfiguration);
    }
    oidcClient.setName(oidcConfiguration.getClientId());
    oidcClient.setCallbackUrl(callbackUrl);

    oidcClient.init();
  }

  private void generateOAuthConfiguration() {
    oAuthConfiguration = new OAuth20Configuration();
    oAuthConfiguration.setKey(clientId);
    oAuthConfiguration.setSecret(secret);
    oAuthConfiguration.setTokenAsHeader(false);
    oAuthConfiguration.setWithState(false);
    oAuthConfiguration.setScope(scope);
    oAuthConfiguration.setApi(new GenericApi20(baseUri, baseUri));
    oAuthConfiguration.setProfileDefinition(new GenericOAuth20ProfileDefinition());

    oAuthConfiguration.init();
  }

  private void generateOAuthClient() {
    oAuthClient = new OAuth20Client();
    oAuthClient.setConfiguration(oAuthConfiguration);
    oAuthClient.setCallbackUrl(callbackUrl);

    oAuthClient.init();
  }

  public enum Flow {
    AUTHORIZATION_CODE,
    IMPLICIT,
    CREDENTIAL,
    DEFAULT
  }
}
