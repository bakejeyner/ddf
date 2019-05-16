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

import static junit.framework.TestCase.assertNull;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.util.HashMap;
import java.util.Map;
import org.codice.ddf.security.oidc.client.HandlerConfiguration.Flow;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.pac4j.core.exception.TechnicalException;

@RunWith(MockitoJUnitRunner.class)
public class HandlerConfigurationTest {
  private static Map<String, Object> emptyProperties;
  private static Map<String, Object> validProperties;
  private static Map<String, Object> invalidProperties;

  private HandlerConfiguration handlerConfiguration;

  @Mock
  private OIDCProviderMetadata mockMetadata;

  @BeforeClass
  public static void setupClass() {
    emptyProperties = new HashMap<>();

    validProperties = new HashMap<>();
    validProperties.put(HandlerConfiguration.IDP_TYPE, "generic");
    validProperties.put(HandlerConfiguration.CLIENT_ID, "generic-client");
    validProperties.put(HandlerConfiguration.REALM, "master");
    validProperties.put(HandlerConfiguration.SECRET, "changeit");
    validProperties.put(HandlerConfiguration.DISCOVERY_URI, "https://discovery/uri");
    validProperties.put(HandlerConfiguration.BASE_URI, "https://base/uri");
    validProperties.put(HandlerConfiguration.SCOPE, "openid profile email");
    validProperties.put(HandlerConfiguration.USE_NONCE, "false");
    validProperties.put(HandlerConfiguration.DEFAULT_RESPONSE_TYPE, "code");
    validProperties.put(HandlerConfiguration.RESPONSE_MODE, "form_post");
    validProperties.put(HandlerConfiguration.LOGOUT_URI, "https://logout/uri");

    invalidProperties = new HashMap<>();
    invalidProperties.put(HandlerConfiguration.IDP_TYPE, "invalid idpType");
    invalidProperties.put(HandlerConfiguration.CLIENT_ID, "invalid clientId");
    invalidProperties.put(HandlerConfiguration.REALM, "invalid realm");
    invalidProperties.put(HandlerConfiguration.SECRET, "invalid secret");
    invalidProperties.put(HandlerConfiguration.DISCOVERY_URI, "invalid discoveryUri");
    invalidProperties.put(HandlerConfiguration.BASE_URI, "invalid baseUri");
    invalidProperties.put(HandlerConfiguration.SCOPE, "invalid scope");
    invalidProperties.put(HandlerConfiguration.USE_NONCE, "invalid useNonce");
    invalidProperties.put(
        HandlerConfiguration.DEFAULT_RESPONSE_TYPE, "invalid defaultResponseType");
    invalidProperties.put(HandlerConfiguration.RESPONSE_MODE, "invalid responseMode");
    invalidProperties.put(HandlerConfiguration.LOGOUT_URI, "invalid logoutUri");
  }

  @Test
  public void constructWithNull() {
    handlerConfiguration = new HandlerConfiguration(null);

    assertThat(handlerConfiguration.isConfigured(), is(false));
  }

  @Test
  public void constructWithEmptyProperties() {
    handlerConfiguration = new HandlerConfiguration(emptyProperties);

    assertThat(handlerConfiguration.isConfigured(), is(false));
  }

  @Test
  public void constructWithValidProperties() {
    handlerConfiguration = new HandlerConfiguration(validProperties);

    assertThat(handlerConfiguration.isConfigured(), is(true));
  }

  @Test
  public void constructWithInvalidProperties() {
    handlerConfiguration = new HandlerConfiguration(invalidProperties);

    assertThat(handlerConfiguration.isConfigured(), is(true));
  }

  @Test
  public void beforeGeneration() {
    handlerConfiguration = new HandlerConfiguration(validProperties);

    assertNull(handlerConfiguration.getOidcConfiguration());
    assertNull(handlerConfiguration.getOidcClient());
    assertNull(handlerConfiguration.getLogoutActionBuilder());
    assertNull(handlerConfiguration.getOAuthConfiguration());
    assertNull(handlerConfiguration.getOAuthClient());
  }

  @Test
  public void generateBeforeConfiguringFlow() {
    handlerConfiguration = new HandlerConfiguration(validProperties);
    handlerConfiguration.generate();

    assertThat(handlerConfiguration.getOidcConfiguration().getResponseType(), is(validProperties.get(HandlerConfiguration.DEFAULT_RESPONSE_TYPE)));
    assertThat(handlerConfiguration.getOAuthConfiguration().getResponseType(), is(validProperties.get(HandlerConfiguration.DEFAULT_RESPONSE_TYPE)));
  }

  @Test
  public void configureFlowDefault() {
    handlerConfiguration = new HandlerConfiguration(validProperties);
    handlerConfiguration.configureFlow(Flow.DEFAULT);
    handlerConfiguration.generate();

    assertThat(handlerConfiguration.getOidcConfiguration().getResponseType(), is(validProperties.get(HandlerConfiguration.DEFAULT_RESPONSE_TYPE)));
    assertThat(handlerConfiguration.getOAuthConfiguration().getResponseType(), is(validProperties.get(HandlerConfiguration.DEFAULT_RESPONSE_TYPE)));
  }

  @Test
  public void configureFlowAuthorizationCode() {
    handlerConfiguration = new HandlerConfiguration(validProperties);
    handlerConfiguration.configureFlow(Flow.AUTHORIZATION_CODE);
    handlerConfiguration.generate();

    assertThat(handlerConfiguration.getOidcConfiguration().getResponseType(), is("code"));
    assertThat(handlerConfiguration.getOAuthConfiguration().getResponseType(), is("code"));
  }

  @Test
  public void configureFlowImplicit() {
    handlerConfiguration = new HandlerConfiguration(validProperties);
    handlerConfiguration.configureFlow(Flow.IMPLICIT);
    handlerConfiguration.generate();

    assertThat(handlerConfiguration.getOidcConfiguration().getResponseType(), is("id_token"));
    assertThat(handlerConfiguration.getOAuthConfiguration().getResponseType(), is("id_token"));
  }

  @Test
  public void configureFlowCredential() {
    handlerConfiguration = new HandlerConfiguration(validProperties);
    handlerConfiguration.configureFlow(Flow.CREDENTIAL);
    handlerConfiguration.generate();

    assertThat(handlerConfiguration.getOidcConfiguration().getResponseType(), is("id_token token"));
    assertThat(handlerConfiguration.getOAuthConfiguration().getResponseType(), is("id_token token"));
  }

  /* Should fail due to a request timeout when init is called */
  @Test
  public void testInit() {
    handlerConfiguration = new HandlerConfiguration(validProperties);
    handlerConfiguration.setCallbackUrl("https://callback/uri");
    handlerConfiguration.configureFlow(Flow.DEFAULT);
    handlerConfiguration.generate();
    handlerConfiguration.getOidcConfiguration().setProviderMetadata(mockMetadata);

    handlerConfiguration.init();
  }

  /* Should fail due to a request timeout to the discoveryUri when init is called */
  @Test(expected = TechnicalException.class)
  public void testInitNoMetadata() {
    handlerConfiguration = new HandlerConfiguration(validProperties);
    handlerConfiguration.configureFlow(Flow.DEFAULT);
    handlerConfiguration.generate();

    handlerConfiguration.init();
  }

  @Test(expected = TechnicalException.class)
  public void testInitNoCallbackUrl() {
    handlerConfiguration = new HandlerConfiguration(validProperties);
    handlerConfiguration.configureFlow(Flow.DEFAULT);
    handlerConfiguration.generate();
    handlerConfiguration.getOidcConfiguration().setProviderMetadata(mockMetadata);

    handlerConfiguration.init();
  }
}
