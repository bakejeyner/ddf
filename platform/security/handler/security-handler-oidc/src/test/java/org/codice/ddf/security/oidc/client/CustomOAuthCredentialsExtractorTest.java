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

import static com.github.scribejava.core.model.OAuthConstants.ACCESS_TOKEN;
import static junit.framework.TestCase.assertNull;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import com.google.common.io.CharStreams;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import java.io.InputStreamReader;
import java.util.function.Function;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.pac4j.core.context.WebContext;
import org.pac4j.oauth.client.OAuth20Client;
import org.pac4j.oauth.config.OAuth20Configuration;
import org.pac4j.oauth.credentials.OAuth20Credentials;

@RunWith(MockitoJUnitRunner.class)
public class CustomOAuthCredentialsExtractorTest {
  private static final String CODE = "code";
  private static final String AUTHORIZATION = "Authorization";
  private static final Function<WebContext, Boolean> CANCELLED_FACTORY = (webContext) -> false;

  private static String authorizationCode;
  private static AccessToken accessToken;
  private static String authorizationHeader;

  private CustomOAuthCredentialsExtractor extractor;
  private OAuth20Credentials credentials;

  @Mock private OAuth20Configuration mockOidcConfiguration;
  @Mock private OAuth20Client mockOAuthClient;
  @Mock private WebContext mockWebContext;

  @BeforeClass
  public static void setupClass() throws Exception {
    authorizationCode = CharStreams.toString(new InputStreamReader(CustomOAuthCredentialsExtractorTest.class.getClassLoader().getResourceAsStream("authorizationCode.txt")));
    String accessTokenString = CharStreams.toString(new InputStreamReader(CustomOAuthCredentialsExtractorTest.class.getClassLoader().getResourceAsStream("accessToken.jwt")));
    
    accessToken = new BearerAccessToken(accessTokenString);
    authorizationHeader = "Bearer " + accessToken;
  }

  @Before
  public void setup() {
    when(mockOidcConfiguration.getHasBeenCancelledFactory()).thenReturn(CANCELLED_FACTORY);

    extractor = new CustomOAuthCredentialsExtractor(mockOidcConfiguration, mockOAuthClient);
  }

  @Test(expected = NullPointerException.class)
  public void extractNullWebContext() {
    extractor.extract(null);
  }

  @Test
  public void extractNoCredentialsOnWebContext() {
    when(mockWebContext.getRequestParameter(CODE)).thenReturn(null);
    when(mockWebContext.getRequestParameter(ACCESS_TOKEN)).thenReturn(null);
    when(mockWebContext.getRequestHeader(AUTHORIZATION)).thenReturn(null);

    credentials = extractor.extract(mockWebContext);

    assertNull(credentials.getCode());
    assertNull(credentials.getAccessToken());
  }

  @Test
  public void extractCodeParameterOnWebContext() {
    when(mockWebContext.getRequestParameter(CODE)).thenReturn(authorizationCode);
    when(mockWebContext.getRequestParameter(ACCESS_TOKEN)).thenReturn(null);
    when(mockWebContext.getRequestHeader(AUTHORIZATION)).thenReturn(null);

    credentials = extractor.extract(mockWebContext);

    assertThat(credentials.getCode(), is(authorizationCode));
    assertNull(credentials.getAccessToken());
  }

  @Test
  public void extractAccessTokenParameterOnWebContext() {
    when(mockWebContext.getRequestParameter(CODE)).thenReturn(null);
    when(mockWebContext.getRequestParameter(ACCESS_TOKEN)).thenReturn(accessToken.toString());
    when(mockWebContext.getRequestHeader(AUTHORIZATION)).thenReturn(null);

    credentials = extractor.extract(mockWebContext);

    assertNull(credentials.getCode());
    assertThat(credentials.getAccessToken().getAccessToken(), is(accessToken.toString()));
  }

  @Test
  public void extractAccessTokenHeaderOnWebContext() {
    when(mockWebContext.getRequestParameter(CODE)).thenReturn(null);
    when(mockWebContext.getRequestParameter(ACCESS_TOKEN)).thenReturn(null);
    when(mockWebContext.getRequestHeader(AUTHORIZATION)).thenReturn(authorizationHeader);

    credentials = extractor.extract(mockWebContext);

    assertNull(credentials.getCode());
    assertThat(credentials.getAccessToken().getAccessToken(), is(accessToken.toString()));
  }

  @Test
  public void extractEverythingOnWebContext() {
    when(mockWebContext.getRequestParameter(CODE)).thenReturn(authorizationCode);
    when(mockWebContext.getRequestParameter(ACCESS_TOKEN)).thenReturn(accessToken.toString());
    when(mockWebContext.getRequestHeader(AUTHORIZATION)).thenReturn(authorizationHeader);

    credentials = extractor.extract(mockWebContext);

    assertThat(credentials.getCode(), is(authorizationCode));
    assertThat(credentials.getAccessToken().getAccessToken(), is(accessToken.toString()));
  }

  @Test
  public void extractBadHeaderOnWebContext() {
    when(mockWebContext.getRequestParameter(CODE)).thenReturn(null);
    when(mockWebContext.getRequestParameter(ACCESS_TOKEN)).thenReturn(null);
    when(mockWebContext.getRequestHeader(AUTHORIZATION)).thenReturn("badHeader");

    credentials = extractor.extract(mockWebContext);

    assertNull(credentials.getCode());
    assertNull(credentials.getAccessToken());
  }
}
