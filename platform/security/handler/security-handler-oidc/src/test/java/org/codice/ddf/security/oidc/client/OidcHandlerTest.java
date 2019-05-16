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
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ddf.security.SecurityConstants;
import ddf.security.common.SecurityTokenHolder;
import ddf.security.http.SessionFactory;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.codice.ddf.security.handler.api.HandlerResult;
import org.codice.ddf.security.handler.api.HandlerResult.Status;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mock;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;

public class OidcHandlerTest {
  private OidcHandler handler;
  private HandlerResult result;

  @Mock private HandlerConfiguration mockConfiguration;
  @Mock private OidcConfiguration mockOidcConfiguration;
  @Mock private OidcClient mockOidcClient;
  @Mock private HttpServletRequest mockRequest;
  @Mock private HttpServletResponse mockResponse;
  @Mock private HttpSession mockSession;
  @Mock private SessionFactory mockSessionFactory;
  @Mock private SecurityTokenHolder mockTokenHolder;

  @BeforeClass
  public static void setupClass() {

  }

  @Before
  public void setup() throws Exception {
    // oidc configuration
    when(mockConfiguration.getOidcConfiguration()).thenReturn(mockOidcConfiguration);

    // oidc client
    when(mockConfiguration.getOidcClient()).thenReturn(mockOidcClient);

    // request
    when(mockRequest.getMethod()).thenReturn("POST");
    when(mockRequest.getServletPath()).thenReturn("https://servlet/path");
    when(mockRequest.getRequestedSessionId()).thenReturn("sessionId");
    when(mockRequest.isRequestedSessionIdValid()).thenReturn(true);

    // session
    when(mockRequest.getSession(any(Boolean.class))).thenReturn(mockSession);
    when(mockSessionFactory.getOrCreateSession(any())).thenReturn(mockSession);

    // token holder
    when(mockSession.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY)).thenReturn(mockTokenHolder);
    when(mockTokenHolder.getSecurityToken()).thenReturn()

    handler = new OidcHandler(mockConfiguration);
  }

  @Test
  public void constructWithNullConfiguration() {
    handler = new OidcHandler(null);

    assertNull(handler.getConfiguration());
  }

  @Test
  public void constructWithEmptyConfiguration() {
    handler = new OidcHandler(new HandlerConfiguration(new HashMap<>()));
  }

  @Test
  public void getNormalizedToken() {
  }

  @Test
  public void getNormalizedTokenHeadRequest() throws Exception {
    when(mockRequest.getMethod()).thenReturn("HEAD");

    result = handler.getNormalizedToken(mockRequest, mockResponse, null, false);

    verify(mockResponse, times(1)).setStatus(HttpServletResponse.SC_OK);
    verify(mockResponse, times(1)).flushBuffer();
    assertThat(result.getStatus(), is(Status.NO_ACTION));
  }

  @Test
  public void getNormalizedTokenNullSessionAndSessionFactory() throws Exception {
    mockSession = null;
    mockSessionFactory = null;

    result = handler.getNormalizedToken(mockRequest, mockResponse, null, false);

    verify(mockResponse, times(1)).setStatus(HttpServletResponse.SC_OK);
    verify(mockResponse, times(1)).flushBuffer();
    assertThat(result.getStatus(), is(Status.NO_ACTION));
  }
}
