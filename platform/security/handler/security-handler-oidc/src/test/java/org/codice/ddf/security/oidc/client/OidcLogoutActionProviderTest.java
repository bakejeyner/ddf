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
import static org.mockito.Mockito.when;

import ddf.action.Action;
import ddf.security.SecurityConstants;
import ddf.security.common.SecurityTokenHolder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.pac4j.core.redirect.RedirectAction;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.logout.OidcLogoutActionBuilder;
import org.pac4j.oidc.profile.OidcProfile;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;

@RunWith(MockitoJUnitRunner.class)
public class OidcLogoutActionProviderTest {
  @Mock private HandlerConfiguration mockConfiguration;
  @Mock private OidcLogoutActionBuilder mockActionBuilder;
  @Mock private RedirectAction mockAction;
  @Mock private OidcProfileCreator mockProfileCreator;
  @Mock private HttpServletRequest mockRequest;
  @Mock private HttpServletResponse mockResponse;
  @Mock private HttpSession mockSession;
  @Mock private OidcCredentials mockCredentials;
  @Mock private SecurityTokenHolder mockTokenHolder;

  private OidcLogoutActionProvider actionProvider;
  private Map<String, Object> subjectMap;

  @Before
  public void setup() throws Exception {
    // oidc logout action builder
    when(mockConfiguration.getLogoutActionBuilder()).thenReturn(mockActionBuilder);
    when(mockActionBuilder.getLogoutAction(any(), any(), any())).thenReturn(mockAction);
    when(mockAction.getLocation()).thenReturn("https://logout/uri");

    // oidc profile creator
    when(mockConfiguration.getOidcProfileCreator()).thenReturn(mockProfileCreator);
    when(mockProfileCreator.create(any(), any())).thenReturn(new OidcProfile());

    actionProvider = new OidcLogoutActionProvider(mockConfiguration);

    subjectMap = new HashMap<>();
    subjectMap.put("http_request", mockRequest);
    subjectMap.put("http_response", mockResponse);
    subjectMap.put(SecurityConstants.SECURITY_SUBJECT, mockCredentials);
  }

  @Test
  public void constructWithNullConfiguration() {
    actionProvider = new OidcLogoutActionProvider(null);

    assertNull(actionProvider.handlerConfiguration);
  }

  @Test
  public void constructWithValidConfiguration() {
    assertThat(actionProvider.handlerConfiguration.equals(mockConfiguration), is(true));
  }

  @Test(expected = IllegalStateException.class)
  public void getActionWithNullConfiguration() {
    actionProvider = new OidcLogoutActionProvider(null);

    actionProvider.getAction(subjectMap);
  }

  @Test
  public void getActionWithNullSubjectMap() {
    assertNull(actionProvider.getAction(null));
  }

  @Test
  public void getActionWithEmptySubjectMap() {
    assertNull(actionProvider.getAction(new HashMap<>()));
  }

  @Test
  public void getActionWithIncorrectSubjectMapType() {
    List<Object> subjectList = new ArrayList<>();
    subjectList.add(mockRequest);
    subjectList.add(mockResponse);
    subjectList.add(mockCredentials);

    assertNull(actionProvider.getAction(subjectList));
  }

  @Test
  public void getAction() {
    when(mockRequest.getSession(any(Boolean.class))).thenReturn(mockSession);

    when(mockSession.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY)).thenReturn(mockTokenHolder);

    when(mockTokenHolder.getSecurityToken()).thenReturn(mockCredentials);

    Action action = actionProvider.getAction(subjectMap);

    assertThat(action.getUrl().toString(), is("https://logout/uri"));
  }

  @Test(expected = IllegalStateException.class)
  public void getActionWithNullSession() {
    when(mockRequest.getSession(any(Boolean.class))).thenReturn(null);

    actionProvider.getAction(subjectMap);
  }

  @Test(expected = IllegalStateException.class)
  public void getActionWithNullTokenHolder() {
    when(mockRequest.getSession(any(Boolean.class))).thenReturn(mockSession);

    when(mockSession.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY)).thenReturn(null);

    actionProvider.getAction(subjectMap);
  }

  @Test(expected = IllegalStateException.class)
  public void getActionWithNullCredentials() {
    when(mockRequest.getSession(any(Boolean.class))).thenReturn(mockSession);

    when(mockSession.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY)).thenReturn(mockTokenHolder);

    when(mockTokenHolder.getSecurityToken()).thenReturn(null);

    actionProvider.getAction(subjectMap);
  }
}
