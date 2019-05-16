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

import com.google.common.annotations.VisibleForTesting;
import ddf.action.Action;
import ddf.action.ActionProvider;
import ddf.action.impl.ActionImpl;
import ddf.security.SecurityConstants;
import ddf.security.common.SecurityTokenHolder;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.codice.ddf.configuration.SystemBaseUrl;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.J2ESessionStore;
import org.pac4j.core.http.ajax.DefaultAjaxRequestResolver;
import org.pac4j.core.redirect.RedirectAction;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.logout.OidcLogoutActionBuilder;
import org.pac4j.oidc.profile.OidcProfile;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcLogoutActionProvider implements ActionProvider {

  private static final Logger LOGGER = LoggerFactory.getLogger(OidcLogoutActionProvider.class);

  private static final String ID = "security.logout.oidc";

  private static final String TITLE = "OIDC Logout";

  private static final String DESCRIPTION =
      "Logging out of the Identity Provider(IdP) will logout all external clients signed in via that Identity Provider.";

  @VisibleForTesting
  final HandlerConfiguration handlerConfiguration;

  public OidcLogoutActionProvider(HandlerConfiguration handlerConfiguration) {
    if (handlerConfiguration == null) {
      LOGGER.warn("OidcLogoutActionProvider received a null HandlerConfiguration during construction. Logout actions will not be generated until the HandlerConfiguration in this provider is updated.");
    }
    this.handlerConfiguration = handlerConfiguration;
  }

  /**
   * *
   *
   * @param <T> is a Map<String, Subject>
   * @param subjectMap containing the corresponding subject
   * @return OidcLogoutActionProvider containing the logout url
   */
  public <T> Action getAction(T subjectMap) {
    if (handlerConfiguration == null) {
      LOGGER.warn("OidcLogoutActionProvider received a null HandlerConfiguration during construction. Logout actions will not be generated until the HandlerConfiguration in this provider is updated.");
      throw new IllegalStateException("OidcLogoutActionProvider received a null HandlerConfiguration during construction. Logout actions will not be generated until the HandlerConfiguration in this provider is updated.");
    }
    if (!canHandle(subjectMap)) {
      LOGGER.warn("Cannot handle passed in subject map ({}) in order to create logout action.",
          subjectMap);
      return null;
    }

    String logoutUrlString = "";
    URL logoutUrl = null;

    try {
      HttpServletRequest request = (HttpServletRequest) ((Map) subjectMap).get("http_request");
      HttpServletResponse response = (HttpServletResponse) ((Map) subjectMap).get("http_response");

      J2ESessionStore sessionStore = new J2ESessionStore();
      J2EContext j2EContext = new J2EContext(request, response, sessionStore);

      HttpSession session = request.getSession(false);
      SecurityTokenHolder savedToken = null;
      if (session != null) {
        savedToken =
            (SecurityTokenHolder) session.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY);
      }

      OidcCredentials credentials = null;
      if (savedToken != null && savedToken.getSecurityToken() != null) {
        credentials = (OidcCredentials) savedToken.getSecurityToken();
      }

      if (credentials == null) {
        throw new IllegalStateException("Unable to determine credentials of client for logout");
      }

      OidcLogoutActionBuilder logoutActionBuilder = handlerConfiguration.getLogoutActionBuilder();
      logoutActionBuilder.setAjaxRequestResolver(
          new DefaultAjaxRequestResolver() {
            @Override
            public boolean isAjax(final WebContext context) {
              return false;
            }
          });

      OidcProfileCreator oidcProfileCreator = handlerConfiguration.getOidcProfileCreator();

      OidcProfile oidcProfile = oidcProfileCreator.create(credentials, j2EContext);

      RedirectAction logoutAction =
          logoutActionBuilder.getLogoutAction(
              j2EContext, oidcProfile, SystemBaseUrl.EXTERNAL.constructUrl("/oidc/logout", true));

      logoutUrlString = logoutAction.getLocation();

      logoutUrl = new URL(logoutUrlString);
    } catch (MalformedURLException e) {
      LOGGER.info("Unable to resolve URL: {}", logoutUrlString);
    } catch (ClassCastException e) {
      LOGGER.debug("Unable to cast parameter to Map<String, Object>, {}", subjectMap, e);
    }
    return new ActionImpl(ID, TITLE, DESCRIPTION, logoutUrl);
  }

  @Override
  public String getId() {
    return ID;
  }

  private <T> boolean canHandle(T subjectMap) {
    if (!(subjectMap instanceof Map)) {
      return false;
    }

    Object credentials = ((Map) subjectMap).get(SecurityConstants.SECURITY_SUBJECT);
    return credentials instanceof OidcCredentials;
  }
}
