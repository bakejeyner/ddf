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
import com.google.common.hash.Hashing;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import ddf.security.SecurityConstants;
import ddf.security.assertion.SecurityAssertion;
import ddf.security.assertion.jwt.impl.SecurityAssertionJwt;
import ddf.security.common.SecurityTokenHolder;
import ddf.security.common.audit.SecurityLogger;
import ddf.security.http.SessionFactory;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.codice.ddf.platform.filter.AuthenticationException;
import org.codice.ddf.platform.filter.AuthenticationFailureException;
import org.codice.ddf.platform.filter.FilterChain;
import org.codice.ddf.security.handler.api.AuthenticationHandler;
import org.codice.ddf.security.handler.api.HandlerResult;
import org.codice.ddf.security.handler.api.HandlerResult.Status;
import org.codice.ddf.security.handler.api.OidcAuthenticationToken;
import org.codice.ddf.security.oidc.client.HandlerConfiguration.Flow;
import org.codice.ddf.security.policy.context.ContextPolicy;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.context.session.J2ESessionStore;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.http.callback.QueryParameterCallbackUrlResolver;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.oauth.credentials.OAuth20Credentials;
import org.pac4j.oauth.credentials.extractor.OAuth20CredentialsExtractor;
import org.pac4j.oauth.exception.OAuthCredentialsException;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.credentials.authenticator.OidcAuthenticator;
import org.pac4j.oidc.credentials.extractor.OidcExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcHandler implements AuthenticationHandler {

  private static final Logger LOGGER = LoggerFactory.getLogger(OidcHandler.class);

  public static final String SOURCE = "OidcHandler";

  public static final String AUTH_TYPE = "OIDC";

  private HandlerConfiguration handlerConfiguration;

  private SessionFactory sessionFactory;

  public OidcHandler(HandlerConfiguration handlerConfiguration) {
    buildConfiguration(handlerConfiguration);
  }

  public void buildConfiguration(HandlerConfiguration handlerConfiguration) {
    this.handlerConfiguration = handlerConfiguration;
  }

  @Override
  public String getAuthenticationType() {
    return AUTH_TYPE;
  }

  /**
   * Handler implementing OIDC authentication.
   *
   * @param request http request to obtain attributes from and to pass into any local filter chains
   *     required
   * @param response http response to return http responses or redirects
   * @param chain original filter chain (should not be called from your handler)
   * @param resolve flag with true implying that credentials should be obtained, false implying
   *     return if no credentials are found.
   * @return result of handling this request - status and optional tokens
   * @throws AuthenticationFailureException
   */
  @Override
  public HandlerResult getNormalizedToken(
      ServletRequest request, ServletResponse response, FilterChain chain, boolean resolve)
      throws AuthenticationFailureException {

    HttpServletRequest httpRequest = (HttpServletRequest) request;
    if (httpRequest.getMethod().equals("HEAD")) {
      return processHeadRequest(response);
    }

    HttpSession session = httpRequest.getSession(false);
    String path = httpRequest.getServletPath();

    LOGGER.debug("Doing OIDC authentication and authorization for path {}.", path);

    // attempt to grab existing credentials off of session
    SecurityTokenHolder tokenHolder = getTokenHolderFromSession(httpRequest, session);
    if (tokenHolder != null && tokenHolder.getSecurityToken() != null) {
      return getCredentialsFromTokenHolder(tokenHolder, session);
    }

    // at this point, the OIDC Handler must be configured
    if (!handlerConfiguration.isInitialized()) {
      LOGGER.error(
          "The OIDC Handler's configuration has not been initialized. "
              + "Configure \"OIDC Handler Configuration\" in the admin console to initialize.");
      HandlerResult handlerResult = new HandlerResult();
      handlerResult.setSource("oidc-" + SOURCE);
      handlerResult.setStatus(Status.NO_ACTION);
      return handlerResult;
    }

    // no credentials found in session, time to try and pull some off of the request
    OidcCredentials credentials = new OidcCredentials();

    StringBuffer requestUrlBuffer = httpRequest.getRequestURL();
    requestUrlBuffer.append(
        httpRequest.getQueryString() == null ? "" : "?" + httpRequest.getQueryString());
    String requestUrl = requestUrlBuffer.toString();

    handlerConfiguration.setCallbackUrl(requestUrl);

    J2ESessionStore sessionStore = new J2ESessionStore();
    J2EContext j2EContext =
        new J2EContext(httpRequest, ((HttpServletResponse) response), sessionStore);

    boolean isMachine = userAgentIsNotBrowser(httpRequest);

    // machine to machine, check for Client Credentials Flow credentials
    if (isMachine) {
      try {
        credentials = getCredentialFlowCredentials(j2EContext);
      } catch (IllegalArgumentException e) {
        LOGGER.error(
            "Problem with the OIDC Handler's HandlerConfiguration. "
                + "Check the OIDC configuration in the admin console.");
        HandlerResult handlerResult = new HandlerResult();
        handlerResult.setSource("oidc-" + SOURCE);
        handlerResult.setStatus(Status.NO_ACTION);
        return handlerResult;
      } catch (OAuthCredentialsException e) {
        LOGGER.error(
            "Problem extracting credentials from machine to machine request. "
                + "See OAuth2's \"Client Credential Flow\" for more information.");
        HandlerResult handlerResult = new HandlerResult();
        handlerResult.setSource("oidc-" + SOURCE);
        handlerResult.setStatus(Status.NO_ACTION);
        return handlerResult;
      }
    } else { // check for Authorization Code Flow or Implicit Flow credentials
      try {
        credentials = getDefaultFlowCredentials(j2EContext);
      } catch (IllegalArgumentException e) {
        LOGGER.error(
            "Problem with the OIDC Handler's HandlerConfiguration. "
                + "Check the OIDC configuration in the admin console.");
        HandlerResult handlerResult = new HandlerResult();
        handlerResult.setSource("oidc-" + SOURCE);
        handlerResult.setStatus(Status.NO_ACTION);
        return handlerResult;
      } catch (TechnicalException ignore) {
      }
    }

    // use Authorization Code to get real credentials
    if (credentials.getCode() != null && credentials.getIdToken() == null) {
      getCredentialsFromAuthorizationCode(credentials, j2EContext);
    }

    // use Access Token to get real credentials
    if (credentials.getAccessToken() != null && credentials.getIdToken() == null) {
      getCredentialsFromAccessToken(credentials);
    }

    // if the request has credentials, process it
    if (credentials.getIdToken() != null) {
      LOGGER.info("ID Token found on request. Saving to session and continuing filter chain.");
      return addCredentialsToSession(credentials, httpRequest, response, j2EContext, requestUrl);
    } else if (!isMachine) { // the request didn't have credentials, go get some
      LOGGER.info(
          "No credentials found on user-agent request. "
              + "Redirect user-agent to keycloak for credentials.");
      return redirectForCredentials(j2EContext, requestUrl);
    } else { // machine request came in without credentials
      LOGGER.info(
          "No credentials found on machine to machine request; no action taken."
              + "See OAuth2's \"Client Credential Flow\" for more information.");
      HandlerResult handlerResult = new HandlerResult();
      handlerResult.setSource("oidc-" + SOURCE);
      handlerResult.setStatus(Status.NO_ACTION);
      return handlerResult;
    }
  }

  @Override
  public HandlerResult handleError(
      ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) {
    HandlerResult result = new HandlerResult(Status.NO_ACTION, null);
    result.setSource("oidc-" + SOURCE);
    LOGGER.debug("In error handler for oidc - no action taken.");
    return result;
  }

  private boolean userAgentIsNotBrowser(HttpServletRequest httpRequest) {
    String userAgentHeader = httpRequest.getHeader("User-Agent");
    // basically all browsers support the "Mozilla" way of operating, so they all have "Mozilla"
    // in the string. I just added the rest in case that ever changes for existing browsers.
    // New browsers should contain "Mozilla" as well, though.
    return userAgentHeader == null
        || !(userAgentHeader.contains("Mozilla")
            || userAgentHeader.contains("Safari")
            || userAgentHeader.contains("OPR")
            || userAgentHeader.contains("MSIE")
            || userAgentHeader.contains("Edge")
            || userAgentHeader.contains("Chrome"));
  }

  private HandlerResult processHeadRequest(ServletResponse response)
      throws AuthenticationFailureException {
    ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_OK);
    try {
      response.flushBuffer();
    } catch (IOException e) {
      throw new AuthenticationFailureException(
          "Unable to send response to HEAD message from OIDC client.");
    }
    return new HandlerResult(Status.NO_ACTION, null);
  }

  private SecurityTokenHolder getTokenHolderFromSession(
      HttpServletRequest httpRequest, HttpSession session) {
    if (httpRequest.getRequestedSessionId() != null && !httpRequest.isRequestedSessionIdValid()) {
      SecurityLogger.audit(
          "Incoming HTTP Request contained possible unknown session ID [{}] for this server.",
          Hashing.sha256()
              .hashString(httpRequest.getRequestedSessionId(), StandardCharsets.UTF_8)
              .toString());
    }
    if (session == null && httpRequest.getRequestedSessionId() != null) {
      session = sessionFactory.getOrCreateSession(httpRequest);
    }

    SecurityTokenHolder tokenHolder = null;
    if (session != null) {
      tokenHolder =
          (SecurityTokenHolder) session.getAttribute(SecurityConstants.SECURITY_TOKEN_KEY);
    }
    return tokenHolder;
  }

  private HandlerResult getCredentialsFromTokenHolder(
      SecurityTokenHolder tokenHolder, HttpSession session) {
    OidcCredentials credentials = (OidcCredentials) tokenHolder.getSecurityToken();
    HandlerResult handlerResult = new HandlerResult();
    if (credentials.getIdToken() != null) {
      OidcAuthenticationToken oidcAuthenticationToken =
          new OidcAuthenticationToken(credentials.getIdToken(), credentials);
      handlerResult.setStatus(Status.COMPLETED);
      handlerResult.setToken(oidcAuthenticationToken);
      return handlerResult;
    } else {
      LOGGER.error("Id Token from TokenHolder is null. Credentials: {}", credentials);
      session.invalidate();
      handlerResult.setStatus(Status.NO_ACTION);
      return handlerResult;
    }
  }

  private OidcCredentials getCredentialFlowCredentials(J2EContext j2EContext)
      throws IllegalArgumentException, OAuthCredentialsException {
    OAuth20Credentials oAuthCredentials;

    handlerConfiguration.configureFlow(Flow.CREDENTIAL);
    handlerConfiguration.generate();

    OAuth20CredentialsExtractor credentialsExtractor =
        new CustomOAuthCredentialsExtractor(
            handlerConfiguration.getOAuthConfiguration(), handlerConfiguration.getOAuthClient());

    oAuthCredentials = credentialsExtractor.extract(j2EContext);

    String code = oAuthCredentials.getCode();
    OAuth2AccessToken oAuth2AccessToken = oAuthCredentials.getAccessToken();
    String accessToken = null;
    if (oAuth2AccessToken != null) {
      accessToken = oAuth2AccessToken.getAccessToken();
    }
    CommonProfile userProfile = oAuthCredentials.getUserProfile();
    OidcCredentials credentials = new OidcCredentials();

    if (code != null) {
      credentials.setCode(new AuthorizationCode(code));
    }
    if (accessToken != null) {
      credentials.setAccessToken(new BearerAccessToken(accessToken));
    }
    if (userProfile != null) {
      credentials.setUserProfile(userProfile);
    }
    return credentials;
  }

  private OidcCredentials getDefaultFlowCredentials(J2EContext j2EContext) {
    handlerConfiguration.configureFlow(Flow.DEFAULT);
    handlerConfiguration.generate();
    handlerConfiguration
        .getOidcClient()
        .setCallbackUrlResolver(new QueryParameterCallbackUrlResolver());

    OidcExtractor oidcExtractor =
        new OidcExtractor(
            handlerConfiguration.getOidcConfiguration(), handlerConfiguration.getOidcClient());
    return oidcExtractor.extract(j2EContext);
  }

  private void getCredentialsFromAuthorizationCode(
      OidcCredentials credentials, J2EContext j2EContext) {
    OidcAuthenticator authenticator =
        new OidcAuthenticator(
            handlerConfiguration.getOidcConfiguration(), handlerConfiguration.getOidcClient());
    authenticator.validate(credentials, j2EContext);
  }

  private void getCredentialsFromAccessToken(OidcCredentials credentials) {
    URI tokenUri =
        handlerConfiguration.getOidcConfiguration().findProviderMetadata().getTokenEndpointURI();
    ClientID clientId = new ClientID(handlerConfiguration.getOidcConfiguration().getClientId());
    Secret secret = new Secret(handlerConfiguration.getOidcConfiguration().getSecret());
    ClientAuthentication clientAuthentication = new ClientSecretBasic(clientId, secret);
    Scope scope = new Scope("openid", "profile", "email");

    TokenRequest tokenRequest =
        new TokenRequest(tokenUri, clientAuthentication, new ClientCredentialsGrant(), scope);
    HTTPRequest tokenHttpRequest = tokenRequest.toHTTPRequest();
    tokenHttpRequest.setConnectTimeout(
        handlerConfiguration.getOidcConfiguration().getConnectTimeout());
    tokenHttpRequest.setReadTimeout(handlerConfiguration.getOidcConfiguration().getReadTimeout());

    TokenResponse tokenResponse = null;
    try {
      HTTPResponse httpResponse = tokenHttpRequest.send();
      tokenResponse = OIDCTokenResponseParser.parse(httpResponse);
    } catch (IOException | ParseException ignore) {
    }

    if (tokenResponse == null || tokenResponse instanceof TokenErrorResponse) {
      LOGGER.warn("Unable to retrieve ID Token with Access Token.");
    }

    OIDCTokenResponse tokenSuccessResponse = (OIDCTokenResponse) tokenResponse;
    OIDCTokens oidcTokens = tokenSuccessResponse.getOIDCTokens();
    credentials.setAccessToken(oidcTokens.getAccessToken());
    credentials.setRefreshToken(oidcTokens.getRefreshToken());
    credentials.setIdToken(oidcTokens.getIDToken());
  }

  private HandlerResult addCredentialsToSession(
      OidcCredentials credentials,
      HttpServletRequest httpRequest,
      ServletResponse response,
      J2EContext j2EContext,
      String requestUrl) {
    String requestedUrl =
        (String) j2EContext.getSessionStore().get(j2EContext, Pac4jConstants.REQUESTED_URL);
    if (requestedUrl == null) {
      requestedUrl = requestUrl;
    }

    OidcAuthenticationToken oidcAuthenticationToken =
        new OidcAuthenticationToken(credentials.getIdToken(), credentials);
    addJwtToSession(httpRequest, credentials);
    try {
      ((HttpServletResponse) response).sendRedirect(requestedUrl);
    } catch (IOException ignore) {
    }
    HandlerResult handlerResult = new HandlerResult();
    handlerResult.setSource("oidc-" + SOURCE);
    handlerResult.setToken(oidcAuthenticationToken);
    handlerResult.setStatus(Status.COMPLETED);

    return handlerResult;
  }

  private HandlerResult redirectForCredentials(J2EContext j2EContext, String requestUrl) {
    handlerConfiguration.configureFlow(Flow.DEFAULT);
    j2EContext.getSessionStore().set(j2EContext, Pac4jConstants.REQUESTED_URL, requestUrl);

    HttpAction redirect = handlerConfiguration.getOidcClient().redirect(j2EContext);

    HandlerResult handlerResult = new HandlerResult();
    handlerResult.setSource("oidc-" + SOURCE);
    handlerResult.setStatus(Status.REDIRECTED);
    return handlerResult;
  }

  // hack

  public void setSessionFactory(SessionFactory sessionFactory) {
    this.sessionFactory = sessionFactory;
  }

  private void addJwtToSession(
      HttpServletRequest httpRequest, OidcCredentials credentials) {
    if (credentials == null) {
      LOGGER.debug("Cannot add null security token to session.");
      return;
    }

    HttpSession session = sessionFactory.getOrCreateSession(httpRequest);
    Object sessionToken = getSecurityToken(session);
    if (sessionToken == null) {
      addSecurityToken(session, credentials);
    }
    SecurityAssertion securityAssertion =
        new SecurityAssertionJwt(credentials.getIdToken(), new ArrayList<>());
    SecurityLogger.audit(
        "Added SAML for user [{}] to session [{}]",
        securityAssertion.getPrincipal().getName(),
        Hashing.sha256().hashString(session.getId(), StandardCharsets.UTF_8).toString());
    int minutes = 60;

    session.setMaxInactiveInterval(minutes * 60);
  }

  private void addSecurityToken(HttpSession session, OidcCredentials token) {
    SecurityTokenHolder holder =
        (SecurityTokenHolder)
            session.getAttribute(ddf.security.SecurityConstants.SECURITY_TOKEN_KEY);

    holder.setSecurityToken(token);
  }

  private Object getSecurityToken(HttpSession session) {
    if (session.getAttribute(ddf.security.SecurityConstants.SECURITY_TOKEN_KEY) == null) {
      LOGGER.debug("Security token holder missing from session. New session created improperly.");
      return null;
    }

    SecurityTokenHolder tokenHolder =
        ((SecurityTokenHolder)
            session.getAttribute(ddf.security.SecurityConstants.SECURITY_TOKEN_KEY));

    OidcCredentials token = (OidcCredentials) tokenHolder.getSecurityToken();

    if (token != null) {
      SecurityAssertion assertion = new SecurityAssertionJwt(token.getIdToken(), new ArrayList<>());
      if (!assertion.isPresentlyValid()) {
        LOGGER.debug("Session SAML token is invalid.  Removing from session.");
        tokenHolder.remove();
        return null;
      }
    }

    return token;
  }

  // end hack
}
