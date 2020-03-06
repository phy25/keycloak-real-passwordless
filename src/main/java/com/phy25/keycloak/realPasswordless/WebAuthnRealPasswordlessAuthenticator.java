package com.phy25.keycloak.realPasswordless;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.exception.WebAuthnException;
import org.jboss.logging.Logger;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.*;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.UriUtils;
import org.keycloak.credential.*;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.WebAuthnAuthenticatorsBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.keycloak.services.messages.Messages.*;

/**
 * Authenticator for WebAuthn authentication with passwordless credential. This class is temporary and will be likely
 * removed in the future during future improvements in authentication SPI
 */
public class WebAuthnRealPasswordlessAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(WebAuthnRealPasswordlessAuthenticator.class);
    private KeycloakSession session;

    public WebAuthnRealPasswordlessAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    private static final String ERR_LABEL = "web_authn_authentication_error";
    private static final String ERR_DETAIL_LABEL = "web_authn_authentication_error_detail";

    private void setErrorResponse(AuthenticationFlowContext context, final String errorCase, final String errorMessage) {
        Response errorResponse = null;
        switch (errorCase) {
            case WEBAUTHN_ERROR_REGISTRATION:
                logger.warn(errorCase);
                context.getEvent()
                        .detail(ERR_LABEL, errorCase)
                        .error(Errors.INVALID_USER_CREDENTIALS);
                errorResponse = createErrorResponse(context, errorCase);
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, errorResponse);
                break;
            case WEBAUTHN_ERROR_API_GET:
                logger.warnv("error returned from navigator.credentials.get(). {0}", errorMessage);
                context.getEvent()
                        .detail(ERR_LABEL, errorCase)
                        .detail(ERR_DETAIL_LABEL, errorMessage)
                        .error(Errors.NOT_ALLOWED);
                errorResponse = createErrorResponse(context, errorCase);
                context.failure(AuthenticationFlowError.INVALID_USER, errorResponse);
                break;
            case WEBAUTHN_ERROR_DIFFERENT_USER:
                logger.warn(errorCase);
                context.getEvent()
                        .detail(ERR_LABEL, errorCase)
                        .error(Errors.DIFFERENT_USER_AUTHENTICATED);
                errorResponse = createErrorResponse(context, errorCase);
                context.failure(AuthenticationFlowError.USER_CONFLICT, errorResponse);
                break;
            case WEBAUTHN_ERROR_AUTH_VERIFICATION:
                logger.warnv("WebAuthn API .get() response validation failure. {0}", errorMessage);
                context.getEvent()
                        .detail(ERR_LABEL, errorCase)
                        .detail(ERR_DETAIL_LABEL, errorMessage)
                        .error(Errors.INVALID_USER_CREDENTIALS);
                errorResponse = createErrorResponse(context, errorCase);
                context.failure(AuthenticationFlowError.INVALID_USER, errorResponse);
                break;
            case WEBAUTHN_ERROR_USER_NOT_FOUND:
                logger.warn(errorCase);
                context.getEvent()
                        .detail(ERR_LABEL, errorCase)
                        .error(Errors.USER_NOT_FOUND);
                errorResponse = createErrorResponse(context, errorCase);
                context.failure(AuthenticationFlowError.UNKNOWN_USER, errorResponse);
                break;
            default:
                // NOP
        }
    }

    private Response createErrorResponse(AuthenticationFlowContext context, final String errorCase) {
        LoginFormsProvider provider = context.form().setError(errorCase);
        UserModel user = context.getUser();
        if (user != null) {
            WebAuthnAuthenticatorsBean authenticators = new WebAuthnAuthenticatorsBean(context.getSession(), context.getRealm(), user, getCredentialType());
            if (authenticators.getAuthenticators() != null) {
                provider.setAttribute(WebAuthnConstants.ALLOWED_AUTHENTICATORS, authenticators);
            }
        }
        return provider.createWebAuthnErrorPage();
    }

    public void authenticate(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form();

        Challenge challenge = new DefaultChallenge();
        String challengeValue = Base64Url.encode(challenge.getValue());
        context.getAuthenticationSession().setAuthNote(WebAuthnConstants.AUTH_CHALLENGE_NOTE, challengeValue);
        form.setAttribute(WebAuthnConstants.CHALLENGE, challengeValue);

        WebAuthnPolicy policy = getWebAuthnPolicy(context);
        String rpId = policy.getRpId();
        if (rpId == null || rpId.isEmpty()) rpId =  context.getUriInfo().getBaseUri().getHost();
        form.setAttribute(WebAuthnConstants.RP_ID, rpId);

        UserModel user = context.getUser();
        boolean isUserIdentified = false;
        if (user != null) {
            // in 2 Factor Scenario where the user has already been identified
            WebAuthnAuthenticatorsBean authenticators = new WebAuthnAuthenticatorsBean(context.getSession(), context.getRealm(), user, getCredentialType());
            if (authenticators.getAuthenticators().isEmpty()) {
                // require the user to register webauthn authenticator
                return;
            }
            isUserIdentified = true;
            form.setAttribute(WebAuthnConstants.ALLOWED_AUTHENTICATORS, authenticators);
        } else {
            // in ID-less & Password-less Scenario
            // NOP
        }
        form.setAttribute(WebAuthnConstants.IS_USER_IDENTIFIED, Boolean.toString(isUserIdentified));

        // read options from policy
        String userVerificationRequirement = policy.getUserVerificationRequirement();
        form.setAttribute(WebAuthnConstants.USER_VERIFICATION, userVerificationRequirement);

        context.challenge(form.createLoginWebAuthn());
    }

    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();

        context.getEvent().detail(Details.CREDENTIAL_TYPE, getCredentialType());

        // receive error from navigator.credentials.get()
        String errorMsgFromWebAuthnApi = params.getFirst(WebAuthnConstants.ERROR);
        if (errorMsgFromWebAuthnApi != null && !errorMsgFromWebAuthnApi.isEmpty()) {
            setErrorResponse(context, WEBAUTHN_ERROR_API_GET, errorMsgFromWebAuthnApi);
            return;
        }

        String baseUrl = UriUtils.getOrigin(context.getUriInfo().getBaseUri());
        String rpId = context.getUriInfo().getBaseUri().getHost();

        Origin origin = new Origin(baseUrl);
        Challenge challenge = new DefaultChallenge(context.getAuthenticationSession().getAuthNote(WebAuthnConstants.AUTH_CHALLENGE_NOTE));
        ServerProperty server = new ServerProperty(origin, rpId, challenge, null);

        byte[] credentialId = Base64Url.decode(params.getFirst(WebAuthnConstants.CREDENTIAL_ID));
        byte[] clientDataJSON = Base64Url.decode(params.getFirst(WebAuthnConstants.CLIENT_DATA_JSON));
        byte[] authenticatorData = Base64Url.decode(params.getFirst(WebAuthnConstants.AUTHENTICATOR_DATA));
        byte[] signature = Base64Url.decode(params.getFirst(WebAuthnConstants.SIGNATURE));

        final String userHandle = params.getFirst(WebAuthnConstants.USER_HANDLE);
        final String userId;
        // existing User Handle means that the authenticator used Resident Key supported public key credential
        if (userHandle == null || userHandle.isEmpty()) {
            // Resident Key not supported public key credential was used
            // so rely on the user that has already been authenticated
            userId = context.getUser().getId();
        } else {
            // decode using the same charset as it has been encoded (see: WebAuthnRegister.java)
            userId = new String(Base64Url.decode(userHandle), StandardCharsets.UTF_8);
            if (context.getUser() != null) {
                // Resident Key supported public key credential was used,
                // so need to confirm whether the already authenticated user is equals to one authenticated by the webauthn authenticator
                String firstAuthenticatedUserId = context.getUser().getId();
                if (firstAuthenticatedUserId != null && !firstAuthenticatedUserId.equals(userId)) {
                    context.getEvent()
                            .detail("first_authenticated_user_id", firstAuthenticatedUserId)
                            .detail("web_authn_authenticator_authenticated_user_id", userId);
                    setErrorResponse(context, WEBAUTHN_ERROR_DIFFERENT_USER, null);
                    return;
                }
            } else {
                // Resident Key supported public key credential was used,
                // and the user has not yet been identified
                // so rely on the user authenticated by the webauthn authenticator
                // NOP
            }
        }

        boolean isUVFlagChecked = false;
        String userVerificationRequirement = getWebAuthnPolicy(context).getUserVerificationRequirement();
        if (WebAuthnConstants.OPTION_REQUIRED.equals(userVerificationRequirement)) isUVFlagChecked = true;

        UserModel user = session.users().getUserById(userId, context.getRealm());
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                credentialId,
                clientDataJSON,
                authenticatorData,
                signature,
                server,
                isUVFlagChecked
        );

        WebAuthnCredentialModelInput cred = new WebAuthnCredentialModelInput(getCredentialType());
        cred.setAuthenticationContext(authenticationContext);

        boolean result = false;
        try {
            if (user != null) {
                result = session.userCredentialManager().isValid(context.getRealm(), user, cred);
            }
        } catch (WebAuthnException wae) {
            setErrorResponse(context, WEBAUTHN_ERROR_AUTH_VERIFICATION, wae.getMessage());
            return;
        }
        String encodedCredentialID = Base64Url.encode(credentialId);
        if (result) {
            String isUVChecked = Boolean.toString(isUVFlagChecked);
            logger.debugv("WebAuthn Authentication successed. isUserVerificationChecked = {0}, PublicKeyCredentialID = {1}", isUVChecked, encodedCredentialID);
            context.setUser(user);
            context.getEvent()
                    .detail("web_authn_authenticator_user_verification_checked", isUVChecked)
                    .detail("public_key_credential_id", encodedCredentialID);
            context.success();
        } else {
            context.getEvent()
                    .detail("web_authn_authenticated_user_id", userId)
                    .detail("public_key_credential_id", encodedCredentialID);
            setErrorResponse(context, WEBAUTHN_ERROR_USER_NOT_FOUND, null);
            context.cancelLogin();
        }
    }

    protected WebAuthnPolicy getWebAuthnPolicy(AuthenticationFlowContext context) {
        return context.getRealm().getWebAuthnPolicyPasswordless();
    }

    protected String getCredentialType() {
        return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return session.userCredentialManager().isConfiguredFor(realm, user, getCredentialType());
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // ask the user to do required action to register webauthn authenticator
        if (!user.getRequiredActions().contains(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID)) {
            user.addRequiredAction(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID);
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Collections.singletonList((WebAuthnPasswordlessRegisterFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, WebAuthnPasswordlessRegisterFactory.PROVIDER_ID));
    }


    public void close() {
        // NOP
    }
}