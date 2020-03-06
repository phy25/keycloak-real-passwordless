package com.phy25.keycloak.realPasswordless;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.WebAuthnCredentialModel;


public class WebAuthnRealPasswordlessAuthenticatorFactory extends WebAuthnAuthenticatorFactory {

    public static final String PROVIDER_ID = "webauthn-auth-realpasswordless";

    @Override
    public String getReferenceCategory() {
        return WebAuthnCredentialModel.TYPE_PASSWORDLESS;
    }

    @Override
    public String getDisplayType() {
        return "WebAuthn Real Passwordless Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Authenticator for Real Passwordless WebAuthn authentication";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new WebAuthnRealPasswordlessAuthenticator(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}