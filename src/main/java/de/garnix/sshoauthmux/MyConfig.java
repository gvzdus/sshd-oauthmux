package de.garnix.sshoauthmux;

import org.aeonbits.owner.Config;
import org.aeonbits.owner.Reloadable;

@Config.HotReload
@Config.Sources("file:/etc/sshd-oauthmux/application.properties")

interface MyConfig extends Config, Reloadable {
    @Config.DefaultValue("https://api.amazon.com/auth/O2/token")
    String oauthOutURL();

    @Config.DefaultValue("clientSekret")
    String oauthOutClientSecret();

    @Config.DefaultValue("clientID")
    String oauthOutClientID();

    @Config.DefaultValue("amzn-fXXXX")
    String oauthInClientID();

    @Config.DefaultValue("Basic XXXXXXXXXXXXX")
    String oauthInClientAuthorization();

    @Config.DefaultValue("58824")
    int sshPort();

    @Config.DefaultValue("INFO")
    String logLevel();

    @Config.DefaultValue("")
    String lambdaInClientAuthorization();

    @Config.Separator("\\|")
    @Config.DefaultValue(
            "Strict-Transport-Security: max-age=31536000; includeSubDomains|" +
            "X-Frame-Options: SAMEORIGIN|" +
            "X-Content-Type-Options: nosniff|" +
            "X-XSS-Protection: 1; mode=block|" +
            "Content-Security-Policy: default-src 'unsafe-inline' 'self'|" +
            "Referrer-Policy: strict-origin-when-cross-origin")
    String[] responseHeaders();

    @Config.DefaultValue("25")
    int sshReconnectOffset();

    @Config.DefaultValue("30")
    int sshReconnectRandom();
}