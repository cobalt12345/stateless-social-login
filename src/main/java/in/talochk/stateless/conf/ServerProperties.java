package in.talochk.stateless.conf;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Configuration properties from YAML.
 *
 * @author dtalochkin
 */
@Configuration
@Getter
@Setter
@ConfigurationProperties(prefix = "app.authorization-server")
public class ServerProperties {

    private String clientRegisterId;

    private String clientId;

    private String clientSecret;

    private List<String> landingUrisForCodeExchange;

    private ServerProperties.Google google;

    private ServerProperties.Keycloak keycloak;

    private ServerProperties.HttpSession httpSession;

    @Getter
    @Setter
    public static class Google {
        private String clientId;
        private String clientSecret;
        private String loginFormProviderDirectUri;
    }

    @Getter
    @Setter
    public static class Keycloak {
        private String loginFormProviderDirectUri;
    }

    @Getter
    @Setter
    public static class HttpSession {
        private String redisKeysNamespace;
        private String sessionCookieDomainNamePattern;
        private String sessionCookieName;
        private Integer cookieMaxAgeSeconds;
    }
}
