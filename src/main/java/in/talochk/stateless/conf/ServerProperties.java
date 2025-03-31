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
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app.authorization-server")
public class ServerProperties {

    private String clientRegisterId;

    private String clientId;

    private String clientSecret;

    private List<String> landingUrisForCodeExchange;

    @Getter
    @Setter
    public static class Google {
        private String clientId;
        private String clientSecret;
    }
}
