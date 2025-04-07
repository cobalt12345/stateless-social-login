package in.talochk.stateless.conf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.util.Map;

/**
 * @author dtalochkin
 */
@Configuration
public class RedisConfig {

    @Bean
    public RedisTemplate<String, OAuth2AuthorizationRequest> redisTemplateAuthorizationRequestsData(
            RedisConnectionFactory redisConnectionFactory) {

        RedisTemplate<String, OAuth2AuthorizationRequest> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        redisTemplate.setKeySerializer(new StringRedisSerializer());

        return redisTemplate;
    }

    @Bean
    public RedisTemplate<String, Map<String, OAuth2AuthorizedClient>> redisTemplateAuthorizedClientData(
            RedisConnectionFactory redisConnectionFactory) {

        RedisTemplate<String, Map<String, OAuth2AuthorizedClient>> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        redisTemplate.setKeySerializer(new StringRedisSerializer());

        return redisTemplate;
    }

    @Bean
    public RedisTemplate<String, Authentication> redisTemplateAuthenticatedPrincipleData(
            RedisConnectionFactory redisConnectionFactory) {

        RedisTemplate<String, Authentication> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        redisTemplate.setKeySerializer(new StringRedisSerializer());

        return redisTemplate;
    }

    @Bean
    public RedisTemplate<String, OAuth2Authorization> redisTemplateAuthorizationData(
            RedisConnectionFactory redisConnectionFactory) {

        RedisTemplate<String, OAuth2Authorization> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        redisTemplate.setKeySerializer(new StringRedisSerializer());

        return redisTemplate;
    }

}
