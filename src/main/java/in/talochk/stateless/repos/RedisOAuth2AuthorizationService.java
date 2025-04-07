package in.talochk.stateless.repos;

import in.talochk.stateless.conf.ServerProperties;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

/**
 * @author dtalochkin
 */
@Service
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final RedisTemplate<String, OAuth2Authorization> redisTemplateAuthorizationData;
    private final String authRedisPrefix;

    public RedisOAuth2AuthorizationService(RedisTemplate<String, OAuth2Authorization> redisTemplateAuthorizationData,
        ServerProperties serverProperties) {

        this.redisTemplateAuthorizationData = redisTemplateAuthorizationData;
        authRedisPrefix = serverProperties.getHttpSession()
                .getRedisKeysNamespace().concat(":authorization:");
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        redisTemplateAuthorizationData.opsForValue().set(authRedisPrefix.concat(authorization.getId()), authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        redisTemplateAuthorizationData.delete(authRedisPrefix.concat(authorization.getId()));
    }

    @Override
    public OAuth2Authorization findById(String id) {

        return redisTemplateAuthorizationData.opsForValue().get(authRedisPrefix.concat(id));
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {

        OAuth2Authorization foundAuthorization;
        try (Cursor<String> cursor = redisTemplateAuthorizationData.scan(ScanOptions.scanOptions().match(
                authRedisPrefix.concat("*")).build())) {

            while(cursor.hasNext()) {
                var nextAuthorizationId = cursor.next();
                foundAuthorization = redisTemplateAuthorizationData.opsForValue().get(nextAuthorizationId);
                var foundToken = foundAuthorization.getToken(token);
                if (null != foundToken) {

                    return foundAuthorization;
                }
            }
        }

        return null;
    }
}
