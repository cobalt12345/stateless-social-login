package in.talochk.stateless.repos;

import in.talochk.stateless.conf.ServerProperties;
import in.talochk.stateless.util.Utility;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * @author dtalochkin
 */
@Slf4j
@Repository
public class ExtendedAuthorizedClientRepository implements OAuth2AuthorizedClientRepository {

    private final RedisTemplate<String, Map<String, OAuth2AuthorizedClient>> redisTemplateAuthorizedClientData;
    private final RedisTemplate<String, Authentication> redisTemplateAuthenticatedPrincipleData;
    private final String authorizedClientPrefix;
    private final String authenticatedPrinciple;
    private final Utility utility;

    private static final int AUTHORIZED_CLIENTS_TTL = 5 * 60; //seconds
    private static final int AUTHENTICATED_PRINCIPLE_TTL = AUTHORIZED_CLIENTS_TTL;

    public ExtendedAuthorizedClientRepository(
            RedisTemplate<String, Map<String, OAuth2AuthorizedClient>> redisTemplateAuthorizedClientData,
                RedisTemplate<String, Authentication> redisTemplateAuthenticatedPrincipleData,
                    ServerProperties serverProperties, Utility utility) {

        this.redisTemplateAuthorizedClientData = redisTemplateAuthorizedClientData;
        this.redisTemplateAuthenticatedPrincipleData = redisTemplateAuthenticatedPrincipleData;
        authorizedClientPrefix = serverProperties.getHttpSession().getRedisKeysNamespace() +
                ":authorized_clients:";

        authenticatedPrinciple = serverProperties.getHttpSession().getRedisKeysNamespace() +
                ":authenticated_principle:";

        this.utility = utility;
    }

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, Authentication principal, HttpServletRequest request) {
        var authorizedClients = getAuthorizedClients(request).get(clientRegistrationId);
        var authRequestId = authorizedClientPrefix + utility.retrieveAuthCodeRequestId(request);
        log.debug("Loaded authorized clients for request Id='{}': {}", authRequestId, authorizedClients);

        return (T) authorizedClients;
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal, HttpServletRequest request, HttpServletResponse response) {
        Map<String, OAuth2AuthorizedClient> authorizedClients = this.getAuthorizedClients(request);
        authorizedClients.put(authorizedClient.getClientRegistration().getRegistrationId(), authorizedClient);
        var authRequestId = authorizedClientPrefix + utility.retrieveAuthCodeRequestId(request);

        redisTemplateAuthorizedClientData.opsForValue().set(authRequestId, authorizedClients,
                Duration.of(AUTHORIZED_CLIENTS_TTL, ChronoUnit.SECONDS));

        log.debug("Saved authorized clients with for request Id='{}': {}", authRequestId, authorizedClients);
        authRequestId = authenticatedPrinciple + utility.retrieveAuthCodeRequestId(request);
        redisTemplateAuthenticatedPrincipleData.opsForValue().set(authRequestId, principal,
                Duration.of(AUTHENTICATED_PRINCIPLE_TTL, ChronoUnit.SECONDS));

        log.debug("Saved authenticated principle for request Id='{}': {}", authRequestId, principal);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, Authentication principal, HttpServletRequest request, HttpServletResponse response) {
        Map<String, OAuth2AuthorizedClient> authorizedClients = this.getAuthorizedClients(request);
        var authRequestId = authorizedClientPrefix + utility.retrieveAuthCodeRequestId(request);
        if (!authorizedClients.isEmpty()) {
            if (authorizedClients.remove(clientRegistrationId) != null) {
                if (!authorizedClients.isEmpty()) {
                    redisTemplateAuthorizedClientData.opsForValue().set(authRequestId, authorizedClients,
                            Duration.of(AUTHORIZED_CLIENTS_TTL, ChronoUnit.SECONDS));
                } else {
                    redisTemplateAuthorizedClientData.delete(authRequestId);
                }
                log.debug("Removed authorized client with registration Id='{}' for request Id='{}'",
                        clientRegistrationId, authRequestId);
            }
        }
    }

    public Authentication getAuthenticationByAuthCodeRequestId(String authCodeRequestId) {
        var authRequestId = authenticatedPrinciple + authCodeRequestId;
        var authenticatedPrinciple = redisTemplateAuthenticatedPrincipleData.opsForValue().get(authRequestId);
        log.debug("Authenticated principle for request Id='{}': {}", authRequestId, authenticatedPrinciple);

        return authenticatedPrinciple;
    }

    private Map<String, OAuth2AuthorizedClient> getAuthorizedClients(HttpServletRequest request) {
        var requestId = authorizedClientPrefix + utility.retrieveAuthCodeRequestId(request);
        var authorizedClients = Optional.ofNullable(redisTemplateAuthorizedClientData.opsForValue().get(requestId))
                .orElse(new HashMap<>());

        return authorizedClients;
    }
}
