package in.talochk.stateless.repos;

import in.talochk.stateless.conf.ServerProperties;
import in.talochk.stateless.util.Utility;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

/**
 * @author dtalochkin
 */
@Slf4j
@Repository
public class SharedAuthCodeRequestRepository implements AuthorizationRequestRepository {

    private final RedisTemplate<String, OAuth2AuthorizationRequest> redisTemplateAuthorizationRequestsData;
    private final String authorizationCodeRequestIdPrefix;
    private final int cookieMaxAge;
    private final int authorizationRequestTtl;
    private final String authCodeRequestIdCookieName;
    private final Utility utility;

    public SharedAuthCodeRequestRepository(
            RedisTemplate<String, OAuth2AuthorizationRequest> redisTemplateAuthorizationRequestsData,
                ServerProperties serverProperties, Utility utility) {

        this.redisTemplateAuthorizationRequestsData = redisTemplateAuthorizationRequestsData;
        authorizationCodeRequestIdPrefix = serverProperties.getHttpSession()
                .getRedisKeysNamespace() + ":authorization_code_request_id:";

        cookieMaxAge = serverProperties.getHttpSession().getCookieMaxAgeSeconds();
        authorizationRequestTtl = cookieMaxAge;
        authCodeRequestIdCookieName = serverProperties.getHttpSession()
                .getSessionCookieName();

        this.utility = utility;
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        var requestId = authorizationCodeRequestIdPrefix + utility.retrieveAuthCodeRequestId(request);
        log.debug("Load Authorization Request with Id='{}'", requestId);
        var authorizationRequest = Optional.ofNullable(redisTemplateAuthorizationRequestsData.opsForValue()
                .get(requestId)).orElseThrow();

        return authorizationRequest;
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
                                         HttpServletResponse response) {

        var requestId = UUID.randomUUID().toString();
        log.debug("Save Authorization Request with Id='{}'", authorizationCodeRequestIdPrefix + requestId);
        var requestIdCookie = new Cookie(authCodeRequestIdCookieName, requestId);
        requestIdCookie.setMaxAge(cookieMaxAge);
        requestIdCookie.setPath(utility.getCookiePath(request));
        requestIdCookie.setSecure(request.isSecure());
        requestIdCookie.setHttpOnly(true);
        response.addCookie(requestIdCookie);

        redisTemplateAuthorizationRequestsData.opsForValue().set(authorizationCodeRequestIdPrefix + requestId,
                authorizationRequest, Duration.of(authorizationRequestTtl, ChronoUnit.SECONDS));
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {

        var requestId = utility.retrieveAuthCodeRequestId(request);
        log.debug("Remove Authorization Request with Id='{}'", requestId);
        var authorizationRequest = redisTemplateAuthorizationRequestsData.opsForValue()
                .getAndDelete(authorizationCodeRequestIdPrefix.concat(requestId));

        return authorizationRequest;
    }
}
