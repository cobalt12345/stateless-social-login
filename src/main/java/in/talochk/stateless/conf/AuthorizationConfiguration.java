package in.talochk.stateless.conf;

import in.talochk.stateless.converters.AuthCodeRequestConverter;
import in.talochk.stateless.handlers.UserSuccessfullyLoggedIn;
import in.talochk.stateless.repos.ExtendedAuthorizedClientRepository;
import in.talochk.stateless.repos.SharedAuthCodeRequestRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.util.matcher.ParameterRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;

/**
 * Authorization configuration.
 *
 * @author dtalochkin
 */
@RequiredArgsConstructor
@EnableConfigurationProperties
@EnableWebSecurity
@Configuration
public class AuthorizationConfiguration {

    private static final String SOCIAL_LOGIN_PROVIDER_PARAMETER = "provider";
    private static final String GOOGLE_SOCIAL_LOGIN_PROVIDER = "google";
    private static final String KEYCLOAK_SOCIAL_LOGIN_PROVIDER = "keycloak";

    private final ServerProperties serverProperties;

    @Bean
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer(HttpSecurity httpSecurity) {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        return authorizationServerConfigurer;
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        return new InMemoryRegisteredClientRepository(
                RegisteredClient.withId(serverProperties.getClientRegisterId())
                        .clientId(serverProperties.getClientId())
                        .clientSecret(serverProperties.getClientSecret())
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUris(
                                uris -> uris.addAll(serverProperties.getLandingUrisForCodeExchange())
                        )
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .build()

        );
    }

    @Order(HIGHEST_PRECEDENCE)
    @Bean
    SecurityFilterChain authorizationServerSecurityFilterChain(
            OAuth2AuthorizationServerConfigurer authorizationServerConfigurer,
            HttpSecurity httpSecurity, AuthCodeRequestConverter authCodeRequestConverter,
            CookieRequestCache cookieRequestCache) throws Exception {

        RequestMatcher requestMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        return httpSecurity.securityMatcher(requestMatcher)
                .with(authorizationServerConfigurer, customizer -> {
                    customizer.authorizationEndpoint(
                            authorizationEndpointCustomizer -> authorizationEndpointCustomizer
                                    .authorizationRequestConverter(authCodeRequestConverter));
                })
                .sessionManagement(sessionManagementCustomizer -> sessionManagementCustomizer.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS))
                .requestCache(requestCacheCustomizer -> requestCacheCustomizer.requestCache(cookieRequestCache))
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()))
                .exceptionHandling(exceptionHandlingCustomizer -> {
                    exceptionHandlingCustomizer.defaultAuthenticationEntryPointFor(
                            new LoginUrlAuthenticationEntryPoint(serverProperties.getGoogle()
                                    .getLoginFormProviderDirectUri()),

                            new ParameterRequestMatcher(SOCIAL_LOGIN_PROVIDER_PARAMETER, GOOGLE_SOCIAL_LOGIN_PROVIDER)
                    );
                    exceptionHandlingCustomizer.defaultAuthenticationEntryPointFor(
                            new LoginUrlAuthenticationEntryPoint(serverProperties.getKeycloak()
                                    .getLoginFormProviderDirectUri()),

                            new ParameterRequestMatcher(SOCIAL_LOGIN_PROVIDER_PARAMETER, KEYCLOAK_SOCIAL_LOGIN_PROVIDER)
                    );
                })
                .authorizeHttpRequests(authorizeHttpRequestsCustomizer -> {
                    authorizeHttpRequestsCustomizer.anyRequest().authenticated();
                })
                .build();
    }

    @Order(2)
    @Bean
    SecurityFilterChain defaultFilterChain(HttpSecurity httpSecurity,
                                           UserSuccessfullyLoggedIn userSuccessfullyLoggedIn,
                                           SharedAuthCodeRequestRepository sharedAuthCodeRequestRepository,
                                           ExtendedAuthorizedClientRepository extendedAuthorizedClientRepository,
                                           CookieRequestCache cookieRequestCache)
            throws Exception {

        return httpSecurity.authorizeHttpRequests(customizer -> customizer.anyRequest().authenticated())
                .oauth2Login(customizer -> {
                    customizer.successHandler(userSuccessfullyLoggedIn);
                    customizer.authorizationEndpoint(authorizationEndpointCustomizer ->
                            authorizationEndpointCustomizer.authorizationRequestRepository(
                                    sharedAuthCodeRequestRepository));

                    customizer.authorizedClientRepository(extendedAuthorizedClientRepository);
                })
                .sessionManagement(sessionManagementCustomizer -> sessionManagementCustomizer.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS))
                .requestCache(requestCacheCustomizer -> requestCacheCustomizer.requestCache(cookieRequestCache))
                .build();
    }

    @Bean
    CookieRequestCache cookieRequestCache() {

        return new CookieRequestCache();
    }
}
