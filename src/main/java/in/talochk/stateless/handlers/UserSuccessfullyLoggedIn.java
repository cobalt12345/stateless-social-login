package in.talochk.stateless.handlers;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.function.Consumer;

/**
 * Post processor is called when user successfully logges in.
 *
 * @author dtalochkin
 */
@Component
@Slf4j
public class UserSuccessfullyLoggedIn extends SavedRequestAwareAuthenticationSuccessHandler {

    public UserSuccessfullyLoggedIn(CookieRequestCache cookieRequestCache) {
        setRequestCache(cookieRequestCache);
        setTargetUrlParameter("redirect_uri");
    }

    private Consumer<OAuth2User> oauth2UserHandler = (user) -> {
        log.info("Success user login: {}", user);
    };

    private Consumer<OidcUser> oidcUserHandler = (user) -> this.oauth2UserHandler.accept(user);


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AuthenticationToken) {
            if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                this.oidcUserHandler.accept(oidcUser);
            } else if (authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
                this.oauth2UserHandler.accept(oAuth2User);
            }
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }

}
