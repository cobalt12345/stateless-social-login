package in.talochk.stateless.util;

import in.talochk.stateless.conf.ServerProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.stream.Stream;

/**
 * @author dtalochkin
 */
@RequiredArgsConstructor
@Component
public class Utility {

    private final ServerProperties serverProperties;

    public String retrieveAuthCodeRequestId(HttpServletRequest request) {

        return Stream.of(request.getCookies()).filter(cookie -> cookie.getName().equals(
                serverProperties.getHttpSession().getSessionCookieName())).findFirst().orElseThrow()
                    .getValue();
    }

    public String getCookiePath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return (StringUtils.hasLength(contextPath)) ? contextPath : "/";
    }

}
