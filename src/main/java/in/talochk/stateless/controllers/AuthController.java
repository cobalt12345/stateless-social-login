package in.talochk.stateless.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * @author dtalochkin
 */
@Slf4j
@RestController
public class AuthController {

    @GetMapping("/code")
    public void exchangeCode(HttpServletResponse response,
                             @Value("${app.authorization-server.code-authorization-uri}")
                             String codeAuthUri) throws IOException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("User authenticated! %s", authentication);

        response.sendRedirect(codeAuthUri);
    }

    @GetMapping("/source")
    public String propertiesSource(@Value("${app.properties.source}") String source) {

        return source;
    }
}
