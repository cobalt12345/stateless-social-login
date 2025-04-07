package in.talochk.stateless;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties
@SpringBootApplication
public class StatelessSocialLoginApplication {

	public static void main(String[] args) {
		SpringApplication.run(StatelessSocialLoginApplication.class, args);
	}

}
