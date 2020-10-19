package spring.third.oauth.request;

import spring.third.oauth.config.AuthConfig;
import spring.third.oauth.utils.AuthStateUtils;
import org.junit.Test;

public class AuthWeChatMpRequestTest {

    @Test
    public void authorize() {

        AuthRequest request = new AuthWeChatMpRequest(AuthConfig.builder()
            .clientId("a")
            .clientSecret("a")
            .redirectUri("https://www.justauth.cn")
            .build());
        System.out.println(request.authorize(AuthStateUtils.createState()));
    }
}
