package spring.third.oauth.request;

import com.alibaba.fastjson.JSONObject;
import spring.third.oauth.cache.AuthStateCache;
import spring.third.oauth.config.AuthConfig;
import spring.third.oauth.config.AuthDefaultSource;
import spring.third.oauth.enums.AuthUserGender;
import spring.third.oauth.model.AuthCallback;
import spring.third.oauth.model.AuthToken;
import spring.third.oauth.model.AuthUser;

/**
 * 阿里云登录
 *
 * @author snippet0809 (https://github.com/snippet0809)
 * @since 1.15.5
 */
public class AuthAliyunRequest extends AuthDefaultRequest {

    public AuthAliyunRequest(AuthConfig config) {
        super(config, AuthDefaultSource.ALIYUN);
    }

    public AuthAliyunRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.ALIYUN, authStateCache);
    }

    @Override
    protected AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());
        JSONObject accessTokenObject = JSONObject.parseObject(response);
        return AuthToken.builder()
                .accessToken(accessTokenObject.getString("access_token"))
                .expireIn(accessTokenObject.getIntValue("expires_in"))
                .tokenType(accessTokenObject.getString("token_type"))
                .idToken(accessTokenObject.getString("id_token"))
                .refreshToken(accessTokenObject.getString("refresh_token"))
                .build();
    }

    @Override
    protected AuthUser getUserInfo(AuthToken authToken) {
        String userInfo = doGetUserInfo(authToken);
        JSONObject object = JSONObject.parseObject(userInfo);
        return AuthUser.builder()
            .rawUserInfo(object)
            .uuid(object.getString("sub"))
            .username(object.getString("login_name"))
            .nickname(object.getString("name"))
            .gender(AuthUserGender.UNKNOWN)
            .token(authToken)
            .source(source.toString())
            .build();
    }

}
