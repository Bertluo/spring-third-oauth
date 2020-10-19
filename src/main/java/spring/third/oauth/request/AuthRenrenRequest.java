package spring.third.oauth.request;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.xkcoding.http.util.UrlUtil;
import spring.third.oauth.cache.AuthStateCache;
import spring.third.oauth.config.AuthConfig;
import spring.third.oauth.enums.AuthUserGender;
import spring.third.oauth.enums.scope.AuthRenrenScope;
import spring.third.oauth.exception.AuthException;
import spring.third.oauth.model.AuthCallback;
import spring.third.oauth.model.AuthResponse;
import spring.third.oauth.model.AuthToken;
import spring.third.oauth.model.AuthUser;
import spring.third.oauth.utils.AuthScopeUtils;
import spring.third.oauth.utils.HttpUtils;
import spring.third.oauth.utils.UrlBuilder;

import java.util.Objects;

import static spring.third.oauth.config.AuthDefaultSource.RENREN;
import static spring.third.oauth.enums.AuthResponseStatus.SUCCESS;

/**
 * 人人登录
 *
 * @author hongwei.peng (pengisgood(at)gmail(dot)com)
 * @since 1.9.0
 */
public class AuthRenrenRequest extends AuthDefaultRequest {

    public AuthRenrenRequest(AuthConfig config) {
        super(config, RENREN);
    }

    public AuthRenrenRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, RENREN, authStateCache);
    }

    @Override
    protected AuthToken getAccessToken(AuthCallback authCallback) {
        return this.getToken(accessTokenUrl(authCallback.getCode()));
    }

    @Override
    protected AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);
        JSONObject userObj = JSONObject.parseObject(response).getJSONObject("response");

        return AuthUser.builder()
            .rawUserInfo(userObj)
            .uuid(userObj.getString("id"))
            .avatar(getAvatarUrl(userObj))
            .nickname(userObj.getString("name"))
            .company(getCompany(userObj))
            .gender(getGender(userObj))
            .token(authToken)
            .source(source.toString())
            .build();
    }

    @Override
    public AuthResponse refresh(AuthToken authToken) {
        return AuthResponse.builder()
            .code(SUCCESS.getCode())
            .data(getToken(this.refreshTokenUrl(authToken.getRefreshToken())))
            .build();
    }

    private AuthToken getToken(String url) {
        String response = new HttpUtils(config.getHttpConfig()).post(url);
        JSONObject jsonObject = JSONObject.parseObject(response);
        if (jsonObject.containsKey("error")) {
            throw new AuthException("Failed to get token from Renren: " + jsonObject);
        }

        return AuthToken.builder()
            .tokenType(jsonObject.getString("token_type"))
            .expireIn(jsonObject.getIntValue("expires_in"))
            .accessToken(UrlUtil.urlEncode(jsonObject.getString("access_token")))
            .refreshToken(UrlUtil.urlEncode(jsonObject.getString("refresh_token")))
            .openId(jsonObject.getJSONObject("user").getString("id"))
            .build();
    }

    private String getAvatarUrl(JSONObject userObj) {
        JSONArray jsonArray = userObj.getJSONArray("avatar");
        if (Objects.isNull(jsonArray) || jsonArray.isEmpty()) {
            return null;
        }
        return jsonArray.getJSONObject(0).getString("url");
    }

    private AuthUserGender getGender(JSONObject userObj) {
        JSONObject basicInformation = userObj.getJSONObject("basicInformation");
        if (Objects.isNull(basicInformation)) {
            return AuthUserGender.UNKNOWN;
        }
        return AuthUserGender.getRealGender(basicInformation.getString("sex"));
    }

    private String getCompany(JSONObject userObj) {
        JSONArray jsonArray = userObj.getJSONArray("work");
        if (Objects.isNull(jsonArray) || jsonArray.isEmpty()) {
            return null;
        }
        return jsonArray.getJSONObject(0).getString("name");
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户授权后的token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
            .queryParam("access_token", authToken.getAccessToken())
            .queryParam("userId", authToken.getOpenId())
            .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
            .queryParam("scope", this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthRenrenScope.values())))
            .build();
    }
}
