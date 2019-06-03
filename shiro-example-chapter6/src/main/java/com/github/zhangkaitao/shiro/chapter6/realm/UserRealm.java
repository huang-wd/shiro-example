package com.github.zhangkaitao.shiro.chapter6.realm;

import com.github.zhangkaitao.shiro.chapter6.service.UserService;
import com.github.zhangkaitao.shiro.chapter6.service.UserServiceImpl;
import com.github.zhangkaitao.shiro.chapter6.entity.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-28
 * <p>Version: 1.0
 */
public class UserRealm extends AuthorizingRealm {

    private UserService userService = new UserServiceImpl();

    /**
     * 根据用户名获取并设置用户角色和角色权限码
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.setRoles(userService.findRoles(username));
        authorizationInfo.setStringPermissions(userService.findPermissions(username));
        return authorizationInfo;
    }

    /**
     * 检查用户名与密码是否匹配 判断是否登录成功
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
        User user = userService.findByUsername(username);
        if (user == null) {
            /**
             * 没找到帐号
             */
            throw new UnknownAccountException();
        }
        if (Boolean.TRUE.equals(user.getLocked())) {
            /**
             * 帐号锁定
             */
            throw new LockedAccountException();
        }

        //交给AuthenticatingRealm使用CredentialsMatcher进行密码匹配，如果觉得人家的不好可以自定义实现
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                //用户名
                user.getUsername(),
                //密码
                user.getPassword(),
                //salt=username+salt
                ByteSource.Util.bytes(user.getCredentialsSalt()),
                //realm name
                getName()
        );
        return authenticationInfo;
    }
}
