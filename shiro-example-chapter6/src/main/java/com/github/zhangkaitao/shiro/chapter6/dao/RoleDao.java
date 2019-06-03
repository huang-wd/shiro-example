package com.github.zhangkaitao.shiro.chapter6.dao;

import com.github.zhangkaitao.shiro.chapter6.entity.Role;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-28
 * <p>Version: 1.0
 */
public interface RoleDao {

    Role createRole(Role role);

    void deleteRole(Long roleId);

    void correlationPermissions(Long roleId, Long... permissionIds);

    void unCorrelationPermissions(Long roleId, Long... permissionIds);

}
