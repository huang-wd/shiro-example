package com.github.zhangkaitao.shiro.chapter6.dao;

import com.github.zhangkaitao.shiro.chapter6.entity.Permission;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-28
 * <p>Version: 1.0
 */
public interface PermissionDao {

    Permission createPermission(Permission permission);

    void deletePermission(Long permissionId);

}
