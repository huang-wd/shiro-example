package com.github.zhangkaitao.shiro.chapter6.entity;

import java.io.Serializable;
import java.util.Objects;

/**
 * 用户角色关系
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-28
 * <p>Version: 1.0
 */
public class UserRole implements Serializable {

    private Long userId;
    private Long roleId;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public Long getRoleId() {
        return roleId;
    }

    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        UserRole userRole = (UserRole) o;

        if (!Objects.equals(roleId, userRole.roleId)) {
            return false;
        }
        return Objects.equals(userId, userRole.userId);

    }

    @Override
    public int hashCode() {
        int result = userId != null ? userId.hashCode() : 0;
        result = 31 * result + (roleId != null ? roleId.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "UserRole{" +
                "userId=" + userId +
                ", roleId=" + roleId +
                '}';
    }
}
