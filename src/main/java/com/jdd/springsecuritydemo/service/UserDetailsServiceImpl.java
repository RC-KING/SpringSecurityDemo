package com.jdd.springsecuritydemo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 自定义的登录逻辑
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    // PasswordEncoder是密码加密解密的工具类
    @Autowired
    private PasswordEncoder pw;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("进入loadUserByUsername方法!");
        // 1.查询数据库,用户名是否存在,若不存在则抛出异常UsernameNotFoundException
        if(!"admin".equals(username)){
            throw new UsernameNotFoundException("用户名不存在!");
        }
        // 2.把查询出来的密码(注册的时候已经被加密过的)进行解析,放入构造参数
        String password = pw.encode("123");
        return new User(username,password,
                // 授权工具类
                AuthorityUtils
                        .commaSeparatedStringToAuthorityList
                                ("admin,normal," +
                                        "ROLE_jdd," +
                                        "/main.html," +
                                        "/insert,/delete"));
    }
}
