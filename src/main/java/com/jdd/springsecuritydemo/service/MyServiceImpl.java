package com.jdd.springsecuritydemo.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;

@Service
public class MyServiceImpl implements MyService {
    @Override
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        // 获得主体
        Object object = authentication.getPrincipal();
        if (object instanceof UserDetails){
            UserDetails userDetails = (UserDetails)object;
            // 拿到所有权限
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            // 判断权限中是否授权这个URI
            return authorities.contains(new SimpleGrantedAuthority(request.getRequestURI()));
        }
        return false;
    }
}
