package com.jdd.springsecuritydemo.config;

import com.jdd.springsecuritydemo.handle.MyAuthenticationFailHandler;
import com.jdd.springsecuritydemo.handle.MyAuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * SpringSecurity配置类
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder getPassword(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 表单提交
        http.formLogin()
                // 用户自定义登录表单中的表单提交变量
                .usernameParameter("userName")
                .passwordParameter("password")
                // login页面中的form表单的action对应起来
                .loginProcessingUrl("/login")
                // 自定义登录页面
                .loginPage("/login.html")
                // 登录后成的自定义处理器,可以跨域访问,可以不通过controller进行页面跳转
                // 不能和successForwardUrl共存
                //.successForwardUrl("/toMain")
                .successHandler(new MyAuthenticationSuccessHandler("http://www.baidu.com"))
                //.failureForwardUrl("/toError")
                .failureHandler(new MyAuthenticationFailHandler("/error.html"));

        // 授权认证
        http.authorizeRequests()
                // 将自定义的登录页面放行
                .antMatchers("/login.html").permitAll()
                // 错误页面放行
                .antMatchers("/error.html").permitAll()
                // 所有请求,都需要授权认证,必须登录之后才能被访问
                .anyRequest().authenticated();


        // 关闭csrf防护
        http.csrf().disable();
    }
}
