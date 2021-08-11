package com.jdd.springsecuritydemo.config;

import com.jdd.springsecuritydemo.handle.MyAccessDeniedHandler;
import com.jdd.springsecuritydemo.handle.MyAuthenticationFailHandler;

import com.jdd.springsecuritydemo.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * SpringSecurity配置类
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAccessDeniedHandler myAccessDeniedHandler;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private PersistentTokenRepository persistentTokenRepository;


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
                //.successHandler(new MyAuthenticationSuccessHandler("http://www.baidu.com"))
                .successForwardUrl("/toMain")// 这个方法是要去走Controller方法的

                //.failureForwardUrl("/toError")
                .failureHandler(new MyAuthenticationFailHandler("/error.html"));

        // 授权认证
        http.authorizeRequests()
                // 将自定义的登录页面放行
                .antMatchers("/login.html").permitAll()
                // 错误页面放行
                .antMatchers("/error.html").permitAll()
                // 表示放行js,css,images下的所有目录(常用!!!!)
                .antMatchers("/js/**","/css/**","/images/**").permitAll()
                // 放行图片资源(所有目录下的以.xxx结尾的都被放行)(不常用)
                .antMatchers("/**/*.png","/**/*.jpg").permitAll()
                // 正则表达式匹配规则
                .regexMatchers(".+[.]png").permitAll()
                // 配置servletPath前缀
                // .mvcMatchers("/demo").servletPath("/xxxx").permitAll()
                // 等同于.antMatchers("/xxxx/demo").permitAll()

                // 配置页面访问的权限
                // 权限明严格区分大小写
                //.antMatchers("/main1.html").hasAuthority("admin")
                //.antMatchers("/main1.html").hasAnyAuthority("admin","normal")

                // 角色判断
                //.antMatchers("/main2.html").hasRole("jdd")
                //.antMatchers("/main2.html").hasAnyRole("jdd","jxx")

                // IP判断
                //.antMatchers("/main.html").hasIpAddress("127.0.0.1")

                // 自定义access方法
                //.anyRequest().access("@myServiceImpl.hasPermission(request,authentication)");

                // 所有请求,都需要授权认证,必须登录之后才能被访问
                .anyRequest().authenticated();



        // 关闭csrf防护
        http.csrf().disable();

        // 403处理页面配置 (异常处理)
        http.exceptionHandling()
                .accessDeniedHandler(myAccessDeniedHandler);


        // 配置RememberMe功能
        http.rememberMe()
                // 登录逻辑
                .userDetailsService(userDetailsService)
                // 持久层对象
                .tokenRepository(persistentTokenRepository);


    }
    @Bean
    public PasswordEncoder getPassword(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository getPersistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        // 自动建表,第一次启动需要,第二次启动注释掉
        // jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }


}
