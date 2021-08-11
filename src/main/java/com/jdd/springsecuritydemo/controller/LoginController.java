package com.jdd.springsecuritydemo.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {


//    @RequestMapping("login")
//    public String login(){
//        System.out.println("执行登录方法");
//        return "redirect:main.html";
//    }

    /**
     * 登录之后,跳转的请求
     * @return
     */
    @PreAuthorize("hasRole('ROLE_jdd')")
    @Secured("ROLE_jddd")
    @RequestMapping("toMain")
    public String toMain(){

        return "redirect:main.html";
    }
    /**
     * 登录错误
     * @return
     */
    @RequestMapping("toError")
    public String toError(){

        return "redirect:error.html";
    }

    @RequestMapping("demo")
    public String demo(){
        return "demo";
    }

}
