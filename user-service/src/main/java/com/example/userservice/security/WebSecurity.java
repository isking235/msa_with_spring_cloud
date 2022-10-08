package com.example.userservice.security;

import com.example.userservice.service.UserService;
import org.apache.catalina.User;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    private UserService userService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private Environment env;

    public WebSecurity(Environment env, UserService userService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.env = env;
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception { //권한에 관한 것
        //super.configure(http);
        http.csrf().disable();
        //http.authorizeRequests().antMatchers("/users/**").permitAll(); //이건 login 구현 하면서 주석 처리
        http.authorizeRequests().antMatchers("/users/**")
                .hasIpAddress("192.168.0.100")
                .and()
                .addFilter(getAuthenticationFilter());

        //이까지 입력하면 h2-console가 접속이 안된다.
        //아래 소스를 추가한다.
        http.headers().frameOptions().disable();

    }

    private AuthenticationFilter getAuthenticationFilter() throws Exception {
        AuthenticationFilter authenticationFilter = new AuthenticationFilter();
        authenticationFilter.setAuthenticationManager(authenticationManager());

        return authenticationFilter;
    }

    // select pwd from users where email = ?
    // db_pwd(encrypted == input_pwd(encrypted)
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception { //인증에 관한 것
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
    }
}
