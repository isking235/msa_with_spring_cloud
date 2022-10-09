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
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

//        http.authorizeRequests().antMatchers("/users/**").permitAll();

        http.authorizeRequests().antMatchers("/actuator/**").permitAll();
        http.authorizeRequests().antMatchers("/health_check/**").permitAll();
        http.authorizeRequests().antMatchers("/**")
                //.hasIpAddress(env.getProperty("gateway.ip")) // <- IP 변경
                .access("hasIpAddress('" + env.getProperty("gateway.ip") + "')")
                .and()
                .addFilter(getAuthenticationFilter());

//        http.authorizeRequests().antMatchers("/users")
//                .hasIpAddress(env.getProperty("gateway.ip")) // <- IP 변경
//                .and()
//                .addFilter(getAuthenticationFilter());
//
//        http.authorizeRequests().anyRequest().denyAll();

        http.headers().frameOptions().disable();
    }

    private AuthenticationFilter getAuthenticationFilter() throws Exception {
        AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager(), userService, env);
        //authenticationFilter.setAuthenticationManager(authenticationManager()); //생성자로 생성하기 때문에 필요 없어짐

        return authenticationFilter;
    }

    // select pwd from users where email = ?
    // db_pwd(encrypted == input_pwd(encrypted)
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception { //인증에 관한 것
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
    }
}
