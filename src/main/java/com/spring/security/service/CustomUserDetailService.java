package com.spring.security.service;

import com.spring.security.module.ApplicationUser;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CustomUserDetailService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        ApplicationUser applicationUser = loadApplicationUserByUserName(username);
        PasswordEncoder encoder =
                PasswordEncoderFactories.createDelegatingPasswordEncoder();

        return new User(applicationUser.getUsername(), encoder.encode(applicationUser.getPassword()),
                AuthorityUtils.createAuthorityList("ROLE_USER"));

    }


    public ApplicationUser loadApplicationUserByUserName(String username) {
        System.out.println("USERNAME IS : " + username);
        return new ApplicationUser("batman", "pass");
    }
}
