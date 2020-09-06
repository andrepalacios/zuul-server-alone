package com.andre.servicio.app.zuul.oauth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableResourceServer
public class ResourceServerConfig  extends ResourceServerConfigurerAdapter{
	
	@Value("${config.security.oauth.jwt.key}")
    private String jwtKey;

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		 resources.tokenStore(tokenStore());
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		 http.authorizeRequests().antMatchers("/api/security/oauth/**").permitAll()
	        .antMatchers(HttpMethod.GET, "/api/productos/listar", "/api/users/users").permitAll()
	        .antMatchers(HttpMethod.GET, "/api/productos/listar/{id}",
	                "/api/usuarios/usuarios/{id}").hasAnyRole("ADMIN", "USER")
	        .antMatchers(HttpMethod.POST, "/api/productos/crear", "/api/usuarios/usuarios").hasRole("ADMIN")
	        .antMatchers(HttpMethod.PUT, "/api/productos/editar/{id}","/api/productos/addstock/{id}/cantidad/{qty}", 
	        		"/api/productos/removestock/{id}/cantidad/{qty}", "/productos/addsale/{id}/cantidad/{qty}",
	        		"/api/usuarios/usuarios/{id}").hasAnyRole("ADMIN", "USER")
	        .antMatchers(HttpMethod.DELETE, "/api/productos/eliminar/{id}", "api/usuarios/usuarios/{id}").hasRole("ADMIN")
	        .anyRequest().authenticated();

	}
	
	@Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
        tokenConverter.setSigningKey(jwtKey);
        return tokenConverter;
    }


}
