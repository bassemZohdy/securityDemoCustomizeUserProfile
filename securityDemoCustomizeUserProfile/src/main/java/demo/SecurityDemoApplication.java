package demo;

import java.util.Collection;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;

import org.h2.server.web.WebServlet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableWebSecurity
@EnableTransactionManagement
public class SecurityDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityDemoApplication.class, args);
	}

	@Bean
	public ServletRegistrationBean h2servletRegistration() {
		ServletRegistrationBean registration = new ServletRegistrationBean(
				new WebServlet());
		registration.addUrlMappings("/db/*");
		return registration;
	}
}

@RestController
class MyController {

	@RequestMapping("/showCustom")
	public String showCustom() {
		User activeUser = (User) SecurityContextHolder.getContext()
				.getAuthentication().getPrincipal();
		return activeUser.getCustom();
	}
}

@Configuration
class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private UserDetailsService userDetailsService;

	@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
		auth.userDetailsService(userDetailsService);
	}

	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().headers().disable().authorizeRequests()
				.antMatchers("/resources/**", "/signup", "/about", "/db/**")
				.permitAll().antMatchers("/showCustom").authenticated()
				.antMatchers("/admin/**").hasRole("ADMIN").anyRequest()
				.authenticated().and().formLogin();
	}

}

@Service
class UserDetailsServiceImpl implements UserDetailsService {

	private UserRepository repo;

	@Autowired
	public UserDetailsServiceImpl(UserRepository repo) {
		this.repo = repo;
	}

	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		User user = repo.findOne(username);
		if (user == null) {
			return null;
		}
		return user;
	}

}

@Repository
interface UserRepository extends JpaRepository<User, String> {
}

@Entity
class Authority implements GrantedAuthority {

	@GeneratedValue
	@Id
	private Integer id;
	@ManyToOne(cascade = CascadeType.REFRESH, targetEntity = User.class, fetch = FetchType.LAZY)
	private User user;
	private String authority;

	@Override
	public String getAuthority() {
		return authority;
	}

	public void setAuthority(String authority) {
		this.authority = authority;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	@Override
	public String toString() {
		return "Authorities [authority=" + authority + "]";
	}

}

@Entity
class User implements UserDetails {

	@Id
	private String username;
	private String password;
	private String custom;

	private boolean enabled;

	@OneToMany(targetEntity = Authority.class, mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
	private Collection<Authority> authorities;

	public String getCustom() {
		return custom;
	}

	public void setCustom(String custom) {
		this.custom = custom;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return enabled;
	}

	@Override
	public boolean isAccountNonLocked() {
		return enabled;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return enabled;
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	@Override
	public String toString() {
		return "Users [username=" + username + ", password=" + password
				+ ", custom=" + custom + ", authorities=" + authorities + "]";
	}

}