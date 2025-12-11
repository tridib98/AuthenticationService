package com.rims.Myauthenticationservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication(scanBasePackages = "com.rims.Myauthenticationservice")
public class AuthenticationserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationserviceApplication.class, args);
		System.out.println("*******************************************");
		System.out.println("*****Authentication Service is running*****");
		System.out.println("*******************************************");
	}

}
