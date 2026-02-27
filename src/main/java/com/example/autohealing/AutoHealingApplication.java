package com.example.autohealing;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class AutoHealingApplication {

	public static void main(String[] args) {
		SpringApplication.run(AutoHealingApplication.class, args);
	}

}
