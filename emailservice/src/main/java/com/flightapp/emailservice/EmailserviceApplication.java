package com.flightapp.emailservice;

import org.springframework.amqp.rabbit.annotation.EnableRabbit;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnableRabbit
@SpringBootApplication
public class EmailserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(EmailserviceApplication.class, args);
    }

}
