package com.flightapp.flightservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.kafka.annotation.EnableKafka;

@EnableDiscoveryClient
@EnableKafka
@SpringBootApplication
public class FlightserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(FlightserviceApplication.class, args);
    }

}
