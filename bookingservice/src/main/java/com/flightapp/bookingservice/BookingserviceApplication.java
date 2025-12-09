package com.flightapp.bookingservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.kafka.annotation.EnableKafka;


@EnableFeignClients(basePackages = "com.flightapp.bookingservice.feign")
@EnableDiscoveryClient
@EnableKafka
@SpringBootApplication
public class BookingserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(BookingserviceApplication.class, args);
    }

}
