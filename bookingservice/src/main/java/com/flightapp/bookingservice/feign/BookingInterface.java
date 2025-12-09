package com.flightapp.bookingservice.feign;

import com.flightapp.bookingservice.model.FlightResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "FLIGHTSERVICE", fallback = BookingInterfaceFallbackFactory.class)
public interface BookingInterface {

    @PostMapping("/flights/{id}/reserve")
    void reserve(@PathVariable("id") String id, @RequestParam("seats") int seats);

    @PostMapping("/flights/{id}/release")
    void release(@PathVariable("id") String id, @RequestParam("seats") int seats);

    @GetMapping("/flights/{id}")
    FlightResponse getFlight(@PathVariable("id") String id);
}
