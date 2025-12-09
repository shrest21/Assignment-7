package com.flightapp.flightservice.controller;

import com.flightapp.flightservice.model.Flight;
import com.flightapp.flightservice.service.FlightService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@RequestMapping("/flights")
public class FlightController {

    private final FlightService service;

    @PostMapping
    public Mono<Flight> add(@RequestBody Flight flight) {
        return service.addFlight(flight);
    }

    @GetMapping("/search")
    public Flux<Flight> search(@RequestParam String from,
                               @RequestParam String to) {
        return service.search(from, to);
    }

    @GetMapping
    public Flux<Flight> all() {
        return service.getAllFlights();
    }

    @GetMapping("/{id}")
    public Mono<Flight> find(@PathVariable String id) {
        return service.getFlightById(id);
    }
    @PostMapping("/{id}/reserve")
    public Mono<Void> reserve(@PathVariable String id, @RequestParam int seats) {
        return service.reserveSeats(id, seats);
    }

    @PostMapping("/{id}/release")
    public Mono<Void> release(@PathVariable String id, @RequestParam int seats) {
        return service.releaseSeats(id, seats);
    }

}
