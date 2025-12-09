package com.flightapp.flightservice.service;

import com.flightapp.flightservice.model.Flight;
import com.flightapp.flightservice.repository.FlightRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class FlightService {

    private final FlightRepository repo;

    public Mono<Flight> addFlight(Flight flight) {
        return repo.save(flight);
    }

    public Flux<Flight> search(String from, String to) {
        return repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCase(from, to);
    }

    public Flux<Flight> getAllFlights() {
        return repo.findAll();
    }

    public Mono<Flight> getFlightById(String id) {
        return repo.findById(id);
    }

    public Mono<Void> reserveSeats(String flightId, int seats) {
        return repo.findById(flightId)
                .flatMap(f -> {
                    if (f.getTotalSeats() < seats) {
                        return Mono.error(new IllegalStateException("Not enough seats"));
                    }
                    f.setTotalSeats(f.getTotalSeats() - seats);
                    return repo.save(f);
                })
                .then();
    }

    public Mono<Void> releaseSeats(String flightId, int seats) {
        return repo.findById(flightId)
                .flatMap(f -> {
                    f.setTotalSeats(f.getTotalSeats() + seats);
                    return repo.save(f);
                })
                .then();
    }
}
