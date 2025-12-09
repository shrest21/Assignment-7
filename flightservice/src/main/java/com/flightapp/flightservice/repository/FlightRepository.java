package com.flightapp.flightservice.repository;

import com.flightapp.flightservice.model.Flight;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Flux;

public interface FlightRepository extends ReactiveMongoRepository<Flight, String> {

    Flux<Flight> findByFromPlaceIgnoreCaseAndToPlaceIgnoreCase(String from, String to);

}
