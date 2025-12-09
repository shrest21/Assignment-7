package com.flightapp.flightservice.service;

import com.flightapp.flightservice.model.Flight;
import com.flightapp.flightservice.repository.FlightRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.*;

class FlightServiceTest {

    @Mock
    private FlightRepository repo;

    @InjectMocks
    private FlightService service;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    private Flight sampleFlight() {
        Flight f = new Flight();
        f.setId("F001");
        f.setFromPlace("DEL");
        f.setToPlace("BLR");
        f.setTotalSeats(100);
        return f;
    }

    @Test
    void testAddFlight() {
        Flight f = sampleFlight();
        when(repo.save(f)).thenReturn(Mono.just(f));

        StepVerifier.create(service.addFlight(f))
                .expectNext(f)
                .verifyComplete();

        verify(repo).save(f);
    }

    @Test
    void testSearchFlights() {
        Flight f = sampleFlight();
        when(repo.findByFromPlaceIgnoreCaseAndToPlaceIgnoreCase("DEL", "BLR"))
                .thenReturn(Flux.just(f));

        StepVerifier.create(service.search("DEL", "BLR"))
                .expectNext(f)
                .verifyComplete();
    }

    @Test
    void testGetAllFlights() {
        Flight f = sampleFlight();
        when(repo.findAll()).thenReturn(Flux.just(f));

        StepVerifier.create(service.getAllFlights())
                .expectNextCount(1)
                .verifyComplete();
    }

    @Test
    void testGetFlightById() {
        Flight f = sampleFlight();
        when(repo.findById("F001")).thenReturn(Mono.just(f));

        StepVerifier.create(service.getFlightById("F001"))
                .expectNext(f)
                .verifyComplete();
    }

    @Test
    void testReserveSeatsSuccess() {
        Flight f = sampleFlight();

        when(repo.findById("F001")).thenReturn(Mono.just(f));
        when(repo.save(any())).thenReturn(Mono.just(f));

        StepVerifier.create(service.reserveSeats("F001", 10))
                .verifyComplete();

        verify(repo).save(any());
    }

    @Test
    void testReserveSeatsFailure() {
        Flight f = sampleFlight();
        f.setTotalSeats(5);

        when(repo.findById("F001")).thenReturn(Mono.just(f));

        StepVerifier.create(service.reserveSeats("F001", 10))
                .expectError(IllegalStateException.class)
                .verify();

        verify(repo, never()).save(any());
    }

    @Test
    void testReleaseSeats() {
        Flight f = sampleFlight();

        when(repo.findById("F001")).thenReturn(Mono.just(f));
        when(repo.save(any())).thenReturn(Mono.just(f));

        StepVerifier.create(service.releaseSeats("F001", 10))
                .verifyComplete();

        verify(repo).save(any());
    }
}
