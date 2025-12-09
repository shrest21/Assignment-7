package com.flightapp.flightservice.controller;

import com.flightapp.flightservice.model.Flight;
import com.flightapp.flightservice.service.FlightService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

class FlightControllerTest {

    private FlightService service;
    private WebTestClient web;

    @BeforeEach
    void setup() {
        service = Mockito.mock(FlightService.class);
        FlightController controller = new FlightController(service);
        web = WebTestClient.bindToController(controller).build();
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

        when(service.addFlight(any())).thenReturn(Mono.just(f));

        web.post()
                .uri("/flights")
                .bodyValue(f)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("F001");
    }

    @Test
    void testSearch() {
        Flight f = sampleFlight();

        when(service.search("DEL", "BLR")).thenReturn(Flux.just(f));

        web.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/flights/search")
                        .queryParam("from", "DEL")
                        .queryParam("to", "BLR")
                        .build())
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Flight.class)
                .hasSize(1);
    }

    @Test
    void testAllFlights() {
        when(service.getAllFlights()).thenReturn(Flux.just(sampleFlight()));

        web.get()
                .uri("/flights")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Flight.class)
                .hasSize(1);
    }

    @Test
    void testFindFlight() {
        Flight f = sampleFlight();
        when(service.getFlightById("F001")).thenReturn(Mono.just(f));

        web.get()
                .uri("/flights/F001")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("F001");
    }

    @Test
    void testReserve() {
        when(service.reserveSeats("F001", 5)).thenReturn(Mono.empty());

        web.post()
                .uri("/flights/F001/reserve?seats=5")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void testRelease() {
        when(service.releaseSeats("F001", 5)).thenReturn(Mono.empty());

        web.post()
                .uri("/flights/F001/release?seats=5")
                .exchange()
                .expectStatus().isOk();
    }
}
