package com.flightapp.bookingservice.service;

import com.flightapp.bookingservice.dto.BookingRequest;
import com.flightapp.bookingservice.feign.BookingInterface;
import com.flightapp.bookingservice.model.*;
import com.flightapp.bookingservice.repository.BookingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class BookingServiceTest {

    @Mock
    private BookingRepository bookingRepository;

    @Mock
    private BookingInterface flightClient;

    @InjectMocks
    private BookingService bookingService;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    private FlightResponse sampleFlight() {
        FlightResponse flight = new FlightResponse();
        flight.setId("F001");
        flight.setTotalSeats(100);
        flight.setPrice(5000);
        flight.setDepartureTime("10:00");
        flight.setFlightDate("2025-12-03");
        return flight;
    }

    @Test
    void testBookFlight_success() throws Exception {
        BookingRequest request = new BookingRequest();
        request.setFlightId("F001");
        request.setEmail("test@gmail.com");
        request.setName("John");
        request.setSeats(2);
        request.setPassengers(Collections.emptyList());

        when(flightClient.getFlight("F001")).thenReturn(sampleFlight());
        when(bookingRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Booking booking = bookingService.bookFlight(request);

        assertThat(booking).isNotNull();
        assertThat(booking.getStatus()).isEqualTo(BookingStatus.BOOKED);

        verify(flightClient).reserve("F001", 2);
        verify(bookingRepository).save(any());
    }

    @Test
    void testBookFlight_invalidSeatCount() {
        BookingRequest request = new BookingRequest();
        request.setSeats(0);

        assertThatThrownBy(() -> bookingService.bookFlight(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Seat count must be > 0");
    }

    @Test
    void testBookFlight_flightNotFound() {
        BookingRequest request = new BookingRequest();
        request.setFlightId("X001");
        request.setSeats(1);

        when(flightClient.getFlight("X001")).thenReturn(null);

        assertThatThrownBy(() -> bookingService.bookFlight(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Flight not found");
    }

    @Test
    void testGetByPnr_found() {
        Booking b = new Booking();
        b.setPnr("PNR123");
        when(bookingRepository.findByPnr("PNR123")).thenReturn(b);

        Booking result = bookingService.getByPnr("PNR123");
        assertThat(result).isEqualTo(b);
    }

    @Test
    void testGetByPnr_notFound() {
        when(bookingRepository.findByPnr("XYZ")).thenReturn(null);

        assertThatThrownBy(() -> bookingService.getByPnr("XYZ"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("PNR not found");
    }

    @Test
    void testHistoryByEmail() {
        when(bookingRepository.findByEmail("a@gmail.com"))
                .thenReturn(Collections.singletonList(new Booking()));

        assertThat(bookingService.historyByEmail("a@gmail.com")).hasSize(1);
    }

    @Test
    void testAllBookings() {
        when(bookingRepository.findAll()).thenReturn(Collections.singletonList(new Booking()));

        assertThat(bookingService.allBookings()).hasSize(1);
    }

    @Test
    void testCancelByPnr_success() throws Exception {
        Booking b = new Booking();
        b.setPnr("PNR123");
        b.setFlightId("F001");
        b.setSeats(2);
        when(bookingRepository.findByPnr("PNR123")).thenReturn(b);
        when(bookingRepository.save(any())).thenAnswer(i -> i.getArgument(0));

        Booking result = bookingService.cancelByPnr("PNR123");

        assertThat(result.getStatus()).isEqualTo(BookingStatus.CANCELLED);
        verify(flightClient).release("F001", 2);
    }

    @Test
    void testCancelByPnr_notFound() {
        when(bookingRepository.findByPnr("ABC")).thenReturn(null);

        assertThatThrownBy(() -> bookingService.cancelByPnr("ABC"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("PNR not found");
    }
}
