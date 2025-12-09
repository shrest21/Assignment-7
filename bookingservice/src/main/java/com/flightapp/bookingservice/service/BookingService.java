package com.flightapp.bookingservice.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flightapp.bookingservice.config.RabbitMQConfig;
import com.flightapp.bookingservice.dto.BookingRequest;
import com.flightapp.bookingservice.feign.BookingInterface;
import com.flightapp.bookingservice.model.*;
import com.flightapp.bookingservice.repository.BookingRepository;
import com.flightapp.bookingservice.util.PnrGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class BookingService {

    @Autowired
    private RabbitTemplate rabbitTemplate;

    private final BookingRepository bookingRepo;
    private final BookingInterface flightClient;

    public Booking bookFlight(BookingRequest request) throws Exception {

        int seatCount =
                (request.getPassengers() != null && !request.getPassengers().isEmpty())
                        ? request.getPassengers().size()
                        : request.getSeats();

        if (seatCount <= 0) {
            throw new IllegalArgumentException("Seat count must be > 0");
        }

        FlightResponse flight = flightClient.getFlight(request.getFlightId());
        if (flight == null) {
            throw new RuntimeException("Flight not found for id: " + request.getFlightId());
        }

        if (flight.getTotalSeats() < seatCount) {
            throw new RuntimeException("Not enough seats available");
        }

        flightClient.reserve(request.getFlightId(), seatCount);

        Booking booking = new Booking();
        booking.setPnr(PnrGenerator.generate(8));
        booking.setFlightId(request.getFlightId());
        booking.setEmail(request.getEmail());
        booking.setName(request.getName());
        booking.setMealType(request.getMealType());
        booking.setSeats(seatCount);
        booking.setPassengers(request.getPassengers());
        booking.setStatus(BookingStatus.BOOKED);
        booking.setBookingDate(LocalDateTime.now().toString());
        booking.setJourneyDate(flight.getFlightDate() + "T" + flight.getDepartureTime());
        booking.setTotalPrice(seatCount * flight.getPrice());

        Booking saved = bookingRepo.save(booking);
        rabbitTemplate.convertAndSend(
                RabbitMQConfig.BOOKING_EXCHANGE,
                RabbitMQConfig.CONFIRM_ROUTING_KEY,
                booking
        );



        return saved;
    }

    public Booking getByPnr(String pnr) {
        Booking booking = bookingRepo.findByPnr(pnr);
        if (booking == null) {
            throw new RuntimeException("PNR not found: " + pnr);
        }
        return booking;
    }

    public List<Booking> historyByEmail(String email) {
        return bookingRepo.findByEmail(email);
    }

    public List<Booking> allBookings() {
        return bookingRepo.findAll();
    }

    public Booking cancelByPnr(String pnr) throws Exception{
        Booking booking = bookingRepo.findByPnr(pnr);
        if (booking == null) {
            throw new RuntimeException("PNR not found: " + pnr);
        }

        flightClient.release(booking.getFlightId(), booking.getSeats());

        booking.setStatus(BookingStatus.CANCELLED);
        booking.setBookingDate(LocalDateTime.now().toString());

        Booking saved = bookingRepo.save(booking);
        rabbitTemplate.convertAndSend(
                RabbitMQConfig.BOOKING_EXCHANGE,
                RabbitMQConfig.CANCEL_ROUTING_KEY,
                booking
        );



        return saved;
    }
}
