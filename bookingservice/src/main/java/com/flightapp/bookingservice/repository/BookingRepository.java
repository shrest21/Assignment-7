package com.flightapp.bookingservice.repository;

import com.flightapp.bookingservice.model.Booking;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface BookingRepository extends MongoRepository<Booking, String> {

    Booking findByPnr(String pnr);

    List<Booking> findByEmail(String email);
}
