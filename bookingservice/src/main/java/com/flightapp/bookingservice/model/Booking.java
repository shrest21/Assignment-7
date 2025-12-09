package com.flightapp.bookingservice.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Data
@NoArgsConstructor
@Document(collection = "bookings")
public class Booking {

    @Id
    private String id;
    private String pnr;
    private String flightId;
    private String email;
    private String name;
    private int seats;
    private String mealType;
    private String bookingDate;
    private String journeyDate;
    private double totalPrice;
    private BookingStatus status;
    private List<Passenger> passengers;
}
