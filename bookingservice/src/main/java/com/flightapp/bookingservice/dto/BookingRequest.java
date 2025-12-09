package com.flightapp.bookingservice.dto;

import com.flightapp.bookingservice.model.Passenger;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class BookingRequest {
    private String flightId;
    private String name;
    private String email;
    private int seats;
    private String mealType;
    private List<Passenger> passengers;
}
