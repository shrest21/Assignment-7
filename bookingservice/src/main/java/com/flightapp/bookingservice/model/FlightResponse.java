package com.flightapp.bookingservice.model;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class FlightResponse {

    private String id;
    private String airline;
    private String fromPlace;
    private String toPlace;
    private String flightName;
    private String departureTime;
    private String arrivalTime;
    private String flightDate;
    private int totalSeats;
    private int price;
}
