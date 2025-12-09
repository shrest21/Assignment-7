package com.flightapp.emailservice.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Booking {

    private String id;
    private String pnr;
    private String flightId;
    private String email;
    private String name;
    private int seats;
    private String mealType;
    private LocalDateTime bookingDate;
    private LocalDateTime journeyDate;
    private double totalPrice;
    private String status;

    private List<Passenger> passengers;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Passenger {
        private String name;
        private String gender;
        private int age;
        private String seatNumber;
        private String meal;
    }
}
