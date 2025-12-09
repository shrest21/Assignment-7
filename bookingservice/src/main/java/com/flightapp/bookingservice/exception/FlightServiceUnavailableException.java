package com.flightapp.bookingservice.exception;

public class FlightServiceUnavailableException extends RuntimeException {

    public FlightServiceUnavailableException(String message) {
        super(message);
    }
}
