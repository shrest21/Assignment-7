package com.flightapp.bookingservice.feign;

import com.flightapp.bookingservice.exception.FlightServiceUnavailableException;
import com.flightapp.bookingservice.model.FlightResponse;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

@Component
public class BookingInterfaceFallbackFactory implements FallbackFactory<BookingInterface> {

    @Override
    public BookingInterface create(Throwable cause) {

        return new BookingInterface() {

            @Override
            public void reserve(String id, int seats) {
                throw new FlightServiceUnavailableException(
                        "Flight service is DOWN. Cannot reserve seats right now."
                );
            }

            @Override
            public void release(String id, int seats) {
                System.out.println("Flight service down. Release skipped safely.");
            }

            @Override
            public FlightResponse getFlight(String id) {
                throw new FlightServiceUnavailableException(
                        "Flight service is DOWN. Cannot fetch flight details."
                );
            }
        };
    }
}
