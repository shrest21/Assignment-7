package com.flightapp.bookingservice.exception;

import feign.FeignException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // ✅ Your custom exception
    @ExceptionHandler(FlightServiceUnavailableException.class)
    public ResponseEntity<Map<String, Object>> handleFlightDown(FlightServiceUnavailableException ex) {
        return build503(ex.getMessage());
    }

    // ✅ SAFETY NET: If Feign still throws anything
    @ExceptionHandler(FeignException.class)
    public ResponseEntity<Map<String, Object>> handleFeign(FeignException ex) {
        return build503("Flight service is DOWN (Feign communication failed)");
    }

    private ResponseEntity<Map<String, Object>> build503(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", 503);
        response.put("error", "SERVICE_UNAVAILABLE");
        response.put("message", message);

        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
}
