package com.flightapp.flightservice.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document(collection = "flights")
public class Flight {

    @Id
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
