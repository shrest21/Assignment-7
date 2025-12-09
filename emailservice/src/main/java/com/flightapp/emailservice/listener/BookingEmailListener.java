package com.flightapp.emailservice.listener;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flightapp.emailservice.config.RabbitMQConfig;
import com.flightapp.emailservice.model.Booking;
import com.flightapp.emailservice.service.EmailSenderService;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Service;

@Service
public class BookingEmailListener {

    private final EmailSenderService emailSender;
    private final ObjectMapper objectMapper;

    public BookingEmailListener(EmailSenderService emailSender, ObjectMapper objectMapper) {
        this.emailSender = emailSender;
        this.objectMapper = objectMapper;
    }

    // ✅ CONFIRMATION EMAIL
    @RabbitListener(queues = "booking.confirm.queue")
    public void sendBookingConfirmation(String message) throws JsonProcessingException {

        Booking booking = objectMapper.readValue(message, Booking.class);

        emailSender.sendBookingConfirmationEmail(
                booking.getEmail(),
                booking.getPnr(),
                booking.getName(),
                booking.getFlightId()
        );

        System.out.println("✅ CONFIRMATION EMAIL SENT");
    }

    // ✅ CANCELLATION EMAIL
    @RabbitListener(queues = RabbitMQConfig.BOOKING_CANCEL_QUEUE)
    public void sendBookingCancellation(String message) throws JsonProcessingException {

        Booking booking = objectMapper.readValue(message, Booking.class);

        emailSender.sendBookingCancellationEmail(
                booking.getEmail(),
                booking.getPnr(),
                booking.getName(),
                booking.getFlightId()
        );

        System.out.println("✅ CANCELLATION EMAIL SENT");
    }
}
