package com.flightapp.emailservice.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailSenderService {

    private final JavaMailSender mailSender;

    public EmailSenderService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendBookingConfirmationEmail(
            String to,
            String pnr,
            String name,
            String flightId
    ) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("shrest21@gmail.com");
        message.setTo(to);
        message.setSubject("Flight Booking Confirmed");
        message.setText(
                "Hello " + name + ",\n\n" +
                        "Your flight booking is CONFIRMED.\n\n" +
                        "PNR: " + pnr + "\n" +
                        "Flight ID: " + flightId + "\n\n" +
                        "Thank you for booking with us!"
        );

        mailSender.send(message);
        System.out.println("Booking confirmation email sent to " + to);
    }

    public void sendBookingCancellationEmail(
            String to,
            String pnr,
            String name,
            String flightId
    ) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("shrest21@gmail.com");
        message.setTo(to);
        message.setSubject("Flight Booking Cancelled");
        message.setText(
                "Hello " + name + ",\n\n" +
                        "Your flight booking has been CANCELLED.\n\n" +
                        "PNR: " + pnr + "\n" +
                        "Flight ID: " + flightId + "\n\n" +
                        "We hope to serve you again."
        );

        mailSender.send(message);
        System.out.println("Booking cancellation email sent to " + to);
    }
}
