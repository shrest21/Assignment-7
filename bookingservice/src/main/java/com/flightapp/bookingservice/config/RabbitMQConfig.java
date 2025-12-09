package com.flightapp.bookingservice.config;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfig {

    public static final String BOOKING_EXCHANGE = "booking.exchange";

    public static final String BOOKING_CONFIRM_QUEUE = "booking.confirm.queue";
    public static final String BOOKING_CANCEL_QUEUE  = "booking.cancel.queue";

    public static final String CONFIRM_ROUTING_KEY = "booking.confirm";
    public static final String CANCEL_ROUTING_KEY  = "booking.cancel";


    @Bean
    public TopicExchange bookingExchange() {
        return new TopicExchange(BOOKING_EXCHANGE);
    }

    @Bean
    public Queue confirmQueue() {
        return new Queue(BOOKING_CONFIRM_QUEUE, true);
    }

    @Bean
    public Queue cancelQueue() {
        return new Queue(BOOKING_CANCEL_QUEUE, true);
    }

    @Bean
    public Binding confirmBinding() {
        return BindingBuilder
                .bind(confirmQueue())
                .to(bookingExchange())
                .with(CONFIRM_ROUTING_KEY);
    }

    @Bean
    public Binding cancelBinding() {
        return BindingBuilder
                .bind(cancelQueue())
                .to(bookingExchange())
                .with(CANCEL_ROUTING_KEY);
    }

    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(jsonMessageConverter());
        return template;
    }

}
