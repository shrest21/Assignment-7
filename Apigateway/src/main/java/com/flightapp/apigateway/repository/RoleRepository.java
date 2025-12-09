package com.flightapp.apigateway.repository;

import com.flightapp.apigateway.model.Role;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Mono;

public interface RoleRepository extends ReactiveMongoRepository<Role, String> {
    Mono<Role> findByName(String name);
}
