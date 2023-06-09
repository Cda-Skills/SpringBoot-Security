package org.tuto.springSecurity6.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.tuto.springSecurity6.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

}
