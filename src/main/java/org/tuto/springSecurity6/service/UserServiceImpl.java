package org.tuto.springSecurity6.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.tuto.springSecurity6.model.User;
import org.tuto.springSecurity6.repository.UserRepository;

@Service
public class UserServiceImpl implements UserService{

	@Autowired
	UserRepository userRepository;
	
	public User saveUser(User user) {
		return userRepository.save(user);
	}
	
	public User updateUser(User user) {
		
		return userRepository.save(user);
	}

	public User getUser(Long id) {
		
		return userRepository.findById(id).get();
	}

	public List<User> getAllUsers() {
		
		return userRepository.findAll();
	}

	public void deleteUserById(Long id) {
		
		userRepository.deleteById(id);
	}

	public void deleteAllUsers() {
		// TODO Auto-generated method stub
		userRepository.deleteAll();
	}

}
