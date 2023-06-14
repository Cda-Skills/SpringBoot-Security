package org.tuto.springSecurity6.model;

import java.util.Date;

import org.springframework.format.annotation.DateTimeFormat;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;


@Entity
// H2 n'accepte pas "User" comme nom de table
@Table(name="Utilisateurs")
public class User {

	//springBoot Jpa :
	@Id 
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long idUser;
	
	private String pseudo;
	
	private String email;
	
	private String password;
	
	private String passwordCheck;
	
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date date;
	// TODO la date devrait etre automatisée
	
	
	public User() {
		super();
	}
	
	
	public User(String pseudo, String email, String password, String passwordCheck, Date date) {
		super();
		this.pseudo = pseudo;
		this.email = email;
		this.password = password;
		this.passwordCheck = passwordCheck;
		this.date = date;
	}


	public Long getIdUser() {
		return idUser;
	}

	
	public void setIdUser(Long idUser) {
		this.idUser = idUser;
	}

	public String getPseudo() {
		return pseudo;
	}

	public void setPseudo(String pseudo) {
		this.pseudo = pseudo;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPasswordCheck() {
		return passwordCheck;
	}

	public void setPasswordCheck(String passwordCheck) {
		this.passwordCheck = passwordCheck;
	}

	public Date getDate() {
		return date;
	}

	public void setDate(Date date) {
		this.date = date;
	}



	@Override
	public String toString() {
		return "User [idUser=" + idUser + ", pseudo=" + pseudo + ", email=" + email + ", password=" + password
				+ ", passwordCheck=" + passwordCheck + ", date=" + date + "]";
	}
	

}
