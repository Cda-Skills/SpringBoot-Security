package org.tuto.springSecurity6.controller;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.tuto.springSecurity6.model.User;
import org.tuto.springSecurity6.service.UserService;

@Controller
public class UserController {

	@Autowired
	UserService userService;
	
	@RequestMapping("/inscription")
		public String formulaire() {
		
		return "formulaire";
	}
	
	@RequestMapping("/save")
	public String Inscrit(@ModelAttribute("userAddtribute") User user){
		userService.saveUser(user);
		return "formulaire";
	}
	
	@RequestMapping("/listUser")
	public String listUser(ModelMap modelMap) {
		modelMap.addAttribute("users", userService.getAllUsers());
		return "listUser";
	}
	
}
