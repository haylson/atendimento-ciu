package com.acre.ciu.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.acre.ciu.model.Usuario;
import com.acre.ciu.service.UsuarioService;

@Controller
public class SegurancaController {
	
	@Autowired
	private UsuarioService usuarioService;
	

	@RequestMapping("/login")
	public String login(@AuthenticationPrincipal User user){
		
		if(user != null){
			String senha = user.getPassword();
			
			System.out.println(senha);
		}
		
		if(user != null){
			return "redirect:/ciu/pesquisa";
		}
		
		return "login";
	}
	
	@RequestMapping("/logout")
	public String logout(){
		
		return "redirect:/logout";
	}
	
	@GetMapping("/usuario/senha")
	public ModelAndView novo(Usuario usuario) {
		ModelAndView mv = new ModelAndView("usuario/trocar-senha");
		
		usuario = usuarioService.pegarUsuarioLogado();
		
		mv.addObject(usuario);
		return mv;
	}
	
	@PostMapping("/usuario/senha")
	public ModelAndView alterarSenha(Usuario usuario) throws Exception {
		
		ModelAndView mv = new ModelAndView("usuario/trocar-senha");
		
		String novaSenha = usuario.getNovaSenha();
		String repetirSenha = usuario.getRepetirSenha();
		
		if(!novaSenha.equals(repetirSenha)){
			System.out.println("Senhas não são iguais...");
		}
		
		usuario = usuarioService.pegarUsuarioLogado();
		
		usuario.setSenha(novaSenha);
		
		usuario = usuarioService.salvar(usuario);
		
		mv.addObject(usuario);
		
		return new ModelAndView("redirect:/usuario/senha");
	}
	
	/*@PostMapping("/ciu/novo")
	public ModelAndView salvar(@Valid Ciu ciu, BindingResult result, RedirectAttributes attributes) {
		
		if(ciu != null){
			throw new RuntimeException();
		}
		
		ciuRepository.save(ciu);
		attributes.addFlashAttribute("mensagemSucesso", "Cadastro salvo com sucesso!");
		return new ModelAndView("redirect:/ciu/novo");
	}*/
	
}
