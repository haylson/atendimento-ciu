package com.acre.ciu.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import com.acre.ciu.model.Usuario;
import com.acre.ciu.repository.UsuarioRepository;

@Repository
public class UsuarioService implements UserDetailsService {
	
	@Autowired
	private UsuarioRepository repository;

	@Override
	public Usuario loadUserByUsername(String nome){

		List<Usuario> usuarios = repository.findByNomeIgnoreCase(nome);
		
		if(usuarios.isEmpty()) {
			throw new UsernameNotFoundException("Usuário " + nome + " não encontrado!");
		}
		
		return usuarios.get(0);
		
	}
	
	public Usuario pegarUsuarioLogado() {
		
		Usuario usuarioLogado = (Usuario) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		return usuarioLogado;
	}
	
	public Usuario salvar(Usuario usuario){
		
		Long id = usuario.getId();
		
		repository.save(usuario);
		
		System.out.println(usuario);
		
		return usuario;
	}
	

}
