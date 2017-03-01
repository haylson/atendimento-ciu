package com.acre.ciu.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.acre.ciu.model.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
	
	public List<Usuario> findByNomeIgnoreCase(String nome);

}
