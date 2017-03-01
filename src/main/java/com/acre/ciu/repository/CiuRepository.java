package com.acre.ciu.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.acre.ciu.model.Ciu;

public interface CiuRepository extends JpaRepository<Ciu, Long>{
	
	public List<Ciu> findByNomeContainingIgnoreCase(String nome);
	
	public List<Ciu> findByCpfContainingIgnoreCase(String cpf);

}
