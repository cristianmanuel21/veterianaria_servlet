package com.pe.app.repository;

import com.pe.app.model.Veterinaria;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VeterinariaRepository extends JpaRepository<Veterinaria, Long> {
	
	public Veterinaria findByNombre(String nombre);

}
