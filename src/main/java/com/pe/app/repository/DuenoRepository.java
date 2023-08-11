package com.pe.app.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.pe.app.model.Dueno;

public interface DuenoRepository extends JpaRepository<Dueno, Long>{
	
}
