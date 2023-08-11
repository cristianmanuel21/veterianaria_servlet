package com.pe.app.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import com.pe.app.model.DuenoVeterinaria;

public interface DuenoVeterinariaRepository extends JpaRepository<DuenoVeterinaria, Long>{
	
	/*
	 * 	@Query(value="select count(*) from favourites f where f.user_id=:auhtorId",nativeQuery=true)
	public Long countByAuhtorId(@Param("auhtorId")Long auhtorId);
	 * */
	
	
	@Query(value="select dueno_id from duenoveterinarias f where  f.veterinaria_id=:vetId",nativeQuery=true)
	public List<Long>findDuenosBytVetId(@Param("vetId")Long vetId);
	

}
