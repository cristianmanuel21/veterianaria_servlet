package com.pe.app.controller;

import java.net.URI;
import com.pe.app.services.VeterinariaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.pe.app.model.Veterinaria;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import javax.validation.Valid;

@RestController
@RequestMapping("/veterinaria")
public class VeterinariaController {
	
	@Autowired
	private VeterinariaService veterinariaService;

	@GetMapping
	public ResponseEntity<?> getAll(){
		return new ResponseEntity<>(veterinariaService.getAll(),HttpStatus.OK);
	}
	
	@GetMapping("/{id}")
	public ResponseEntity<Veterinaria> getVeterinaria(@PathVariable(name="id") Long id){
		Veterinaria veterinaria = veterinariaService.getById(id);
		return new ResponseEntity<>(veterinaria,HttpStatus.OK);
	}
	
	
	@PostMapping
	public ResponseEntity<Veterinaria> saveVeterinaria(@Valid @RequestBody Veterinaria veterinaria){
		Veterinaria newVeterinaria=veterinariaService.save(veterinaria);
		HttpHeaders responseHeaders = new HttpHeaders();
		URI newCacheUri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(newVeterinaria.getId())
				.toUri();
		responseHeaders.setLocation(newCacheUri);
		return new ResponseEntity<>(newVeterinaria,responseHeaders,HttpStatus.CREATED);
	}

	@PutMapping("/{id}")
	public ResponseEntity<Veterinaria> updateVeterinaria(@RequestBody Veterinaria veterinaria, @PathVariable(name="id") Long id){
		Veterinaria newVeterinaria=veterinariaService.getById(id);
		if(veterinaria.getDireccion()!=null && !veterinaria.getDireccion().isEmpty()) newVeterinaria.setNombre(veterinaria.getNombre());
		if(veterinaria.getTelefono()!=null && !veterinaria.getTelefono().isEmpty()) newVeterinaria.setTelefono(veterinaria.getTelefono());
		return new ResponseEntity<>(veterinariaService.save(newVeterinaria), HttpStatus.CREATED);
	}


}
