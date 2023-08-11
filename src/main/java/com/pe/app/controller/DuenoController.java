package com.pe.app.controller;

import java.net.URI;
import com.pe.app.services.DuenoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.pe.app.model.Dueno;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import javax.validation.Valid;

@RestController
@RequestMapping("/dueno")
public class DuenoController {
	
	@Autowired
	private DuenoService duenoService;
	
	@GetMapping
	public ResponseEntity<?> getAll(){
		return new ResponseEntity<>(duenoService.getAll(),HttpStatus.OK);
	}

	@GetMapping("/{id}")
	public ResponseEntity<Dueno> getDueno(@PathVariable(name="id") Long id){
		Dueno dueno = duenoService.getById(id);
		return new ResponseEntity<>(dueno,HttpStatus.OK);
	}

	@PostMapping
	public ResponseEntity<Dueno> saveDueno(@Valid @RequestBody Dueno dueno){
		Dueno newDueno=duenoService.save(dueno);
		HttpHeaders responseHeaders = new HttpHeaders();
		URI newCacheUri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(newDueno.getId())
				.toUri();
		responseHeaders.setLocation(newCacheUri);
		return new ResponseEntity<>(newDueno, responseHeaders, HttpStatus.CREATED);
	}

	@PutMapping("/{id}")
	public ResponseEntity<Dueno> updateDueno(@RequestBody Dueno dueno, @PathVariable(name="id") Long id){
		Dueno newDueno = duenoService.getById(id);
		if(dueno.getCelular()!=null && !dueno.getCelular().isEmpty()) newDueno.setCelular(dueno.getCelular());
		if(dueno.getDireccion()!=null && !dueno.getDireccion().isEmpty()) newDueno.setDireccion(dueno.getDireccion());
		if(dueno.getCorreo()!=null && !dueno.getCorreo().isEmpty()) newDueno.setCorreo(dueno.getCorreo());
		if(dueno.getTelefono()!=null && !dueno.getTelefono().isEmpty()) newDueno.setTelefono(dueno.getTelefono());
		return new ResponseEntity<>(duenoService.save(newDueno), HttpStatus.CREATED);
	}

	@DeleteMapping("/{id}")
	public ResponseEntity<Void> deleteDueno(Long id){
		duenoService.deleteDueno(id);
		return new ResponseEntity<>(HttpStatus.NO_CONTENT);
	}

}
