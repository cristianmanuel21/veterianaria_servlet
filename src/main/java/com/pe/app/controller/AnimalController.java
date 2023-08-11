package com.pe.app.controller;

import java.net.URI;

import com.pe.app.services.AnimalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.pe.app.model.Animal;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;

@RestController
@RequestMapping("/animal")
public class AnimalController {
	
	@Autowired
	private AnimalService animalService;

	@GetMapping
	public ResponseEntity<?> getAll(){
		return new ResponseEntity<>(animalService.getAll(),HttpStatus.OK);
	}
	
	@GetMapping("/{id}")
	public ResponseEntity<Animal> getAnimal(@PathVariable(name="id") Long id){
		Animal animal = animalService.getById(id);
		return new ResponseEntity<>(animal,HttpStatus.OK);
	}
	
	@PostMapping
	public ResponseEntity<Animal> saveAnimal(@Valid  @RequestBody Animal animal){
		Animal newAnimal=animalService.save(animal);
		HttpHeaders responseHeaders = new HttpHeaders();
		URI newCacheUri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(newAnimal.getId())
				.toUri();
		responseHeaders.setLocation(newCacheUri);
		return new ResponseEntity<>(newAnimal, responseHeaders, HttpStatus.CREATED);
	}

	@PutMapping("/{id}")
	public ResponseEntity<Animal> updateAnimal(@RequestBody Animal animal, @PathVariable(name="id") Long id){
		Animal newAnimal = animalService.getById(id);
		if(animal.getNombre()!=null && !animal.getNombre().isEmpty()) newAnimal.setNombre(animal.getNombre());
		return new ResponseEntity<>(animalService.save(newAnimal), HttpStatus.CREATED);
	}

	@DeleteMapping("/{id}")
	public ResponseEntity<Void> deleteAnimal(Long id){
		animalService.deleteById(id);
		return new ResponseEntity<>(HttpStatus.NO_CONTENT);
	}


}
